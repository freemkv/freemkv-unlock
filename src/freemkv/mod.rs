//! Unlock drives that identify themselves as freemkv firmware.
//!
//! The vendor IDENTITY response must parse as a [`FirmwareIdentity`] on the
//! supported grammar ([`FirmwareIdentity::is_supported`]). Commands use the
//! builders in [`crate::firmware`], which mirror the firmware ABI.
//! Unlocking sets Region to free, Speed to max, Unrestricted on, and Encryption
//! to [`crate::firmware::STATE_OFF`].
//! Encryption-off disables the certificate/bus barrier; the retired Bus feature
//! must not be used as a substitute.

use crate::firmware::{
    Feature, FirmwareIdentity, MEMREAD_LEN, MIN_ALLOC_LEN, REGION_FREE, SPEED_MAX, STATE_OFF,
    STATE_ON, build_identity_cdb, build_memread_cdb, build_set_cdb,
};
use crate::scsi::{DataDirection, ScsiTransport, is_dead_bus};
use crate::{UnlockCtx, UnlockError, Unlocked, Unlocker};

/// Allocation the IDENTITY / DUMPALL data-in phase reads back (a fixed 64-byte
/// window, matching [`MEMREAD_LEN`]).
const RESP_LEN: usize = MEMREAD_LEN;

// The freemkv custom-firmware unlocker. Detection: IDENTITY on a supported
// firmware version — no bundled profile catalog needed, unlike
// crate::ld::LdUnlocker. Stateless: `unlock()` returns what it learned.
#[derive(Default)]
pub struct FreemkvUnlocker;

impl FreemkvUnlocker {
    pub fn new() -> Self {
        FreemkvUnlocker
    }

    // Issue IDENTITY: Ok(true) only for freemkv firmware on the supported
    // grammar; Ok(false) if rejected, not freemkv, or below MIN_FW_VERSION (older
    // fw answers SETs with GOOD; unlock not validated). Dead bus: Err(Transport).
    fn identify(&self, scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
        let cdb = build_identity_cdb(RESP_LEN as u16);
        let mut buf = [0u8; RESP_LEN];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) => {
                let n = r.bytes_transferred.min(buf.len());
                let id = (r.status == 0)
                    .then(|| FirmwareIdentity::parse(&buf[..n]))
                    .flatten();
                let supported = id.as_ref().is_some_and(FirmwareIdentity::is_supported);
                if !supported {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "freemkv_identity_no_match",
                        version = id.as_ref().map(|i| i.version.as_str()),
                        "IDENTITY probe did not report supported freemkv firmware"
                    );
                }
                Ok(supported)
            }
            Err(e) => {
                if is_dead_bus(&e) {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "freemkv_identity_transport_fault",
                        "transport fault on the freemkv IDENTITY probe; aborting"
                    );
                    return Err(UnlockError::Transport);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_identity_rejected",
                    status = e.status,
                    "freemkv IDENTITY probe rejected by the drive; not this firmware"
                );
                Ok(false)
            }
        }
    }

    // Issue a `Set(feature, state)` over the required data-in phase. Ok(()) on GOOD status;
    // NotApplicable if rejected; Transport only on a dead bus.
    fn set(
        &self,
        scsi: &mut dyn ScsiTransport,
        feature: Feature,
        state: u8,
    ) -> std::result::Result<(), UnlockError> {
        let cdb = build_set_cdb(feature, state);
        // SET needs the data-in phase its CDB advertises — a no-data SET is aborted
        // (CHECK CONDITION, HW-confirmed on BU40N fw 0.8.1). Buffer sized from the SAME
        // const the CDB advertises (MIN_ALLOC_LEN) so the transfer length has one source.
        let mut buf = [0u8; MIN_ALLOC_LEN as usize];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) if r.status == 0 => Ok(()),
            Ok(r) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_set_rejected",
                    feature = ?feature,
                    state,
                    status = r.status,
                    "freemkv SET rejected by the drive"
                );
                Err(UnlockError::NotApplicable)
            }
            Err(e) => {
                if is_dead_bus(&e) {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "freemkv_set_transport_fault",
                        feature = ?feature,
                        "transport fault on a freemkv SET; aborting"
                    );
                    return Err(UnlockError::Transport);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_set_rejected_as_err",
                    feature = ?feature,
                    status = e.status,
                    "freemkv SET rejected (via Err)"
                );
                Err(UnlockError::NotApplicable)
            }
        }
    }

    /// DumpAll diagnostic RAM read (DUMPALL): return the 64-byte window at
    /// `addr`. A host-side diagnostic path only — not used by the unlock flow.
    #[allow(dead_code)]
    fn dump_ram(
        &self,
        scsi: &mut dyn ScsiTransport,
        addr: u32,
    ) -> std::result::Result<[u8; MEMREAD_LEN], UnlockError> {
        let cdb = build_memread_cdb(addr);
        let mut buf = [0u8; MEMREAD_LEN];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) if r.status == 0 && r.bytes_transferred >= MEMREAD_LEN => Ok(buf),
            Ok(_) => Err(UnlockError::NotApplicable),
            Err(e) => {
                if is_dead_bus(&e) {
                    Err(UnlockError::Transport)
                } else {
                    Err(UnlockError::NotApplicable)
                }
            }
        }
    }

    // Full freemkv unlock: IDENTITY (hard gate) → Set(Region,free) →
    // Set(Speed,max) → Set(Unrestricted,on) (best-effort) → Set(Encryption,off)
    // (LOAD-BEARING — consolidated cert/bus bypass) → bare 0xAD VID (best-effort).
    fn full_unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
    ) -> std::result::Result<Unlocked, UnlockError> {
        // IDENTITY: must be a freemkv drive.
        if !self.identify(scsi)? {
            return Err(UnlockError::NotApplicable);
        }
        // Best-effort feature set: only a dead bus aborts.
        let best_effort = |r: std::result::Result<(), UnlockError>,
                           what: &'static str|
         -> std::result::Result<(), UnlockError> {
            match r {
                Ok(()) => Ok(()),
                Err(UnlockError::Transport) => Err(UnlockError::Transport),
                Err(_) => {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "freemkv_feature_unavailable",
                        feature = what,
                        "feature unavailable; continuing"
                    );
                    Ok(())
                }
            }
        };
        // Region-free + riplock lift (best-effort features).
        best_effort(self.set(scsi, Feature::Region, REGION_FREE), "region")?;
        best_effort(self.set(scsi, Feature::Speed, SPEED_MAX), "speed")?;
        // ABI full-bypass recipe: engage BD/UHD discs rather than rely on the
        // RAM defaults (RESET_TO_OEM or a saved config may leave it off).
        best_effort(
            self.set(scsi, Feature::Unrestricted, STATE_ON),
            "unrestricted",
        )?;
        // Encryption = off (LOAD-BEARING): the consolidated cert/bus bypass —
        // drive acts pre-authenticated (bare 0xAD returns the VID with no
        // cert/AKE) AND content returns de-bussed. No fallback.
        match self.set(scsi, Feature::Encryption, STATE_OFF) {
            Ok(()) => {}
            Err(UnlockError::Transport) => return Err(UnlockError::Transport),
            Err(_) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_disable_encryption_rejected",
                    "Set(Encryption, off) rejected — cannot unlock this drive"
                );
                return Err(UnlockError::VidUnavailable);
            }
        }
        // Bare 0xAD VID read — the shared BEST-EFFORT reader (identical to the
        // LD/Renesas routes). Encryption=off already unlocked the drive, so a
        // VID miss must not discard it: only a dead bus propagates (`?`), else `None`.
        let vid = crate::vid::read_aacs_vid(scsi)?;
        tracing::debug!(
            target: "freemkv::disc",
            phase = "freemkv_unlocked",
            has_vid = vid.is_some(),
            "freemkv drive unlocked (Encryption=off — consolidated cert/bus bypass)"
        );
        Ok(Unlocked { vid, bus_key: None })
    }
}

impl Unlocker for FreemkvUnlocker {
    fn name(&self) -> &'static str {
        "freemkv"
    }

    /// Recognise the drive by its IDENTITY knock, lift riplock/region and open
    /// Unrestricted (best-effort), set Encryption=off (the actual unlock), and
    /// read the Volume ID with a bare `0xAD` (best-effort). `Some` when the
    /// Encryption=off set succeeded — the drive is unlocked whether or not the
    /// VID read did; `None` if it isn't supported freemkv firmware;
    /// `Err(Transport)` on a dead bus. `ctx` is unused: this unlocker
    /// self-identifies rather than matching on drive identity.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        crate::fallthrough(self.full_unlock(scsi))
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
