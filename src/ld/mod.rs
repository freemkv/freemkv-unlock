//! ld — the MediaTek MT1959 firmware unlocker.
//!
//! Self-contained module: it owns the bundled drive profiles, firmware blobs,
//! the WRITE_BUFFER / MODE SELECT upload, the unlock CDBs, and the variant-A /
//! variant-B handshake. It implements [`crate::Unlocker`] — removing AACS bus
//! encryption AT THE DRIVE (the unlocked drive serves clear content) and
//! reporting the OEM Volume ID.

// `cdb` is only the bdemu emulator's wire format (real unlocking uses profile
// templates), gated behind `emulation`; also compiled under `cfg(test)` so its
// wire-format tests run in default-feature CI.
#[cfg(any(feature = "emulation", test))]
mod cdb;
mod error;
mod platform;
mod profile;

use crate::ld::error::Result;
use crate::scsi::{DataDirection, ScsiTransport};
use crate::{DriveId, UnlockCtx, UnlockError, Unlocked, Unlocker};

// ── Public profile catalog ──────────────────────────────────────────────────
// Only the catalog is public (supported-drive lookup, used by bdemu); the
// unlock mechanism stays private.

pub use profile::{DriveProfile as Profile, Identity, Platform, ProfileMatch, Profiles};

/// The bundled MT1959 profile catalog (parsed once, process-cached), or
/// `None` if the embedded JSON fails to parse (a build-time bug). Pair with
/// [`Profiles::get`] to look up a specific drive:
/// `freemkv_unlock::ld::profiles().and_then(|p| p.get(&drive_id))`.
pub fn profiles() -> Option<&'static Profiles> {
    profile::bundled()
}

/// The bundled profile matching a drive identity, if the drive is supported.
/// Convenience over [`profiles`] + [`Profiles::get`].
pub fn profile(drive_id: &DriveId) -> Option<ProfileMatch> {
    profile::find_bundled(drive_id)
}

/// The unlock-handshake wire format the bdemu test-emulator needs to impersonate
/// an ld-unlockable drive: the marker an unlocked drive returns and the
/// READ BUFFER mode/buf-id that constitutes an unlock request. Behind the
/// non-default `emulation` feature so real clients never see ld's wire format.
#[cfg(feature = "emulation")]
pub use cdb::{UNLOCK_MARKER, is_unlock_read_buffer};

// The MT1959 unlocker. Matches a drive against the bundled profile database and
// runs the firmware-unlock + disc-speed-calibration handshake over raw SCSI.
// Stateless: `unlock()` returns what it learned.
#[derive(Default)]
pub struct LdUnlocker;

impl LdUnlocker {
    pub fn new() -> Self {
        LdUnlocker
    }
}

/// The firmware-unlocker name for a drive that has a bundled profile (for
/// drive-info "is this drive supported?" display), or `None`. A pure profile
/// lookup — does NOT touch the drive or unlock anything.
pub(crate) fn firmware_name(id: &DriveId) -> Option<&'static str> {
    profile::find_bundled(id).map(|_| "LD")
}

impl LdUnlocker {
    // Read the OEM Volume ID via the matched profile's vendor CDB (profile passed
    // in to avoid a redundant 206-entry catalog scan). Ok(Some) on a well-formed
    // response; Ok(None) if unreadable; Err only on a transport fault.
    fn read_oem_vid(
        &self,
        scsi: &mut dyn ScsiTransport,
        profile: &profile::DriveProfile,
    ) -> Result<Option<[u8; 16]>> {
        const RESPONSE_LEN: usize = 36;
        const EXPECTED_HEADER: [u8; 3] = [0x00, 0x22, 0x00];

        let Some(cdb) = profile.read_vid_cdb else {
            return Ok(None);
        };

        let mut buf = vec![0u8; RESPONSE_LEN];
        let result = scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000)?;
        // Per the transport contract a drive sense arrives as `Ok` with non-zero
        // `status`, not `Err` — without this check a CHECK CONDITION reads as a
        // successful response and the zero-filled buffer parses as a bogus VID.
        if result.status != 0 {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "oem_vid_check_condition",
                status = result.status,
                "OEM VID CDB returned a drive sense"
            );
            return Ok(None);
        }
        if result.bytes_transferred < RESPONSE_LEN {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "oem_vid_short_response",
                bytes_transferred = result.bytes_transferred,
                "OEM VID CDB returned short response"
            );
            return Ok(None);
        }
        if buf[0..3] != EXPECTED_HEADER {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "oem_vid_bad_header",
                "OEM VID response header mismatch"
            );
            return Ok(None);
        }
        let mut vid = [0u8; 16];
        vid.copy_from_slice(&buf[4..20]);
        tracing::debug!(target: "freemkv::disc", phase = "oem_vid_ok", "OEM VID retrieved via unlocker");
        Ok(Some(vid))
    }
}

impl LdUnlocker {
    // The MediaTek firmware unlock. Since it removes AACS at the drive (clear
    // content), this one op satisfies both features and bus-removal, so both
    // trait methods delegate here.
    fn firmware_unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        let id = ctx.drive_id;
        let Some(m) = profile::find_bundled(id) else {
            return Err(UnlockError::NotApplicable);
        };
        if matches!(m.platform, profile::Platform::Renesas) {
            // Renesas is a different platform (handled by the Renesas unlocker).
            return Err(UnlockError::NotApplicable);
        }
        let is_variant_b = matches!(m.platform, profile::Platform::Mt1959B);
        use platform::PlatformDriver;
        let mut mt = platform::mt1959::Mt1959::new(m.profile.clone(), is_variant_b);
        // A transport fault → UnlockError::Transport; any other firmware failure
        // → NotApplicable (via From<error::Error>).
        mt.init(scsi)?;
        // `init` only proves the handshake completed, not that the drive reached
        // extended-access state. Reporting unlocked off `init` alone shipped
        // ciphertext at rc=0.
        if !mt.is_unlocked() {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "firmware_unlock_incomplete",
                "firmware handshake completed but the drive is not in the extended-access state; falling through"
            );
            return Err(UnlockError::NotApplicable);
        }
        // Prime the per-region speed table. Best-effort (must not fail the unlock)
        // but not silent — an unlogged `let _ =` made a failed calibration
        // indistinguishable from success in the rip log.
        if let Err(e) = mt.probe_disc(scsi) {
            // A transport fault here is a dead bus, not a calibration miss — most
            // profiles never touch the bus again, so this was the only dead-bus
            // signal.
            if e.is_transport_failure() {
                tracing::warn!(
                    target: "freemkv::disc",
                    phase = "probe_disc_transport_fault",
                    "transport fault during disc speed calibration; aborting"
                );
                return Err(UnlockError::Transport);
            }
            tracing::warn!(
                target: "freemkv::disc",
                phase = "probe_disc_failed",
                transport_failure = false,
                "disc speed calibration failed; continuing with the drive's default speed table"
            );
        }
        let vid = self.read_oem_vid(scsi, &m.profile)?;
        Ok(Unlocked { vid, bus_key: None })
    }
}

impl Unlocker for LdUnlocker {
    fn name(&self) -> &'static str {
        "LD"
    }

    /// Match the drive against the bundled profile database and run the firmware
    /// unlock — one op that removes bus encryption at the drive (clear content)
    /// and reads the OEM Volume ID (best-effort). `Some` when the firmware
    /// handshake reached the extended-access state; `None` for an unknown drive
    /// or an incomplete handshake; `Err(Transport)` on a dead bus.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        crate::fallthrough(self.firmware_unlock(scsi, ctx))
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
