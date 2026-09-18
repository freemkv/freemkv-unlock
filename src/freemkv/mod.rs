//! freemkv — the self-identifying custom-firmware unlocker.
//!
//! Detects a freemkv-firmware drive by issuing the vendor IDENTITY command
//! (`3C 0E C0 DE 01 …`) and checking the reply starts `b"freemkv"` — no bundled
//! profile database is needed, unlike [`crate::ld`], because the firmware
//! self-identifies.
//!
//! The wire grammar (verbs/features/states, CDB layout) lives in
//! [`crate::firmware`], the typed mirror of `freemkv-fw/src/abi.rs`. This module
//! only sequences the vendor commands into an unlock; it reuses the firmware
//! module's CDB builders so the wire framing never drifts.
//!
//! Unlock mapping onto the grammar: region-free = `Set(Region, free)`
//! (`REGION_FREE`), riplock lift = `Set(Speed, max)` (`SPEED_MAX`), the
//! load-bearing transport unlock = `Set(Ake, off)` (`STATE_OFF` — drive acts
//! pre-authenticated → a bare `0xAD` returns the VID with no cert and no AKE), and
//! the trailing bus-off = `Set(Bus, off)` (`STATE_OFF`, content de-bussed). Under
//! the migrated spec the HRL/AKE/BUS unlock direction is `STATE_OFF`, not `0x01`.

use crate::firmware::{
    Feature, MEMREAD_LEN, MIN_ALLOC_LEN, REGION_FREE, RESP_MAGIC, SPEED_MAX, STATE_OFF,
    build_identity_cdb, build_memread_cdb, build_set_cdb,
};
use crate::scsi::{DataDirection, ScsiTransport};
use crate::{UnlockCtx, UnlockError, Unlocked, Unlocker};

/// The ASCII magic leading the IDENTITY reply — the ENTIRE freemkv-detection
/// mechanism (no bundled profile database; the firmware self-identifies).
const IDENTITY_MARKER: &[u8] = RESP_MAGIC;

/// Allocation the IDENTITY / DUMPALL data-in phase reads back (a fixed 64-byte
/// window, matching [`firmware::MEMREAD_LEN`]).
const RESP_LEN: usize = MEMREAD_LEN;

/// Whether a transport error is a genuine dead bus (a senseless
/// transport-failure status) rather than a drive rejection surfaced through a
/// non-conforming transport (`Err` carrying a sense).
fn is_dead_bus(e: &crate::scsi::ScsiError) -> bool {
    e.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none()
}

// The freemkv custom-firmware unlocker. Detection: IDENTITY, checking the reply
// starts "freemkv" — no bundled profile catalog needed, unlike
// crate::ld::LdUnlocker. Stateless: `unlock()` returns what it learned.
#[derive(Default)]
pub struct FreemkvUnlocker;

impl FreemkvUnlocker {
    pub fn new() -> Self {
        FreemkvUnlocker
    }

    // Issue IDENTITY: Ok(true) if the reply starts "freemkv", Ok(false) if
    // rejected/mismatched (not this firmware). A dead bus is Err(Transport) —
    // this is the FIRST command, so a transport fault must abort.
    fn identify(&self, scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
        let cdb = build_identity_cdb(RESP_LEN as u16);
        let mut buf = [0u8; RESP_LEN];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) => {
                let matched = r.status == 0
                    && r.bytes_transferred >= IDENTITY_MARKER.len()
                    && buf[..IDENTITY_MARKER.len()] == *IDENTITY_MARKER;
                if !matched {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "freemkv_identity_no_match",
                        "IDENTITY probe did not report freemkv firmware"
                    );
                }
                Ok(matched)
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
    // Set(Speed,max) (best-effort) → Set(Ake,off) (LOAD-BEARING) → bare 0xAD VID
    // (best-effort) → Set(Bus,off) (trailing, best-effort).
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
        // Ake = off/null (LOAD-BEARING): drive acts pre-authenticated, so a bare
        // 0xAD returns the VID with no cert/AKE. No fallback. The migrated spec
        // puts the null/bypass direction on STATE_OFF (0x00), not 0x01.
        match self.set(scsi, Feature::Ake, STATE_OFF) {
            Ok(()) => {}
            Err(UnlockError::Transport) => return Err(UnlockError::Transport),
            Err(_) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_null_ake_rejected",
                    "Set(Ake, null) rejected — cannot unlock this drive"
                );
                return Err(UnlockError::VidUnavailable);
            }
        }
        // Bare 0xAD VID read — the shared BEST-EFFORT reader (identical to the
        // LD/Renesas routes). The null AKE already unlocked the drive, so a VID
        // miss must not discard it: only a dead bus propagates (`?`), else `None`.
        let vid = crate::vid::read_aacs_vid(scsi)?;
        // Trailing Set(Bus, off): remove in-transit bus encryption (STATE_OFF is
        // the de-bussed direction). FULLY best-effort — inert without the lever,
        // and a failure here never discards an already-obtained unlock.
        if let Err(e) = self.set(scsi, Feature::Bus, STATE_OFF) {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "freemkv_bus_off_unavailable",
                ?e,
                "bus-off (Set Bus) not applied; continuing"
            );
        }
        tracing::debug!(
            target: "freemkv::disc",
            phase = "freemkv_unlocked",
            has_vid = vid.is_some(),
            "freemkv drive unlocked (null AKE — Ake=off)"
        );
        Ok(Unlocked { vid, bus_key: None })
    }
}

impl Unlocker for FreemkvUnlocker {
    fn name(&self) -> &'static str {
        "freemkv"
    }

    /// Recognise the drive by its IDENTITY knock, lift riplock/region
    /// (best-effort), null the AKE (the actual unlock), and read the Volume ID
    /// with a bare `0xAD` (best-effort). `Some` when the null-AKE set succeeded —
    /// the drive is unlocked whether or not the VID read did; `None` if it isn't
    /// a freemkv drive; `Err(Transport)` on a dead bus. `ctx` is unused: this
    /// unlocker self-identifies rather than matching on drive identity.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        crate::fallthrough(self.full_unlock(scsi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscKind;
    use crate::firmware::{
        REGION_FREE, RESET_TO_OEM, STATE_OFF, build_identity_cdb, build_memread_cdb,
        build_reset_cdb, build_set_cdb,
    };
    use crate::scsi::mock::{MockTransport, Reply};
    use crate::scsi::{DataDirection, Result, ScsiResult, ScsiTransport};

    fn ctx(id: &crate::DriveId) -> UnlockCtx<'_> {
        UnlockCtx::new(id, DiscKind::Unknown)
    }

    /// Serves a fixed payload with a GOOD status (used for the Identity probe).
    struct FakeTransport {
        payload: Vec<u8>,
    }
    impl ScsiTransport for FakeTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            let n = self.payload.len().min(data.len());
            data[..n].copy_from_slice(&self.payload[..n]);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }

    fn freemkv_identity_payload() -> Vec<u8> {
        let mut p = vec![0u8; RESP_LEN];
        let s = b"freemkv";
        p[..s.len()].copy_from_slice(s);
        p[s.len()] = 0x42; // version
        p
    }

    /// A well-formed format-0x80 VID structure: 4-byte header, 16-byte VID at
    /// offset 4, 16-byte MAC (zeroed on the bare path — it isn't checked). 36 =
    /// the fixed `0xAD` fmt-0x80 response length (see `crate::vid`).
    fn vid_ds_response(vid: [u8; 16]) -> Vec<u8> {
        let mut p = vec![0u8; 36];
        p[4..20].copy_from_slice(&vid);
        p
    }

    // ── CDB shape ────────────────────────────────────────────────────────

    /// IDENTITY builds the pinned knock frame with a 64-byte allocation.
    #[test]
    fn identity_cdb_is_the_knock_shape() {
        assert_eq!(
            build_identity_cdb(RESP_LEN as u16),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00]
        );
    }

    /// Regression (BU40N fw 0.8.1): a SET issued WITHOUT the data-in phase its
    /// CDB advertises is aborted by the drive (CHECK CONDITION / Aborted Command),
    /// so the unlocker's `set()` MUST read the MIN_ALLOC_LEN table back like
    /// `FirmwareControl::set` — not send `DataDirection::None`. Before the fix
    /// the whole freemkv unlock failed at `Set(Ake)` and fell back to AACS.
    #[test]
    fn set_issues_the_required_data_in_phase() {
        struct DataInContract;
        impl ScsiTransport for DataInContract {
            fn execute(
                &mut self,
                cdb: &[u8],
                dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> Result<ScsiResult> {
                assert_eq!(cdb[4], 0x02, "test exercises only the SET verb");
                // Model the drive: a SET with no from-device phase is aborted.
                if !matches!(dir, DataDirection::FromDevice) || data.is_empty() {
                    return Ok(ScsiResult {
                        status: 2,
                        bytes_transferred: 0,
                        sense: [0u8; 32],
                    });
                }
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: data.len(),
                    sense: [0u8; 32],
                })
            }
        }
        FreemkvUnlocker::new()
            .set(&mut DataInContract, Feature::Region, REGION_FREE)
            .expect("SET must succeed by issuing the data-in phase the firmware requires");
    }

    /// Each unlock SET is `Verb::Set` (02) on the right feature id (cdb[5]) with
    /// the state at cdb[6]; SET floors its data-in allocation at MIN_ALLOC_LEN
    /// (0x0040 at cdb[7..9]) — the drive aborts a sub-16-byte transfer (HW-confirmed).
    #[test]
    fn unlock_set_cdbs_have_the_new_grammar_shape() {
        // Region-free is REGION_FREE (0x0F) at cdb[6] — 0x01 now forces DVD region 1.
        assert_eq!(
            build_set_cdb(Feature::Region, REGION_FREE),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x02, 0x0F, 0x00, 0x40, 0x00]
        );
        // Speed max is SPEED_MAX (0x00) — the limiter-off leg of Speed.
        assert_eq!(
            build_set_cdb(Feature::Speed, SPEED_MAX),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x01, 0x00, 0x00, 0x40, 0x00]
        );
        // Ake/Bus unlock direction is now STATE_OFF (0x00) at cdb[6], not 0x01.
        assert_eq!(
            build_set_cdb(Feature::Ake, STATE_OFF),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x06, 0x00, 0x00, 0x40, 0x00]
        );
        assert_eq!(
            build_set_cdb(Feature::Bus, STATE_OFF),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x07, 0x00, 0x00, 0x40, 0x00]
        );
    }

    // ── Detection ────────────────────────────────────────────────────────

    #[test]
    fn identify_true_on_freemkv_marker_and_issues_identity_cdb() {
        let mut t = MockTransport::always(Reply::good(freemkv_identity_payload()));
        assert!(FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
        assert_eq!(t.cdbs[0], build_identity_cdb(RESP_LEN as u16));
    }

    #[test]
    fn identify_false_on_non_matching_payload() {
        let mut t = FakeTransport {
            payload: vec![0u8; RESP_LEN],
        };
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_false_on_short_response() {
        let mut t = MockTransport::always(Reply::short(freemkv_identity_payload(), 3));
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_false_when_command_rejected() {
        let mut t = MockTransport::always(Reply::illegal_request());
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_false_when_command_rejected_as_err() {
        let mut t = MockTransport::always(Reply::illegal_request_as_err());
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_transport_fault_aborts() {
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(
            FreemkvUnlocker::new().identify(&mut t).unwrap_err(),
            UnlockError::Transport
        );
    }

    // ── Feature sets ──────────────────────────────────────────────────────

    #[test]
    fn set_region_free_issues_the_set_region_on_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set(&mut t, Feature::Region, REGION_FREE)
            .expect("ok");
        assert_eq!(t.cdbs[0], build_set_cdb(Feature::Region, REGION_FREE));
    }

    #[test]
    fn set_ake_null_issues_the_set_ake_on_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set(&mut t, Feature::Ake, STATE_OFF)
            .expect("ok");
        assert_eq!(t.cdbs[0], build_set_cdb(Feature::Ake, STATE_OFF));
    }

    #[test]
    fn set_drive_rejection_is_not_applicable() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let err = FreemkvUnlocker::new()
            .set(&mut t, Feature::Ake, STATE_OFF)
            .unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }

    #[test]
    fn set_transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let err = FreemkvUnlocker::new()
            .set(&mut t, Feature::Speed, SPEED_MAX)
            .unwrap_err();
        assert_eq!(err, UnlockError::Transport);
    }

    // ── full_unlock / unlock ─────────────────────────────────────────────

    /// The full unlock runs IDENTITY → Set(Region) → Set(Speed) → Set(Ake) →
    /// bare VID → Set(Bus) in order.
    #[test]
    fn full_unlock_issues_identity_region_speed_ake_then_bare_vid_then_bus() {
        let vid = [0x7Cu8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // IDENTITY
                Reply::good(vec![]),                     // Set Region
                Reply::good(vec![]),                     // Set Speed
                Reply::good(vec![]),                     // Set Ake (load-bearing)
                Reply::good(vid_ds_response(vid)),       // 0xAD bare VID
                Reply::good(vec![]),                     // Set Bus (trailing)
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let out = FreemkvUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("no fault")
            .expect("null AKE ⇒ unlocked");
        assert_eq!(out.vid, Some(vid));
        assert_eq!(t.cdbs.len(), 6);
        // The four vendor SETs land on the right features, in order.
        assert_eq!(t.cdbs[0], build_identity_cdb(RESP_LEN as u16));
        assert_eq!(t.cdbs[1], build_set_cdb(Feature::Region, REGION_FREE));
        assert_eq!(t.cdbs[2], build_set_cdb(Feature::Speed, SPEED_MAX));
        assert_eq!(t.cdbs[3], build_set_cdb(Feature::Ake, STATE_OFF));
        assert_eq!(t.cdbs[4][0], crate::scsi::SCSI_READ_DISC_STRUCTURE);
        assert_eq!(t.cdbs[5], build_set_cdb(Feature::Bus, STATE_OFF));
    }

    /// A missing region/speed feature does not fail the unlock (best-effort).
    #[test]
    fn full_unlock_tolerates_missing_region_and_speed() {
        let vid = [0x3Cu8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::illegal_request(),                // region unsupported
                Reply::illegal_request(),                // speed unsupported
                Reply::good(vec![]),                     // null ake
                Reply::good(vid_ds_response(vid)),       // bare VID
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let out = FreemkvUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("no fault")
            .expect("unlocked");
        assert_eq!(out.vid, Some(vid));
    }

    /// The null AKE is LOAD-BEARING: if the drive rejects it, this isn't an
    /// unlockable freemkv drive, so `unlock()` declines (`None`) and falls
    /// through — never a hard error.
    #[test]
    fn declines_when_null_ake_rejected() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::good(vec![]),                     // region
                Reply::good(vec![]),                     // speed
                Reply::illegal_request(),                // null ake REJECTED
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        assert!(
            FreemkvUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .expect("no fault")
                .is_none()
        );
    }

    /// Best-effort VID: the null AKE succeeded (drive unlocked), but the bare
    /// VID read was rejected — `unlock()` still returns `Some`, with `vid: None`.
    #[test]
    fn unlocks_without_vid_when_bare_read_fails() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::good(vec![]),                     // region
                Reply::good(vec![]),                     // speed
                Reply::good(vec![]),                     // null ake
                Reply::illegal_request(),                // bare VID: no medium
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let out = FreemkvUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("no fault")
            .expect("unlocked despite no VID");
        assert_eq!(out.vid, None);
    }

    #[test]
    fn declines_non_freemkv_drive() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let id = crate::DriveId::default();
        assert!(
            FreemkvUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .expect("no fault")
                .is_none()
        );
    }

    #[test]
    fn transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let id = crate::DriveId::default();
        assert_eq!(
            FreemkvUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .unwrap_err(),
            UnlockError::Transport
        );
    }

    // ── DumpAll ──────────────────────────────────────────────────────────

    #[test]
    fn dump_ram_builds_memread_cdb_and_returns_the_window() {
        let mut payload = vec![0xABu8; MEMREAD_LEN];
        payload[0] = 0xEE;
        let mut t = MockTransport::always(Reply::good(payload));
        let got = FreemkvUnlocker::new()
            .dump_ram(&mut t, 0x01F8_1234)
            .expect("dump ok");
        assert_eq!(got[0], 0xEE);
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x09, 0x01, 0xF8, 0x12, 0x34, 0x00]
        );
    }

    #[test]
    fn build_memread_cdb_packs_address_big_endian_at_5_to_9() {
        let cdb = build_memread_cdb(0xDEAD_BEEF);
        assert_eq!(cdb[4], crate::firmware::Verb::DumpAll as u8);
        assert_eq!([cdb[5], cdb[6], cdb[7], cdb[8]], [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cdb[9], 0x00);
    }

    /// RESET builds the pinned all-features-passthrough frame (not issued by the
    /// unlock flow, but pinned here so the shared builder stays honest).
    #[test]
    fn reset_cdb_shape() {
        assert_eq!(
            build_reset_cdb(RESET_TO_OEM),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x00, 0xFF, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn name_is_freemkv() {
        assert_eq!(FreemkvUnlocker::new().name(), "freemkv");
    }
}
