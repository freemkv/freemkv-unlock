//! ld — the MediaTek MT1959 firmware unlocker.
//!
//! Self-contained module: it owns the bundled drive profiles, firmware blobs,
//! the WRITE_BUFFER / MODE SELECT upload, the unlock CDBs, and the variant-A /
//! variant-B handshake. It implements [`crate::Unlocker`] — removing AACS bus
//! encryption AT THE DRIVE (the unlocked drive serves clear content) and
//! reporting the OEM Volume ID.

// `cdb` is only the bdemu emulator's wire format (real unlocking uses profile
// templates), gated behind `emulation`; also compiled under `cfg(test)` so its
// wire-format tests run in default-feature CI. See docs/ld-mod.md — cdb gating.
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
// unlock mechanism stays private. See docs/ld-mod.md — public catalog design.

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
    // trait methods delegate here. See docs/ld-mod.md — firmware_unlock contract.
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
        // ciphertext at rc=0. See docs/ld-mod.md — half-unlock fallback.
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
            // signal. See docs/ld-mod.md — probe_disc dead-bus classification.
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
mod tests {
    use super::*;
    use crate::DiscKind;
    use crate::scsi::{DataDirection, ScsiResult, ScsiTransport};

    /// Unlock context for a fake drive id (kind/host-certs irrelevant to the
    /// firmware unlocker — it keys off the drive identity).
    fn ctx(id: &DriveId) -> UnlockCtx<'_> {
        UnlockCtx::new(id, DiscKind::Unknown)
    }

    /// A fake transport that fills the response buffer from a fixed payload and
    /// reports a configurable transferred-byte count.
    struct FakeTransport {
        payload: Vec<u8>,
        bytes_transferred: usize,
    }
    impl ScsiTransport for FakeTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            let n = self.payload.len().min(data.len());
            data[..n].copy_from_slice(&self.payload[..n]);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: self.bytes_transferred,
                sense: [0u8; 32],
            })
        }
    }

    /// A DriveId for the bundled HL-DT-ST profile that carries a real
    /// `read_vid_cdb`, so `read_oem_vid` finds a profile and issues the CDB.
    fn known_vid_drive_id() -> DriveId {
        make_drive_id("HL-DT-ST", "1.01", "NM00100", "211711202000")
    }

    fn make_drive_id(vendor: &str, rev: &str, vs: &str, date: &str) -> DriveId {
        DriveId {
            vendor_id: vendor.to_string(),
            product_id: String::new(),
            product_revision: rev.to_string(),
            vendor_specific: vs.to_string(),
            firmware_date: date.to_string(),
        }
    }

    /// The bundled profile of the fixture drive (the one carrying a real
    /// `read_vid_cdb`).
    fn known_vid_profile() -> profile::DriveProfile {
        let m = profile::find_bundled(&known_vid_drive_id()).expect("profile match");
        assert!(
            m.profile.read_vid_cdb.is_some(),
            "test fixture drive must carry an OEM VID CDB"
        );
        m.profile
    }

    /// A well-formed 36-byte response (signature 00 22 00, VID at [4..20]) parses
    /// to `Some(vid)`.
    #[test]
    fn read_oem_vid_parses_well_formed_response() {
        let mut payload = vec![0u8; 36];
        payload[0..3].copy_from_slice(&[0x00, 0x22, 0x00]);
        let vid = [0x3Cu8; 16];
        payload[4..20].copy_from_slice(&vid);
        let mut t = FakeTransport {
            payload,
            bytes_transferred: 36,
        };
        let got = LdUnlocker::new()
            .read_oem_vid(&mut t, &known_vid_profile())
            .expect("parse ok");
        assert_eq!(got, Some(vid), "VID parsed from [4..20]");
    }

    /// A short response → `Ok(None)` (drive unlocked, just no readable VID).
    #[test]
    fn read_oem_vid_short_response_is_none() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 20,
        };
        let got = LdUnlocker::new()
            .read_oem_vid(&mut t, &known_vid_profile())
            .expect("short response is Ok(None)");
        assert_eq!(got, None);
    }

    /// A response whose 3-byte signature isn't `00 22 00` → `Ok(None)`.
    #[test]
    fn read_oem_vid_bad_header_is_none() {
        let mut payload = vec![0u8; 36];
        payload[0..3].copy_from_slice(&[0xDE, 0xAD, 0xBE]);
        let mut t = FakeTransport {
            payload,
            bytes_transferred: 36,
        };
        let got = LdUnlocker::new()
            .read_oem_vid(&mut t, &known_vid_profile())
            .expect("bad header is Ok(None)");
        assert_eq!(got, None);
    }

    /// Catches dropping the `result.status` check: a CHECK CONDITION arrives as
    /// `Ok` per the transport contract, so without it the caller's zero-filled
    /// buffer is parsed as a real 36-byte response.
    #[test]
    fn read_oem_vid_check_condition_is_none_not_a_vid() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::illegal_request());
        let got = LdUnlocker::new()
            .read_oem_vid(&mut t, &known_vid_profile())
            .expect("a drive sense is not a transport fault");
        assert_eq!(got, None, "a CHECK CONDITION must never yield a VID");
    }

    /// Catches swallowing a transport fault in the OEM-VID read: a dead bus must
    /// propagate (→ `UnlockError::Transport`), never become `Ok(None)`.
    #[test]
    fn read_oem_vid_transport_fault_propagates() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::TransportFault);
        let err = LdUnlocker::new()
            .read_oem_vid(&mut t, &known_vid_profile())
            .expect_err("a dead bus must not be Ok(None)");
        assert!(err.is_transport_failure());
        assert_eq!(UnlockError::from(err), UnlockError::Transport);
    }

    /// A profile with no OEM-VID CDB → `Ok(None)` without touching the drive.
    #[test]
    fn read_oem_vid_no_cdb_is_none() {
        let mut p = known_vid_profile();
        p.read_vid_cdb = None;
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let got = LdUnlocker::new()
            .read_oem_vid(&mut t, &p)
            .expect("no CDB is Ok(None)");
        assert_eq!(got, None);
    }

    /// Public catalog accessors: `profiles()` returns the bundled catalog and
    /// `profile()` is `profiles().and_then(get)` for a known drive.
    #[test]
    fn public_catalog_accessors_find_the_bundled_fixture_drive() {
        assert!(super::profiles().is_some(), "bundled catalog must parse");
        let m = super::profile(&known_vid_drive_id()).expect("known fixture drive matches");
        assert!(m.profile.read_vid_cdb.is_some());
    }

    /// `unlock_features` on a drive with no matching profile → `NotApplicable`
    /// (fall through), short-circuiting before any firmware handshake.
    #[test]
    fn unlock_no_profile_is_not_applicable() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let unlocked = LdUnlocker::new()
            .unlock(
                &mut t,
                &ctx(&make_drive_id("FAKE-VND", "9.99", "XX12345", "")),
            )
            .expect("no profile → declines, not a hard error");
        assert!(unlocked.is_none());
    }

    // THE defect-1 test: response carries the signature + primary marker but not
    // the secondary one, so init() succeeds but the drive isn't in extended-access
    // state. Catches removing the `is_unlocked()` gate in `firmware_unlock`.
    #[test]
    fn half_unlocked_drive_falls_through_instead_of_claiming_unlocked() {
        use crate::scsi::mock::{MockTransport, Reply};
        let id = known_vid_drive_id();
        let sig = profile::find_bundled(&id)
            .expect("profile")
            .profile
            .signature;

        // 64-byte unlock response: signature + primary marker "MMkv" at [12..16],
        // secondary marker at [16..20] left zeroed.
        let mut resp = vec![0u8; 64];
        resp[0..4].copy_from_slice(&sig);
        resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]);

        let mut t = MockTransport::always(Reply::good(resp));
        let unlocked = LdUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("a half-unlock declines, not a hard error");
        assert!(
            unlocked.is_none(),
            "a half-unlocked drive must fall through to cert-auth"
        );
    }

    /// The whole-unlock happy path still reports unlocked when BOTH firmware
    /// markers are present — the `is_unlocked()` gate must not have made a
    /// genuinely unlocked drive fall through.
    #[test]
    fn fully_unlocked_drive_reports_unlocked() {
        use crate::scsi::mock::{MockTransport, Reply};
        let id = known_vid_drive_id();
        let sig = profile::find_bundled(&id)
            .expect("profile")
            .profile
            .signature;

        let mut resp = vec![0u8; 64];
        resp[0..4].copy_from_slice(&sig);
        resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]);
        resp[16..20].copy_from_slice(&[0x4C, 0x62, 0x44, 0x72]);

        let mut t = MockTransport::always(Reply::good(resp));
        assert!(
            LdUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .expect("no fault")
                .is_some(),
            "both markers → unlocked"
        );
    }

    // THE probe-disc dead-bus test: bus dies during speed calibration after a
    // full unlock; must abort with Transport, not report a successful unlock.
    // See docs/ld-mod.md — probe_disc dead-bus test / mutation notes.
    #[test]
    fn transport_fault_during_probe_disc_is_transport_not_a_successful_unlock() {
        let id = known_vid_drive_id();
        let sig = profile::find_bundled(&id)
            .expect("profile")
            .profile
            .signature;

        // A drive that unlocks fully but whose bus dies on the speed probe.
        struct ProbeFaultsDrive {
            resp: Vec<u8>,
        }
        impl ScsiTransport for ProbeFaultsDrive {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                // READ_BUFFER (0x3C) / SUB_CMD_PROBE (0x14) is the speed probe.
                if cdb.first() == Some(&0x3C) && cdb.get(3) == Some(&0x14) {
                    return Err(crate::scsi::ScsiError {
                        status: crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                        sense: None,
                    });
                }
                let n = self.resp.len().min(data.len());
                data[..n].copy_from_slice(&self.resp[..n]);
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0u8; 32],
                })
            }
        }

        let mut resp = vec![0u8; 64];
        resp[0..4].copy_from_slice(&sig);
        resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]); // primary marker
        resp[16..20].copy_from_slice(&[0x4C, 0x62, 0x44, 0x72]); // secondary marker
        let mut t = ProbeFaultsDrive { resp };

        let err = LdUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect_err("a dead bus during probe must abort, not report success");
        assert_eq!(err, UnlockError::Transport);
    }

    // A drive-sense (not a dead bus) rejecting the speed probe is a genuine
    // calibration miss: warn-and-continue on the default speed table, still
    // reporting a full unlock. Non-transport sibling of the probe-fault test.
    #[test]
    fn drive_sense_during_probe_disc_still_reports_a_successful_unlock() {
        let id = known_vid_drive_id();
        let sig = profile::find_bundled(&id)
            .expect("profile")
            .profile
            .signature;

        let mut resp = vec![0u8; 64];
        resp[0..4].copy_from_slice(&sig);
        resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]); // primary marker
        resp[16..20].copy_from_slice(&[0x4C, 0x62, 0x44, 0x72]); // secondary marker

        struct ProbeSenseDrive {
            resp: Vec<u8>,
        }
        impl ScsiTransport for ProbeSenseDrive {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                // READ_BUFFER (0x3C) / SUB_CMD_PROBE (0x14) is the speed probe.
                if cdb.first() == Some(&0x3C) && cdb.get(3) == Some(&0x14) {
                    return Ok(ScsiResult {
                        status: 0x02,
                        bytes_transferred: 0,
                        sense: [0u8; 32],
                    });
                }
                let n = self.resp.len().min(data.len());
                data[..n].copy_from_slice(&self.resp[..n]);
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0u8; 32],
                })
            }
        }
        let mut t = ProbeSenseDrive { resp };
        assert!(
            LdUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .expect("a calibration miss must not fail the whole unlock")
                .is_some()
        );
    }

    /// Catches classifying a dead bus as "not this unlocker's drive": the very
    /// first unlock command faulting at the transport layer must abort the
    /// consumer (`Transport`), not fall through to the next unlocker.
    #[test]
    fn transport_fault_during_unlock_is_transport_not_not_applicable() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::TransportFault);
        let err = LdUnlocker::new()
            .unlock(&mut t, &ctx(&known_vid_drive_id()))
            .expect_err("dead bus");
        assert_eq!(err, UnlockError::Transport);
    }
}
