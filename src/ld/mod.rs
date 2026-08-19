//! ld — the LibreDrive firmware unlocker (MediaTek MT1959).
//!
//! Self-contained module: it owns the bundled drive profiles, firmware blobs,
//! the WRITE_BUFFER / MODE SELECT upload, the unlock CDBs, and the variant-A /
//! variant-B handshake. It implements [`crate::Unlocker`] — removing AACS bus
//! encryption AT THE DRIVE (the unlocked drive serves clear content) and
//! reporting the OEM Volume ID.

// `cdb` carries ONLY the unlock-handshake wire format that the bdemu emulator
// needs (the real unlocker drives its CDBs from per-drive profile templates, not
// these constants). Compile it only when the `emulation` feature exposes it, so
// it never dead-codes in a normal build.
// Compiled under `cfg(test)` as well as the feature: its tests pin the unlock
// wire format, and gating the whole module on a non-default feature meant CI
// (which builds with default features) never ran them.
#[cfg(any(feature = "emulation", test))]
mod cdb;
mod error;
mod platform;
mod profile;

use crate::ld::error::Result;
use crate::scsi::{DataDirection, ScsiTransport};
use crate::{DriveId, UnlockCtx, UnlockError, Unlocked, Unlocker};

// ── Public profile catalog ──────────────────────────────────────────────────
//
// The catalog of drives the LibreDrive unlocker recognizes is the one piece of
// ld worth exposing publicly: it answers "is this drive supported?" without
// unlocking, and the bdemu test-emulator reads it to impersonate a supported
// drive. The unlock *mechanism* (firmware blobs, upload sequence, CDB wire
// format) stays private — only the catalog and its match result are public.

pub use profile::{DriveProfile as Profile, Identity, Platform, ProfileMatch, Profiles};

/// The bundled LibreDrive profile catalog (parsed once, process-cached), or
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

/// The LibreDrive unlocker. `pub(crate)` — clients reach it only through
/// [`crate::all_unlockers`], never by name (the locked-design contract).
///
/// Matches a drive against the bundled profile database and, on a hit,
/// runs the MediaTek MT1959 firmware-unlock (and disc-speed calibration)
/// handshake over the raw SCSI transport.
pub(crate) struct LibreDrive;

impl LibreDrive {
    pub(crate) fn new() -> Self {
        LibreDrive
    }
}

/// The firmware-unlocker name for a drive that has a bundled profile (for
/// drive-info "is this drive supported?" display), or `None`. A pure profile
/// lookup — does NOT touch the drive or unlock anything.
pub(crate) fn firmware_name(id: &DriveId) -> Option<&'static str> {
    profile::find_bundled(id).map(|_| "LibreDrive")
}

impl LibreDrive {
    /// Read the OEM Volume ID via the matched profile's vendor CDB.
    ///
    /// Takes the profile the caller ALREADY matched rather than re-running
    /// `find_bundled`: the catalog is 206 entries and drive-prep used to scan it
    /// twice per drive (once here, once in `firmware_unlock`) for the same
    /// answer.
    ///
    /// `Ok(Some(vid))` on a well-formed 36-byte response (signature `00 22 00`,
    /// VID at `[4..20]`); `Ok(None)` when there is no OEM-VID CDB or the response
    /// is short / bad-signature / drive-rejected (the drive is still unlocked,
    /// just no VID); `Err` only on a transport fault.
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
        // Per the transport contract a drive sense arrives as `Ok` with a
        // non-zero `status`, NOT as `Err`. Without this check a CHECK CONDITION
        // would be read as a successful 36-byte response and the caller's own
        // zero fill parsed as a Volume ID.
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

impl LibreDrive {
    /// The MediaTek firmware unlock. Because LibreDrive removes AACS bus
    /// encryption AT THE DRIVE (the unlocked drive serves CLEAR content), this ONE
    /// operation satisfies BOTH the drive-features and the bus-removal capability
    /// — so `unlock_features` and `unlock_bus` both delegate here. The result
    /// carries `drive_unlocked: true` (no bus key needed) and the OEM Volume ID.
    ///
    /// A no-firmware-route drive (Renesas / no profile) returns `NotApplicable`; a
    /// transport fault propagates as `Transport`; any other firmware failure also
    /// falls through as `NotApplicable`.
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
        // `init` only proves the handshake COMPLETED — `do_unlock` returns Ok on
        // a response that carried the per-drive signature but not both firmware
        // markers. Only `is_unlocked()` means the drive actually reached the
        // extended-access state and serves clear content. Reporting
        // `drive_unlocked: true` off `init` alone told the consumer the bus was
        // clear on a half-unlocked drive, which suppressed the cert-auth
        // fallback and shipped ciphertext at rc=0. A partial unlock must fall
        // through to the next unlocker.
        if !mt.is_unlocked() {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "firmware_unlock_incomplete",
                "firmware handshake completed but the drive is not in the extended-access state; falling through"
            );
            return Err(UnlockError::NotApplicable);
        }
        // Prime the per-region speed table. Best-effort — it must not fail the
        // unlock — but NOT silent: speed calibration can fail completely, and an
        // unlogged `let _ =` made a fully-failed calibration indistinguishable
        // from a successful one in the rip log.
        if let Err(e) = mt.probe_disc(scsi) {
            // A transport fault here is a DEAD BUS, not a speed-calibration miss.
            // The rest of this path (`read_oem_vid`) is a no-op for the 140/206
            // profiles that carry no `read_vid_cdb`, so it never touches the bus
            // again — meaning this swallowed fault was the ONLY dead-bus signal,
            // and warn-and-continue turned it into `Ok(Unlocked{drive_unlocked:
            // true})`: a dead bus rendered as a fully-unlocked drive (the flagship
            // failure-that-looks-like-success). A genuine calibration miss (drive
            // sense / short reply) still continues on the default speed table.
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
        Ok(Unlocked {
            vid,
            bus_key: None,
            drive_unlocked: true,
        })
    }
}

impl Unlocker for LibreDrive {
    fn name(&self) -> &'static str {
        "LibreDrive"
    }

    /// LibreDrive provides drive features (riplock/speed, OEM VID) — and, because
    /// its firmware unlock serves clear content, bus removal comes free with it.
    fn unlock_features(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        self.firmware_unlock(scsi, ctx)
    }

    /// Same firmware code as [`unlock_features`]: LibreDrive removes the bus at
    /// the drive. In practice the consumer skips this because drive-prep already
    /// set `drive_unlocked`; it's here for completeness / a bus-first call order.
    fn unlock_bus(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        self.firmware_unlock(scsi, ctx)
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
        UnlockCtx::new(id, DiscKind::Unknown, &[])
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
        let got = LibreDrive::new()
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
        let got = LibreDrive::new()
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
        let got = LibreDrive::new()
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
        let got = LibreDrive::new()
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
        let err = LibreDrive::new()
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
        let got = LibreDrive::new()
            .read_oem_vid(&mut t, &p)
            .expect("no CDB is Ok(None)");
        assert_eq!(got, None);
    }

    /// `unlock_features` on a drive with no matching profile → `NotApplicable`
    /// (fall through), short-circuiting before any firmware handshake.
    #[test]
    fn unlock_no_profile_is_not_applicable() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let err = LibreDrive::new()
            .unlock_features(
                &mut t,
                &ctx(&make_drive_id("FAKE-VND", "9.99", "XX12345", "")),
            )
            .expect_err("no profile → NotApplicable");
        assert_eq!(err, UnlockError::NotApplicable);
    }

    /// THE defect-1 test. The drive answers every unlock READ_BUFFER with a
    /// response carrying the per-drive signature and the primary firmware marker
    /// but NOT the secondary one — `do_unlock` returns `Ok` and `init()`
    /// succeeds, yet the drive is NOT in the extended-access state. Reporting
    /// `drive_unlocked: true` here suppresses the cert-auth fallback. Catches
    /// removing the `is_unlocked()` gate in `firmware_unlock`.
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
        let err = LibreDrive::new()
            .unlock_features(&mut t, &ctx(&id))
            .expect_err("a half-unlocked drive must fall through to cert-auth");
        assert_eq!(err, UnlockError::NotApplicable);
    }

    /// The whole-unlock happy path still reports `drive_unlocked` when BOTH
    /// firmware markers are present — the `is_unlocked()` gate must not have
    /// made a genuinely unlocked drive fall through.
    #[test]
    fn fully_unlocked_drive_reports_drive_unlocked() {
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
        let u = LibreDrive::new()
            .unlock_features(&mut t, &ctx(&id))
            .expect("both markers → unlocked");
        assert!(u.drive_unlocked);
    }

    /// THE probe-disc dead-bus test. The drive unlocks fully (both firmware
    /// markers), then the bus DIES during disc-speed calibration. `probe_disc`
    /// used to be warn-and-continued regardless of the fault, and — because the
    /// 140/206 profiles without a `read_vid_cdb` never touch the bus again — a
    /// dead bus was reported as `Ok(Unlocked{drive_unlocked:true})`: a dead bus
    /// rendered as a successful unlock (the flagship failure-that-looks-like-
    /// success). `firmware_unlock` must now abort with `Transport`.
    /// MUTATION: reverting the `if e.is_transport_failure()` return in
    /// `firmware_unlock` (warn-and-continue), OR flattening the probe loops'
    /// transport classification, makes this go red.
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

        let err = LibreDrive::new()
            .unlock_features(&mut t, &ctx(&id))
            .expect_err("a dead bus during probe must abort, not report success");
        assert_eq!(err, UnlockError::Transport);
    }

    /// Catches classifying a dead bus as "not this unlocker's drive": the very
    /// first unlock command faulting at the transport layer must abort the
    /// consumer (`Transport`), not fall through to the next unlocker.
    #[test]
    fn transport_fault_during_unlock_is_transport_not_not_applicable() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::TransportFault);
        let err = LibreDrive::new()
            .unlock_features(&mut t, &ctx(&known_vid_drive_id()))
            .expect_err("dead bus");
        assert_eq!(err, UnlockError::Transport);
    }
}
