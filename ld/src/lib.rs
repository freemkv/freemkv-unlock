//! freemkv-unlock-ld — the LibreDrive unlocker plugin for libfreemkv.
//!
//! This crate owns *how* MediaTek MT1959 drives are firmware-unlocked:
//! the bundled drive profiles, the firmware blobs, the WRITE_BUFFER /
//! MODE SELECT upload, the unlock CDBs, and the variant-A / variant-B
//! handshake logic. libfreemkv knows none of it — it only exposes the
//! [`libfreemkv::Unlocker`] trait and a registry.
//!
//! Plug it in once at process start:
//!
//! ```no_run
//! libfreemkv::register_unlocker(Box::new(freemkv_unlock_ld::LibreDrive::new()));
//! ```
//!
//! With that one line, any drive whose identity matches a bundled profile
//! is firmware-unlocked at drive-prep; everything else falls through to
//! libfreemkv's host-certificate AACS handshake.

// libfreemkv module aliases so the moved firmware code keeps its original
// `crate::error::*` / `crate::scsi::*` paths.
pub(crate) use libfreemkv::{error, scsi};

pub mod cdb;
pub mod profile;

mod platform;

use error::Result;
use libfreemkv::aacs::Vid;
use libfreemkv::{DriveId, ScsiTransport, UnlockError, Unlocker};
use scsi::DataDirection;

/// The LibreDrive unlocker.
///
/// Matches a drive against the bundled profile database and, on a hit,
/// runs the MediaTek MT1959 firmware-unlock (and disc-speed calibration)
/// handshake over the raw SCSI transport.
pub struct LibreDrive;

impl LibreDrive {
    pub fn new() -> Self {
        LibreDrive
    }
}

impl Default for LibreDrive {
    fn default() -> Self {
        Self::new()
    }
}

impl LibreDrive {
    /// Read the OEM Volume ID via the matched profile's vendor CDB.
    ///
    /// This recovers the per-drive READ_BUFFER VID path that lived in
    /// libfreemkv before the unlocker refactor (it was `read_vid_oem` in
    /// `libfreemkv/src/disc/encrypt.rs`), now living inside the unlocker where
    /// the per-drive `read_vid_cdb` template belongs. Folded into [`Self::unlock`]:
    /// an unlocked drive must hand back its Volume ID in one step.
    ///
    /// Returns:
    ///   * `Ok(Vid)` — the profile carries an OEM VID CDB and the drive served a
    ///     well-formed VID. No host certificate or HRL is involved.
    ///   * `Err(UnlockError::VidUnavailable)` — no matching profile, no OEM VID
    ///     CDB, or a short / bad-signature response (auth succeeded but the VID
    ///     could not be read → cert fallback).
    ///   * `Err(UnlockError::Scsi(code))` — the OEM CDB itself failed at the
    ///     transport (via `?` / `From<Error>`).
    ///
    /// Response layout (36 bytes):
    ///   * `[0..3]`   3-byte response signature; expected `00 22 00`
    ///   * `[3]`      reserved
    ///   * `[4..20]`  16-byte Volume ID
    ///   * `[20..36]` reserved / per-drive padding
    fn read_oem_vid(
        &self,
        scsi: &mut dyn ScsiTransport,
        id: &DriveId,
    ) -> std::result::Result<Vid, UnlockError> {
        const RESPONSE_LEN: usize = 36;
        const EXPECTED_HEADER: [u8; 3] = [0x00, 0x22, 0x00];

        // No matching profile, or a profile without an OEM VID CDB → no OEM VID
        // path; the caller falls back to the cert handshake.
        let Some(m) = profile::find_bundled(id) else {
            return Err(UnlockError::VidUnavailable);
        };
        let Some(cdb) = m.profile.read_vid_cdb else {
            return Err(UnlockError::VidUnavailable);
        };

        let mut buf = vec![0u8; RESPONSE_LEN];
        // A transport failure here is a raw SCSI error → Scsi(code) via `?`.
        let result = scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000)?;
        if result.bytes_transferred < RESPONSE_LEN {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "oem_vid_short_response",
                bytes_transferred = result.bytes_transferred,
                "OEM VID CDB returned short response"
            );
            return Err(UnlockError::VidUnavailable);
        }
        if buf[0..3] != EXPECTED_HEADER {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "oem_vid_bad_header",
                header_0 = buf[0],
                header_1 = buf[1],
                header_2 = buf[2],
                "OEM VID response header mismatch"
            );
            return Err(UnlockError::VidUnavailable);
        }
        let mut vid = [0u8; 16];
        vid.copy_from_slice(&buf[4..20]);
        tracing::debug!(
            target: "freemkv::disc",
            phase = "oem_vid_ok",
            "OEM VID retrieved via unlocker"
        );
        Ok(Vid(vid))
    }
}

impl Unlocker for LibreDrive {
    fn name(&self) -> &str {
        "LibreDrive"
    }

    fn matches(&self, id: &DriveId) -> bool {
        profile::find_bundled(id).is_some()
    }

    /// Firmware-unlock the drive AND return the disc's OEM Volume ID in one step
    /// (the new trait folds the old `unlock_drive()` + `read_volume_id()`).
    ///
    /// Maps to [`UnlockError`]:
    ///   * no matching profile / Renesas (no firmware unlock implemented) →
    ///     [`UnlockError::FirmwareNotUnlockable`];
    ///   * a SCSI failure during the firmware-unlock handshake →
    ///     [`UnlockError::Scsi`] (via `?` / `From<Error>`);
    ///   * unlocked but no readable OEM VID → [`UnlockError::VidUnavailable`].
    ///
    /// Any error makes libfreemkv fall through to the in-tree cert handshake.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        id: &DriveId,
    ) -> std::result::Result<Vid, UnlockError> {
        let Some(m) = profile::find_bundled(id) else {
            // matches() returned true but the profile vanished — this unlocker
            // cannot put the firmware into extended mode.
            return Err(UnlockError::FirmwareNotUnlockable);
        };
        if matches!(m.platform, profile::Platform::Renesas) {
            // Renesas firmware unlock is not implemented; cannot unlock the
            // firmware, so the host-cert handshake must carry the disc.
            return Err(UnlockError::FirmwareNotUnlockable);
        }
        let is_variant_b = matches!(m.platform, profile::Platform::Mt1959B);
        use platform::PlatformDriver;
        let mut mt = platform::mt1959::Mt1959::new(m.profile, is_variant_b);
        // Firmware unlock. A SCSI failure becomes UnlockError::Scsi via `?`.
        mt.init(scsi)?;
        // On success, prime the per-region speed table so the drive manages
        // zone speeds internally (best-effort — calibration failure must not
        // fail an otherwise-good unlock).
        let _ = mt.probe_disc(scsi);
        // An unlocked drive must hand back its Volume ID in the same step.
        self.read_oem_vid(scsi, id)
    }

    /// Raise the drive to its maximum read speed.
    ///
    /// Issues the matched profile's `set_speed_max_cdb` (the
    /// `0xBB SET CD SPEED`-to-max command) over the raw transport. A profile
    /// without a `set_speed_max_cdb` (or no matching profile at all) is a
    /// no-op — the drive stays at its current speed.
    fn set_max_read_speed(&self, scsi: &mut dyn ScsiTransport, id: &DriveId) -> Result<()> {
        let Some(m) = profile::find_bundled(id) else {
            return Ok(());
        };
        let Some(cdb) = m.profile.set_speed_max_cdb else {
            return Ok(());
        };
        let mut buf = [0u8; 0];
        scsi.execute(&cdb, DataDirection::None, &mut buf, 5_000)?;
        tracing::debug!(
            target: "freemkv::drive",
            phase = "set_max_read_speed",
            "issued SET CD SPEED (max) via unlocker"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scsi::{DataDirection, ScsiResult, ScsiTransport};

    /// A fake transport that fills the response buffer from a fixed payload
    /// and reports a configurable transferred-byte count. Exercises the OEM
    /// VID response-parse branches without a live drive.
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
        ) -> Result<ScsiResult> {
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
    /// `read_vid_cdb`, so `read_vid` finds a profile and issues the CDB.
    fn known_vid_drive_id() -> DriveId {
        make_drive_id("HL-DT-ST", "1.01", "NM00100", "211711202000")
    }

    fn make_drive_id(vendor: &str, rev: &str, vs: &str, date: &str) -> DriveId {
        let mut inquiry = vec![0u8; 96];
        inquiry[8..8 + vendor.len().min(8)]
            .copy_from_slice(&vendor.as_bytes()[..vendor.len().min(8)]);
        inquiry[32..32 + rev.len().min(4)].copy_from_slice(&rev.as_bytes()[..rev.len().min(4)]);
        inquiry[36..36 + vs.len().min(7)].copy_from_slice(&vs.as_bytes()[..vs.len().min(7)]);
        DriveId::from_inquiry(&inquiry, date)
    }

    /// A well-formed 36-byte response (signature 00 22 00, VID at [4..20])
    /// parses to that VID via the OEM-VID helper `unlock` folds in.
    #[test]
    fn read_oem_vid_parses_well_formed_response() {
        // Confirm the bundled profile actually carries a read_vid_cdb; otherwise
        // read_oem_vid would short-circuit and this test wouldn't exercise the
        // parse path.
        let m = profile::find_bundled(&known_vid_drive_id()).expect("profile match");
        assert!(
            m.profile.read_vid_cdb.is_some(),
            "test fixture drive must carry an OEM VID CDB"
        );

        let mut payload = vec![0u8; 36];
        payload[0..3].copy_from_slice(&[0x00, 0x22, 0x00]);
        let vid = [0x3Cu8; 16];
        payload[4..20].copy_from_slice(&vid);
        let mut t = FakeTransport {
            payload,
            bytes_transferred: 36,
        };
        let got = LibreDrive::new()
            .read_oem_vid(&mut t, &known_vid_drive_id())
            .expect("parse ok");
        assert_eq!(got, Vid(vid), "VID parsed from [4..20]");
    }

    /// A short response (fewer than 36 transferred bytes) → VidUnavailable
    /// (unlocked but no readable VID → cert fallback).
    #[test]
    fn read_oem_vid_short_response_is_vid_unavailable() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 20,
        };
        let err = LibreDrive::new()
            .read_oem_vid(&mut t, &known_vid_drive_id())
            .expect_err("short response must error");
        assert_eq!(err, UnlockError::VidUnavailable);
    }

    /// A response whose 3-byte signature isn't `00 22 00` → VidUnavailable.
    #[test]
    fn read_oem_vid_bad_header_is_vid_unavailable() {
        let mut payload = vec![0u8; 36];
        payload[0..3].copy_from_slice(&[0xDE, 0xAD, 0xBE]); // wrong signature
        let mut t = FakeTransport {
            payload,
            bytes_transferred: 36,
        };
        let err = LibreDrive::new()
            .read_oem_vid(&mut t, &known_vid_drive_id())
            .expect_err("bad header must error");
        assert_eq!(err, UnlockError::VidUnavailable);
    }

    /// A drive with no matching profile → `read_oem_vid` is VidUnavailable
    /// (cert fallback), and the transport is never issued a CDB.
    #[test]
    fn read_oem_vid_no_profile_is_vid_unavailable() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let err = LibreDrive::new()
            .read_oem_vid(&mut t, &make_drive_id("FAKE-VND", "9.99", "XX12345", ""))
            .expect_err("no profile → VidUnavailable");
        assert_eq!(err, UnlockError::VidUnavailable);
    }

    /// `unlock` on a drive with no matching profile → FirmwareNotUnlockable
    /// (this unlocker cannot put the firmware into extended mode), short-
    /// circuiting before any firmware handshake is attempted.
    #[test]
    fn unlock_no_profile_is_firmware_not_unlockable() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let err = LibreDrive::new()
            .unlock(&mut t, &make_drive_id("FAKE-VND", "9.99", "XX12345", ""))
            .expect_err("no profile → FirmwareNotUnlockable");
        assert_eq!(err, UnlockError::FirmwareNotUnlockable);
    }

    /// A transport that records the CDB issued (and how many CDBs it saw),
    /// so the speed test can assert the profile's `set_speed_max_cdb` is the
    /// one sent — or that nothing was sent at all (no-op).
    struct RecordingTransport {
        last_cdb: Vec<u8>,
        calls: usize,
    }
    impl ScsiTransport for RecordingTransport {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            _data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            self.last_cdb = cdb.to_vec();
            self.calls += 1;
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: 0,
                sense: [0u8; 32],
            })
        }
    }

    /// A matched drive whose profile carries `set_speed_max_cdb` → that exact
    /// CDB is issued.
    #[test]
    fn set_max_read_speed_issues_profile_cdb() {
        let m = profile::find_bundled(&known_vid_drive_id()).expect("profile match");
        let expected = m
            .profile
            .set_speed_max_cdb
            .expect("test fixture drive must carry a set_speed_max_cdb");

        let mut t = RecordingTransport {
            last_cdb: Vec::new(),
            calls: 0,
        };
        LibreDrive::new()
            .set_max_read_speed(&mut t, &known_vid_drive_id())
            .expect("set_max_read_speed ok");
        assert_eq!(t.calls, 1, "exactly one CDB issued");
        assert_eq!(
            t.last_cdb,
            expected.to_vec(),
            "the profile's set_speed_max_cdb"
        );
    }

    /// A drive with no matching profile → no-op: no CDB issued, Ok(()).
    #[test]
    fn set_max_read_speed_no_profile_is_noop() {
        let mut t = RecordingTransport {
            last_cdb: Vec::new(),
            calls: 0,
        };
        LibreDrive::new()
            .set_max_read_speed(&mut t, &make_drive_id("FAKE-VND", "9.99", "XX12345", ""))
            .expect("no-profile is a no-op Ok(())");
        assert_eq!(t.calls, 0, "no profile → no CDB issued");
    }
}
