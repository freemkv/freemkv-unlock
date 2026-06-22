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

pub mod profile;

mod platform;

use error::{Error, Result};
use libfreemkv::{DriveId, ScsiTransport, Unlocker};
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

impl Unlocker for LibreDrive {
    fn name(&self) -> &str {
        "LibreDrive"
    }

    fn matches(&self, id: &DriveId) -> bool {
        profile::find_bundled(id).is_some()
    }

    fn unlock(&self, scsi: &mut dyn ScsiTransport, id: &DriveId) -> Result<()> {
        let Some(m) = profile::find_bundled(id) else {
            // matches() returned true but the profile vanished — treat as
            // "nothing to do"; the caller falls back to the cert handshake.
            return Ok(());
        };
        let is_variant_b = matches!(m.platform, profile::Platform::Mt1959B);
        if matches!(m.platform, profile::Platform::Renesas) {
            // Renesas firmware unlock is not implemented; leave the drive
            // untouched so the host-cert handshake carries the disc.
            return Ok(());
        }
        use platform::PlatformDriver;
        let mut mt = platform::mt1959::Mt1959::new(m.profile, is_variant_b);
        // Firmware unlock. On success, prime the per-region speed table so
        // the drive manages zone speeds internally (best-effort — probe
        // calibration failure must not fail an otherwise-good unlock).
        mt.init(scsi)?;
        let _ = mt.probe_disc(scsi);
        Ok(())
    }

    /// OEM Volume ID retrieval.
    ///
    /// An unlocker unlocks drive *functionality*, not just the disc: VID
    /// retrieval via the drive's OEM CDB is a capability separate from
    /// `unlock`. This recovers the per-drive READ_BUFFER VID path that lived
    /// in libfreemkv before the unlocker refactor (it was `read_vid_oem` in
    /// `libfreemkv/src/disc/encrypt.rs`), now living inside the unlocker
    /// where the per-drive `read_vid_cdb` template belongs.
    ///
    /// Returns:
    ///   * `Ok(Some(vid))` — the drive's profile carries an OEM VID CDB and
    ///     the drive served a well-formed VID. No host certificate or HRL is
    ///     involved — VID is decoupled from the cert chain.
    ///   * `Ok(None)` — no profile matched, or the profile carries no OEM VID
    ///     CDB; libfreemkv falls back to the cert-based VID read.
    ///   * `Err(_)` — the OEM CDB ran but returned a short or malformed
    ///     response.
    ///
    /// Response layout (36 bytes):
    ///   * `[0..3]`   3-byte response signature; expected `00 22 00`
    ///   * `[3]`      reserved
    ///   * `[4..20]`  16-byte Volume ID
    ///   * `[20..36]` reserved / per-drive padding
    fn read_vid(&self, scsi: &mut dyn ScsiTransport, id: &DriveId) -> Result<Option<[u8; 16]>> {
        const RESPONSE_LEN: usize = 36;
        const EXPECTED_HEADER: [u8; 3] = [0x00, 0x22, 0x00];

        // No matching profile, or a profile without an OEM VID CDB → no OEM
        // path; the caller falls back to the cert handshake.
        let Some(m) = profile::find_bundled(id) else {
            return Ok(None);
        };
        let Some(cdb) = m.profile.read_vid_cdb else {
            return Ok(None);
        };

        let mut buf = vec![0u8; RESPONSE_LEN];
        let result = scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000)?;
        if result.bytes_transferred < RESPONSE_LEN {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "oem_vid_short_response",
                bytes_transferred = result.bytes_transferred,
                "OEM VID CDB returned short response"
            );
            return Err(Error::AacsVidRead);
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
            return Err(Error::AacsVidRead);
        }
        let mut vid = [0u8; 16];
        vid.copy_from_slice(&buf[4..20]);
        tracing::debug!(
            target: "freemkv::disc",
            phase = "oem_vid_ok",
            "OEM VID retrieved via unlocker"
        );
        Ok(Some(vid))
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
    /// parses to that VID.
    #[test]
    fn read_vid_parses_well_formed_response() {
        // Confirm the bundled profile actually carries a read_vid_cdb;
        // otherwise read_vid would short-circuit to Ok(None) and this test
        // wouldn't exercise the parse path.
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
            .read_vid(&mut t, &known_vid_drive_id())
            .expect("parse ok");
        assert_eq!(got, Some(vid), "VID parsed from [4..20]");
    }

    /// A short response (fewer than 36 transferred bytes) → AacsVidRead.
    #[test]
    fn read_vid_short_response_errors() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 20,
        };
        let err = LibreDrive::new()
            .read_vid(&mut t, &known_vid_drive_id())
            .expect_err("short response must error");
        assert!(matches!(err, Error::AacsVidRead));
    }

    /// A response whose 3-byte signature isn't `00 22 00` → AacsVidRead.
    #[test]
    fn read_vid_bad_header_errors() {
        let mut payload = vec![0u8; 36];
        payload[0..3].copy_from_slice(&[0xDE, 0xAD, 0xBE]); // wrong signature
        let mut t = FakeTransport {
            payload,
            bytes_transferred: 36,
        };
        let err = LibreDrive::new()
            .read_vid(&mut t, &known_vid_drive_id())
            .expect_err("bad header must error");
        assert!(matches!(err, Error::AacsVidRead));
    }

    /// A drive with no matching profile → Ok(None) (cert fallback), and the
    /// transport is never issued a CDB.
    #[test]
    fn read_vid_no_profile_is_none() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let got = LibreDrive::new()
            .read_vid(&mut t, &make_drive_id("FAKE-VND", "9.99", "XX12345", ""))
            .expect("no-profile is Ok(None)");
        assert!(got.is_none(), "no profile → cert fallback");
    }
}
