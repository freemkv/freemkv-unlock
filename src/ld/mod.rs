//! ld — the LibreDrive firmware unlocker (MediaTek MT1959).
//!
//! Self-contained module: it owns the bundled drive profiles, firmware blobs,
//! the WRITE_BUFFER / MODE SELECT upload, the unlock CDBs, and the variant-A /
//! variant-B handshake. It implements [`crate::Unlocker`] — removing AACS bus
//! encryption AT THE DRIVE (the unlocked drive serves clear content) and
//! reporting the OEM Volume ID.

mod cdb;
mod error;
mod platform;
mod profile;

use crate::ld::error::Result;
use crate::scsi::{DataDirection, ScsiTransport};
use crate::{DriveId, UnlockCtx, UnlockError, Unlocked, Unlocker};

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

/// The firmware-unlocker name for a drive that has a bundled profile (for
/// drive-info "is this drive supported?" display), or `None`. A pure profile
/// lookup — does NOT touch the drive or unlock anything.
pub(crate) fn firmware_name(id: &DriveId) -> Option<&'static str> {
    profile::find_bundled(id).map(|_| "LibreDrive")
}

impl LibreDrive {
    /// Read the OEM Volume ID via the matched profile's vendor CDB.
    ///
    /// `Ok(Some(vid))` on a well-formed 36-byte response (signature `00 22 00`,
    /// VID at `[4..20]`); `Ok(None)` when there is no OEM-VID CDB or the response
    /// is short / bad-signature (the drive is still unlocked, just no VID); `Err`
    /// only on a transport fault.
    fn read_oem_vid(&self, scsi: &mut dyn ScsiTransport, id: &DriveId) -> Result<Option<[u8; 16]>> {
        const RESPONSE_LEN: usize = 36;
        const EXPECTED_HEADER: [u8; 3] = [0x00, 0x22, 0x00];

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

impl Unlocker for LibreDrive {
    /// Firmware unlock is a DRIVE-PREP concern: it runs before the disc kind is
    /// probed (`kind == Unknown`) and keys off the drive identity. It must NOT
    /// fire during the later content-keyed dispatch (Aacs/Css), or a DVD/Blu-ray
    /// in a profiled drive would be re-firmware-unlocked.
    fn matches(&self, ctx: &UnlockCtx) -> bool {
        ctx.kind == crate::DiscKind::Unknown && profile::find_bundled(ctx.drive_id).is_some()
    }

    /// Firmware-unlock the drive and report its OEM Volume ID. The unlocked drive
    /// serves CLEAR content, so `drive_unlocked: true` and there is no bus key.
    ///
    /// A no-firmware-route drive (Renesas) returns `NotApplicable` (fall through);
    /// a transport fault propagates as `Transport`; a firmware failure that isn't
    /// a dead bus also falls through (`NotApplicable`).
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        let id = ctx.drive_id;
        let Some(m) = profile::find_bundled(id) else {
            return Err(UnlockError::NotApplicable);
        };
        if matches!(m.platform, profile::Platform::Renesas) {
            // Renesas firmware unlock is not implemented — fall through to cert.
            return Err(UnlockError::NotApplicable);
        }
        let is_variant_b = matches!(m.platform, profile::Platform::Mt1959B);
        use platform::PlatformDriver;
        let mut mt = platform::mt1959::Mt1959::new(m.profile, is_variant_b);
        // Firmware unlock. A transport fault → UnlockError::Transport; any other
        // firmware failure → NotApplicable (via From<error::Error>).
        mt.init(scsi)?;
        // Prime the per-region speed table (best-effort — must not fail the unlock).
        let _ = mt.probe_disc(scsi);
        // The unlocked drive hands back its Volume ID; firmware serves clear
        // content, so no bus key and drive_unlocked = true.
        let vid = self.read_oem_vid(scsi, id)?;
        Ok(Unlocked {
            vid,
            bus_key: None,
            drive_unlocked: true,
        })
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
            product_revision: rev.to_string(),
            vendor_specific: vs.to_string(),
            firmware_date: date.to_string(),
        }
    }

    /// A well-formed 36-byte response (signature 00 22 00, VID at [4..20]) parses
    /// to `Some(vid)`.
    #[test]
    fn read_oem_vid_parses_well_formed_response() {
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
            .read_oem_vid(&mut t, &known_vid_drive_id())
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
            .read_oem_vid(&mut t, &known_vid_drive_id())
            .expect("bad header is Ok(None)");
        assert_eq!(got, None);
    }

    /// A drive with no matching profile → `read_oem_vid` is `Ok(None)`.
    #[test]
    fn read_oem_vid_no_profile_is_none() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let got = LibreDrive::new()
            .read_oem_vid(&mut t, &make_drive_id("FAKE-VND", "9.99", "XX12345", ""))
            .expect("no profile is Ok(None)");
        assert_eq!(got, None);
    }

    /// `unlock` on a drive with no matching profile → `NotApplicable` (fall
    /// through), short-circuiting before any firmware handshake.
    #[test]
    fn unlock_no_profile_is_not_applicable() {
        let mut t = FakeTransport {
            payload: vec![0u8; 36],
            bytes_transferred: 36,
        };
        let err = LibreDrive::new()
            .unlock(
                &mut t,
                &ctx(&make_drive_id("FAKE-VND", "9.99", "XX12345", "")),
            )
            .expect_err("no profile → NotApplicable");
        assert_eq!(err, UnlockError::NotApplicable);
    }
}
