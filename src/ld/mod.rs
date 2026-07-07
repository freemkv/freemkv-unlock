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
#[cfg(feature = "emulation")]
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
        let mut mt = platform::mt1959::Mt1959::new(m.profile, is_variant_b);
        // A transport fault → UnlockError::Transport; any other firmware failure
        // → NotApplicable (via From<error::Error>).
        mt.init(scsi)?;
        // Prime the per-region speed table (best-effort — must not fail the unlock).
        let _ = mt.probe_disc(scsi);
        let vid = self.read_oem_vid(scsi, id)?;
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
}
