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

use error::Result;
use libfreemkv::{DriveId, ScsiTransport, Unlocker};

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
}
