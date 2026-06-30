//! Platform-specific drive unlock + disc probing (LibreDrive internals).

pub mod mt1959;

use crate::ld::error::Result;
use crate::scsi::ScsiTransport;

pub(crate) trait PlatformDriver: Send {
    /// Unlock drive + upload firmware if needed.
    fn init(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()>;

    /// Calibrate drive for this disc. Probes the disc surface so the
    /// drive's firmware learns the optimal speed for each region.
    fn probe_disc(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()>;

    /// True after successful init().
    #[allow(dead_code)]
    fn is_ready(&self) -> bool;

    /// True if the drive is currently in the extended-access state.
    #[allow(dead_code)]
    fn is_unlocked(&self) -> bool {
        false
    }
}
