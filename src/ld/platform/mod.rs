//! Platform-specific drive unlock + disc probing (Mt1959Unlocker internals).

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

    /// True if the drive is currently in the extended-access state. THE gate
    /// `Mt1959Unlocker::firmware_unlock` reports `drive_unlocked` from — `init()`
    /// returning `Ok` only means the handshake completed, not that the drive
    /// serves clear content.
    fn is_unlocked(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::mock::{MockTransport, Reply};

    /// A minimal driver that takes every `PlatformDriver` default (`is_unlocked`)
    /// so the shim's dispatch and the default's `false` are both exercised —
    /// every real driver (`Mt1959`) overrides `is_unlocked`, so without this the
    /// default body is dead in coverage even though it is reachable code.
    struct StubDriver;

    impl PlatformDriver for StubDriver {
        fn init(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()> {
            scsi.execute(&[0], crate::scsi::DataDirection::None, &mut [], 0)?;
            Ok(())
        }

        fn probe_disc(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()> {
            scsi.execute(&[0], crate::scsi::DataDirection::None, &mut [], 0)?;
            Ok(())
        }

        fn is_ready(&self) -> bool {
            true
        }
    }

    #[test]
    fn default_is_unlocked_is_false_and_trait_methods_dispatch() {
        let mut drv = StubDriver;
        let mut scsi = MockTransport::always(Reply::good(vec![]));
        assert!(drv.init(&mut scsi).is_ok());
        assert!(drv.probe_disc(&mut scsi).is_ok());
        assert!(drv.is_ready());
        assert!(!drv.is_unlocked());
    }
}
