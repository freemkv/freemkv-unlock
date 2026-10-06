use super::*;
use crate::scsi::mock::{MockTransport, Reply};

// Minimal driver taking the `PlatformDriver` default `is_unlocked`, so
// the default's `false` path is exercised (real drivers override it).
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
