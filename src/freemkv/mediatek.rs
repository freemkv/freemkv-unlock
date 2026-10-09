//! MediaTek live-loader seam.
//!
//! The common freemkv API is probed first. If it is absent and the drive is
//! identified as MediaTek, a caller-provided loader may install the runtime
//! implementation. The device-specific patching strategy intentionally lives
//! outside this crate until its protocol is defined.

use crate::scsi::ScsiTransport;
use crate::{DriveId, UnlockError};

pub trait LiveLoader: Send + Sync {
    fn is_mediatek(&self, drive: &DriveId) -> bool;
    fn load(&self, scsi: &mut dyn ScsiTransport) -> Result<(), UnlockError>;
}
