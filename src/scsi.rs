//! The SCSI transport contract every unlocker issues CDBs through. The consumer
//! (libfreemkv) implements [`ScsiTransport`] over its own SCSI; the unlockers
//! never see a concrete transport. Common MMC/SPC opcodes live here too.

/// Direction of a SCSI data transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    None,
    FromDevice,
    ToDevice,
}

/// Result of a SCSI command: status byte, bytes transferred, raw sense.
#[derive(Debug, Clone)]
pub struct ScsiResult {
    pub status: u8,
    pub bytes_transferred: usize,
    pub sense: [u8; 32],
}

/// A transport-layer SCSI failure (the command could not complete — bridge
/// crash / disconnect), as opposed to a drive sense returned in [`ScsiResult`].
#[derive(Debug, Clone)]
pub struct ScsiError {
    pub status: u8,
    pub sense: Option<[u8; 32]>,
}

/// Transport-layer result.
pub type Result<T> = std::result::Result<T, ScsiError>;

/// The one capability an unlocker needs from the host: run a raw CDB. `Ok` even
/// on a SCSI sense (inspect `status`); `Err` only on a transport-layer fault.
pub trait ScsiTransport {
    fn execute(
        &mut self,
        cdb: &[u8],
        direction: DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<ScsiResult>;
}

/// Parsed SCSI sense (the diagnostic an unlocker reads off a failed command).
#[derive(Debug, Clone, Copy)]
pub struct ScsiSense {
    pub sense_key: u8,
    pub asc: u8,
    pub ascq: u8,
}

impl ScsiSense {
    /// Parse the fixed-format sense buffer (key at byte 2, ASC at 12, ASCQ at 13).
    pub fn from_buf(sense: &[u8; 32]) -> Self {
        ScsiSense {
            sense_key: sense[2] & 0x0F,
            asc: sense[12],
            ascq: sense[13],
        }
    }
    /// ILLEGAL REQUEST (sense key 0x05) — the drive won't honor the command.
    pub fn is_illegal_request(&self) -> bool {
        self.sense_key == 0x05
    }
}

/// SCSI status byte for a transport-layer failure (bridge crash / disconnect).
pub(crate) const SCSI_STATUS_TRANSPORT_FAILURE: u8 = 0xFF;
/// SCSI status byte CHECK CONDITION (a drive sense is available).
pub(crate) const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;

// Common opcodes used by the unlocker modules.
pub(crate) const SCSI_SET_CD_SPEED: u8 = 0xBB;
pub(crate) const SCSI_SEND_KEY: u8 = 0xA3;
pub(crate) const SCSI_REPORT_KEY: u8 = 0xA4;
pub(crate) const SCSI_READ_DISC_STRUCTURE: u8 = 0xAD;
/// AACS key class selector used in REPORT/SEND KEY CDBs.
pub(crate) const AACS_KEY_CLASS: u8 = 0x02;

/// Build a SET CD SPEED (0xBB) CDB requesting `read_speed` (KB/s; 0xFFFF = max).
pub(crate) fn build_set_cd_speed(read_speed: u16) -> [u8; 12] {
    [
        SCSI_SET_CD_SPEED,
        0x00,
        (read_speed >> 8) as u8,
        read_speed as u8,
        0xFF,
        0xFF,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
}
