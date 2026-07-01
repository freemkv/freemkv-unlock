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
/// SCSI status byte CHECK CONDITION (a drive sense is available). Part of the
/// status contract; currently referenced only by tests asserting the
/// transport-vs-check-condition distinction.
#[allow(dead_code)]
pub(crate) const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;

// Common opcodes used by the unlocker modules.
pub(crate) const SCSI_SET_CD_SPEED: u8 = 0xBB;
pub(crate) const SCSI_SET_STREAMING: u8 = 0xB6;
pub(crate) const SCSI_SEND_KEY: u8 = 0xA3;
pub(crate) const SCSI_REPORT_KEY: u8 = 0xA4;
pub(crate) const SCSI_READ_DISC_STRUCTURE: u8 = 0xAD;
pub(crate) const SCSI_GET_CONFIGURATION: u8 = 0x46;
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

/// Length of a SET STREAMING Performance Descriptor (MMC-6 §6.42).
pub(crate) const SET_STREAMING_DESCRIPTOR_LEN: usize = 28;

/// Build a SET STREAMING (0xB6) CDB + its 28-byte Performance Descriptor
/// requesting maximum read performance across the whole disc. This is the modern
/// riplock lift: many drives (notably slot-loading BD combos over a USB bridge)
/// ignore the legacy SET CD SPEED (0xBB) but honor SET STREAMING, and unlike a
/// firmware unlock it is a STOCK MMC command — safe to issue on a non-unlocked
/// drive, so it never disturbs stock CSS auth.
///
/// `read_kbps` is the requested read size per 1000 ms window; `0xFFFF_FFFF` asks
/// the drive for its maximum. Returns `(cdb, descriptor)`; the caller sends the
/// descriptor as the CDB's data-out payload. The CDB's Parameter List Length
/// (bytes 9–10, big-endian) is the descriptor length.
pub(crate) fn build_set_streaming(
    read_kbps: u32,
) -> ([u8; 12], [u8; SET_STREAMING_DESCRIPTOR_LEN]) {
    let len = SET_STREAMING_DESCRIPTOR_LEN as u16;
    let cdb = [
        SCSI_SET_STREAMING,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        (len >> 8) as u8, // Parameter List Length (MSB)
        len as u8,        // Parameter List Length (LSB)
        0x00,
    ];
    let mut d = [0u8; SET_STREAMING_DESCRIPTOR_LEN];
    // byte 0: flags — RDD=0 (SET performance, don't restore defaults), Exact=0,
    // RA=0. bytes 1–3 reserved.
    // bytes 4..8: Start LBA = 0.
    // bytes 8..12: End LBA = 0xFFFFFFFF (apply across the whole disc).
    d[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    // bytes 12..16: Read Size (kB per Read Time window).
    d[12..16].copy_from_slice(&read_kbps.to_be_bytes());
    // bytes 16..20: Read Time = 1000 ms.
    d[16..20].copy_from_slice(&1000u32.to_be_bytes());
    // bytes 20..24 / 24..28: Write Size / Write Time (mirror read; unused for a
    // read-only rip but the descriptor requires them).
    d[20..24].copy_from_slice(&read_kbps.to_be_bytes());
    d[24..28].copy_from_slice(&1000u32.to_be_bytes());
    (cdb, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SET STREAMING (0xB6) wire format: opcode, the 28-byte Parameter List
    /// Length in CDB bytes 9–10, and the max-speed performance descriptor
    /// (whole-disc End LBA + the requested read size).
    #[test]
    fn set_streaming_cdb_layout() {
        let (cdb, d) = build_set_streaming(0xFFFF_FFFF);
        assert_eq!(cdb[0], SCSI_SET_STREAMING);
        assert_eq!(
            u16::from_be_bytes([cdb[9], cdb[10]]) as usize,
            SET_STREAMING_DESCRIPTOR_LEN,
            "param list length = descriptor length"
        );
        assert_eq!(d.len(), SET_STREAMING_DESCRIPTOR_LEN);
        assert_eq!(&d[8..12], &[0xFF, 0xFF, 0xFF, 0xFF], "whole-disc End LBA");
        assert_eq!(
            u32::from_be_bytes([d[12], d[13], d[14], d[15]]),
            0xFFFF_FFFF,
            "read size requests max"
        );
        assert_eq!(
            u32::from_be_bytes([d[16], d[17], d[18], d[19]]),
            1000,
            "read time window = 1000 ms"
        );
    }
}
