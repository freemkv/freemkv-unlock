//! MT1959 variant B firmware upload.
//!
//! MODE SELECT (0x55) → read metadata → WRITE_BUFFER → vendor verify (0xF1) → unlock × 5+1

use super::{Mt1959, SCSI_READ_BUFFER, SCSI_WRITE_BUFFER};
use crate::ld::error::Result;
use crate::scsi::{DataDirection, ScsiTransport};

const SCSI_MODE_SELECT: u8 = 0x55;
const FIRMWARE_EXTRA: [u8; 16] = [0; 16];
/// Fallback F1 vendor-verify for legacy profiles that predate the per-drive
/// `fw_verify_cdb` capture. It carries ONE drive's token, so it only works for
/// that drive — real profiles must supply their own (see `DriveProfile`).
const VENDOR_VERIFY: [u8; 10] = [0xF1, 0x01, 0x02, 0x00, 0x0D, 0x30, 0x01, 0xF3, 0xAD, 0x23];

pub(super) fn load_firmware(mt: &mut Mt1959, scsi: &mut dyn ScsiTransport) -> Result<()> {
    let firmware = &mt.profile.firmware;
    if firmware.is_empty() {
        return Err(crate::ld::error::Error::UnlockFailed);
    }

    // Step 1: Upload the firmware via MODE SELECT. The profile's `firmware` is
    // the exact per-drive image — extracted at the drive's own load-CDB length
    // (2192..2528 bytes; the old fixed 0x9C0 truncated some drives and over-read
    // others into blob strings). Upload all of it. MODE SELECT(10)'s
    // parameter-list length is 16-bit, so reject only a blob that can't be
    // expressed in the CDB.
    let write_len = firmware.len();
    if write_len > u16::MAX as usize {
        return Err(crate::ld::error::Error::UnlockFailed);
    }
    let mode_select_cdb = [
        SCSI_MODE_SELECT,
        0x10,
        0x00,
        0x00,
        0x00,
        0x00,
        (write_len >> 16) as u8,
        (write_len >> 8) as u8,
        write_len as u8,
        0x00,
    ];
    let mut data = firmware[..write_len].to_vec();
    scsi.execute(&mode_select_cdb, DataDirection::ToDevice, &mut data, 30_000)?;

    // Step 2: Read firmware metadata (READ_BUFFER mode 6, offset 0x3000)
    let read_meta_cdb = [
        SCSI_READ_BUFFER,
        0x06,
        0x00,
        0x00,
        0x30,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
    ];
    let mut meta_resp = [0u8; 16];
    let _ = scsi.execute(
        &read_meta_cdb,
        DataDirection::FromDevice,
        &mut meta_resp,
        5_000,
    );

    // Step 3: Write extra firmware data (all zeros)
    let write_extra_cdb = [
        SCSI_WRITE_BUFFER,
        0x06,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
    ];
    let mut data2 = FIRMWARE_EXTRA.to_vec();
    let _ = scsi.execute(&write_extra_cdb, DataDirection::ToDevice, &mut data2, 5_000);

    // Step 4: Vendor verify (0xF1 — B-only, not standard SCSI). PER-DRIVE: take
    // it from the profile (39 distinct values across the 140 B drives). The
    // const is only a legacy fallback — it carries one drive's token.
    let verify_cdb = mt.profile.fw_verify_cdb.unwrap_or(VENDOR_VERIFY);
    let mut dummy = [0u8; 0];
    let _ = scsi.execute(&verify_cdb, DataDirection::None, &mut dummy, 5_000);

    // Step 5: Unlock retries (up to 5, then a final fatal attempt). On a
    // successful unlock we issue one confirmation pass; its result is
    // intentionally best-effort — the first call already established the
    // unlock state, so a hiccup on the redundant confirmation must not fail
    // an otherwise-good unlock.
    for _attempt in 0..5 {
        if mt.do_unlock(scsi).is_ok() {
            let _ = mt.do_unlock(scsi);
            return Ok(());
        }
    }
    mt.do_unlock(scsi)?;
    Ok(())
}
