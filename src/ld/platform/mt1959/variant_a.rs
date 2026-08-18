//! MT1959 variant A firmware upload.
//!
//! WRITE_BUFFER (0x3B) → verify READ_BUFFER (0x45) → unlock × 2

use super::Mt1959;
use crate::ld::error::Result;
use crate::scsi::{DataDirection, ScsiTransport};

use super::SCSI_WRITE_BUFFER;

const VERIFY_BUFFER_ID: u8 = 0x45;

/// WRITE_BUFFER carries a 24-bit transfer length, so a firmware blob
/// larger than this cannot be uploaded in one command.
const WRITE_BUFFER_MAX_LEN: usize = 0x00FF_FFFF;

pub(super) fn load_firmware(mt: &mut Mt1959, scsi: &mut dyn ScsiTransport) -> Result<()> {
    let firmware = &mt.profile.firmware;
    if firmware.is_empty() {
        return Err(crate::ld::error::Error::UnlockFailed);
    }

    // Upload firmware via WRITE_BUFFER. The CDB's length is a 24-bit field;
    // if the blob exceeds that, the encoded length would silently disagree
    // with the bytes actually sent (`data`). Reject rather than upload a
    // length-mismatched command.
    let len = firmware.len();
    if len > WRITE_BUFFER_MAX_LEN {
        return Err(crate::ld::error::Error::UnlockFailed);
    }
    let cdb = [
        SCSI_WRITE_BUFFER,
        0x06,
        0x00,
        0x00,
        0x00,
        0x00,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x00,
    ];
    let mut data = firmware.clone();
    scsi.execute(&cdb, DataDirection::ToDevice, &mut data, 30_000)?;

    // Verify the firmware loaded (non-fatal — different buffer_id 0x45). There
    // is no documented expected payload to compare against, so the outcome is
    // TRACED rather than asserted: discarding it with `let _ =` meant a corrupt
    // upload proceeded straight into the do_unlock retries with no diagnostic
    // whatsoever, which is exactly the silent-failure shape this crate exists to
    // avoid.
    let verify_cdb = [
        super::SCSI_READ_BUFFER,
        super::MODE_A,
        VERIFY_BUFFER_ID,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        super::VALIDATE_RESPONSE_SIZE,
        0x00,
    ];
    let mut verify_resp = [0u8; super::VALIDATE_RESPONSE_SIZE as usize];
    match scsi.execute(
        &verify_cdb,
        DataDirection::FromDevice,
        &mut verify_resp,
        5_000,
    ) {
        Ok(r) if r.status == 0 && r.bytes_transferred == verify_resp.len() => {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "mt1959a_fw_verify_ok",
                "variant-A firmware verify read returned a full response"
            );
        }
        Ok(r) => {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "mt1959a_fw_verify_bad",
                status = r.status,
                bytes_transferred = r.bytes_transferred,
                "variant-A firmware verify read did not return a full good response"
            );
        }
        // A dead bus mid-upload must abort, not be swallowed into the unlock
        // retries below.
        Err(e) => {
            let err = crate::ld::error::Error::from(e);
            tracing::warn!(
                target: "freemkv::disc",
                phase = "mt1959a_fw_verify_failed",
                transport_failure = err.is_transport_failure(),
                "variant-A firmware verify read failed"
            );
            if err.is_transport_failure() {
                return Err(err);
            }
        }
    }

    // Double unlock after firmware upload. The first establishes the
    // unlock and is fatal on failure; the second is a confirmation pass and
    // is best-effort (matching variant B), so a benign hiccup on the
    // redundant call doesn't fail an already-successful unlock.
    mt.do_unlock(scsi)?;
    let _ = mt.do_unlock(scsi);
    Ok(())
}
