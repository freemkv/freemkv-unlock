//! Shared AACS Volume ID read — the standard `READ DISC STRUCTURE` (`0xAD`,
//! format `0x80`) that returns the VID on a drive whose host-auth / bus has
//! already been opened by a compatible firmware unlock (freemkv Raw Read or
//! MT1959). The Pioneer runtime hook implements the same response layout.
//!
//! BEST-EFFORT: only a dead bus is an `Err(Transport)`. A CHECK CONDITION, a
//! short response, or an all-zero VID all yield `Ok(None)` — a VID miss must
//! never discard an unlock that already removed the bus (a key source can still
//! supply the key).

use crate::UnlockError;
use crate::scsi::{DataDirection, ScsiTransport, is_dead_bus};

/// The 16-byte AACS Volume ID.
const VID_LEN: usize = 16;
/// `READ DISC STRUCTURE` format for the Volume ID.
const DISC_STRUCT_FMT_VID: u8 = 0x80;
/// Response length: a 4-byte header, the 16-byte VID, and a 16-byte MAC. On the
/// bare-read path (no bus key) the MAC can't be verified and is ignored.
const VID_STRUCT_LEN: u16 = 36;

/// The standard `0xAD` fmt-`0x80` (Blu-ray, AGID 0) Volume ID CDB — NOT a vendor
/// knock; valid once the drive's bus/host-auth is open. Mirrors libfreemkv's
/// `read_volume_id`.
pub(crate) fn build_vid_cdb() -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_READ_DISC_STRUCTURE;
    cdb[1] = 0x01; // Blu-ray
    cdb[7] = DISC_STRUCT_FMT_VID;
    cdb[8] = (VID_STRUCT_LEN >> 8) as u8;
    cdb[9] = (VID_STRUCT_LEN & 0xFF) as u8;
    // cdb[10] = agid << 6; AGID 0 on the bare path (no AKE) → 0.
    cdb
}

/// Read the AACS VID with the bare `0xAD` fmt `0x80` (valid only after the drive
/// is unlocked). `Ok(Some(vid))` on a well-formed non-zero VID; `Ok(None)` for
/// any "no VID" outcome (rejected / short / all-zero); `Err(Transport)` only on
/// a dead bus.
pub fn read_aacs_vid(
    scsi: &mut dyn ScsiTransport,
) -> std::result::Result<Option<[u8; 16]>, UnlockError> {
    let cdb = build_vid_cdb();
    let mut buf = [0u8; VID_STRUCT_LEN as usize];
    let result = match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
        Ok(r) => r,
        Err(e) => {
            if is_dead_bus(&e) {
                return Err(UnlockError::Transport);
            }
            tracing::debug!(
                target: "freemkv::disc",
                phase = "vid_rejected_as_err",
                status = e.status,
                "bare VID read rejected (via Err); no Volume ID"
            );
            return Ok(None);
        }
    };
    // A drive sense arrives as Ok with a non-zero status; without this check a
    // CHECK CONDITION's zero-filled buffer would parse as a VID.
    if result.status != 0 {
        tracing::debug!(
            target: "freemkv::disc",
            phase = "vid_check_condition",
            status = result.status,
            "bare VID read returned a drive sense (no medium / drive not open)"
        );
        return Ok(None);
    }
    // Need the 4-byte header + the 16-byte VID.
    if result.bytes_transferred < 4 + VID_LEN {
        tracing::debug!(
            target: "freemkv::disc",
            phase = "vid_short_response",
            bytes_transferred = result.bytes_transferred,
            "bare VID response too short"
        );
        return Ok(None);
    }
    let mut vid = [0u8; VID_LEN];
    vid.copy_from_slice(&buf[4..4 + VID_LEN]);
    // Preserve both backends' rejection of empty/unavailable hardware values.
    if vid.iter().all(|&b| b == 0) || vid.iter().all(|&b| b == 0xff) {
        tracing::debug!(
            target: "freemkv::disc",
            phase = "vid_uniform",
            "bare VID read returned an unavailable Volume ID"
        );
        return Ok(None);
    }
    tracing::debug!(target: "freemkv::disc", phase = "vid_ok", "Volume ID retrieved via bare 0xAD read");
    Ok(Some(vid))
}

#[cfg(test)]
#[path = "vid_tests.rs"]
mod tests;
