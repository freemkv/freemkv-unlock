//! Shared AACS Volume ID read — the standard `READ DISC STRUCTURE` (`0xAD`,
//! format `0x80`) that returns the VID on a drive whose host-auth / bus has
//! already been opened by a firmware or vendor CDB unlock (freemkv Raw Read,
//! MT1959, or a Pioneer/Renesas vendor open). Because those routes put the
//! drive in the same raw-read state, the VID read is identical across them — so
//! it lives here once.
//!
//! BEST-EFFORT: only a dead bus is an `Err(Transport)`. A CHECK CONDITION, a
//! short response, or an all-zero VID all yield `Ok(None)` — a VID miss must
//! never discard an unlock that already removed the bus (a key source can still
//! supply the key). See docs/freemkv-abi.md for the fixed-length reply rules.

use crate::UnlockError;
use crate::scsi::{DataDirection, ScsiTransport};

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

/// A senseless transport-failure status is a genuine dead bus, not a drive
/// rejection surfaced through a non-conforming transport (`Err` with a sense).
fn is_dead_bus(e: &crate::scsi::ScsiError) -> bool {
    e.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none()
}

/// Read the AACS VID with the bare `0xAD` fmt `0x80` (valid only after the drive
/// is unlocked). `Ok(Some(vid))` on a well-formed non-zero VID; `Ok(None)` for
/// any "no VID" outcome (rejected / short / all-zero); `Err(Transport)` only on
/// a dead bus.
pub(crate) fn read_aacs_vid(
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
    // An all-zero VID is what a permissive stub or an unfilled response leaves
    // behind — reject it rather than pass a bogus key downstream.
    if vid.iter().all(|&b| b == 0) {
        tracing::debug!(
            target: "freemkv::disc",
            phase = "vid_all_zero",
            "bare VID read returned an all-zero Volume ID"
        );
        return Ok(None);
    }
    tracing::debug!(target: "freemkv::disc", phase = "vid_ok", "Volume ID retrieved via bare 0xAD read");
    Ok(Some(vid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::mock::{MockTransport, Reply};

    /// A well-formed format-0x80 VID structure: 4-byte header, 16-byte VID at
    /// offset 4, 16-byte MAC (zeroed on the bare path — it isn't checked).
    fn vid_ds_response(vid: [u8; 16]) -> Vec<u8> {
        let mut p = vec![0u8; VID_STRUCT_LEN as usize];
        p[4..20].copy_from_slice(&vid);
        p
    }

    /// The bare VID read is the STANDARD 0xAD READ DISC STRUCTURE (format 0x80,
    /// Blu-ray, AGID 0, len 36) — NOT a vendor knock.
    #[test]
    fn build_vid_cdb_is_standard_0xad_fmt_80() {
        let cdb = build_vid_cdb();
        assert_eq!(cdb[0], crate::scsi::SCSI_READ_DISC_STRUCTURE);
        assert_eq!(cdb[1], 0x01); // Blu-ray
        assert_eq!(cdb[7], 0x80); // AACS Volume ID
        assert_eq!([cdb[8], cdb[9]], [0x00, 0x24]); // 36, BE16
        assert_eq!(cdb[10], 0x00); // AGID 0 (no AKE)
    }

    /// Parses the VID from response[4..20] and issues exactly one 0xAD read.
    #[test]
    fn reads_and_parses_offset_4() {
        let vid = [0x5Au8; 16];
        let mut t = MockTransport::always(Reply::good(vid_ds_response(vid)));
        let got = read_aacs_vid(&mut t).expect("no fault");
        assert_eq!(got, Some(vid));
        assert_eq!(t.cdbs.len(), 1, "exactly one command");
        assert_eq!(t.cdbs[0][0], crate::scsi::SCSI_READ_DISC_STRUCTURE);
        assert_eq!(t.cdbs[0][7], 0x80);
    }

    /// The MAC region (bytes 20..36) is ignored on the bare path.
    #[test]
    fn ignores_the_unverifiable_mac() {
        let vid: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let mut t = MockTransport::always(Reply::good(vid_ds_response(vid)));
        assert_eq!(read_aacs_vid(&mut t).expect("no fault"), Some(vid));
    }

    /// A response too short to carry header + VID → best-effort `Ok(None)`.
    #[test]
    fn short_response_is_none() {
        let mut t = MockTransport::always(Reply::short(vid_ds_response([0x11; 16]), 19));
        assert_eq!(read_aacs_vid(&mut t).expect("no fault"), None);
    }

    /// A CHECK CONDITION (no medium / drive not open) → `Ok(None)`, never a VID
    /// parsed from the zero fill.
    #[test]
    fn check_condition_is_none() {
        let mut t = MockTransport::always(Reply::illegal_request());
        assert_eq!(read_aacs_vid(&mut t).expect("no fault"), None);
    }

    /// An all-zero VID (permissive stub / unfilled response) → `Ok(None)`.
    #[test]
    fn all_zero_is_none() {
        let mut t = MockTransport::always(Reply::good(vid_ds_response([0u8; 16])));
        assert_eq!(read_aacs_vid(&mut t).expect("no fault"), None);
    }

    /// Only a dead bus is an error.
    #[test]
    fn transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(read_aacs_vid(&mut t).unwrap_err(), UnlockError::Transport);
    }
}
