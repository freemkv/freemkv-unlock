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
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
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
fn unavailable_uniform_vid_is_none() {
    for value in [0, 0xff] {
        let mut t = MockTransport::always(Reply::good(vid_ds_response([value; 16])));
        assert_eq!(read_aacs_vid(&mut t).expect("no fault"), None);
    }
}

/// A rejection surfaced as `Err` WITH a sense (a non-conforming transport)
/// is a drive refusal, not a dead bus → `Ok(None)` VID-miss, never
/// `Err(Transport)`.
#[test]
fn err_with_sense_is_a_vid_miss_not_transport() {
    let mut t = MockTransport::always(Reply::illegal_request_as_err());
    assert_eq!(
        read_aacs_vid(&mut t).expect("a sense is not a dead bus"),
        None
    );
}

/// Only a dead bus is an error.
#[test]
fn transport_fault_propagates() {
    let mut t = MockTransport::always(Reply::TransportFault);
    assert_eq!(read_aacs_vid(&mut t).unwrap_err(), UnlockError::Transport);
}
