use super::*;

/// Every variant has its own stable numeric code. Constructing all 17
/// arms also exercises the `#[allow(dead_code)]` variants that the
/// wired handshake path never builds.
#[test]
fn code_is_stable_per_variant() {
    assert_eq!(Error::AacsAgidAlloc.code(), 7001);
    assert_eq!(Error::AacsCertRead.code(), 7002);
    assert_eq!(Error::AacsCertRejected.code(), 7003);
    assert_eq!(Error::AacsCertShort.code(), 7004);
    assert_eq!(Error::AacsCertVerify.code(), 7005);
    assert_eq!(Error::AacsDataKey.code(), 7006);
    assert_eq!(Error::AacsKeyRead.code(), 7007);
    assert_eq!(Error::AacsKeyRejected.code(), 7008);
    assert_eq!(Error::AacsKeyVerify.code(), 7009);
    assert_eq!(Error::AacsHostSignVerify.code(), 7016);
    assert_eq!(Error::AacsNoKeys.code(), 7010);
    assert_eq!(Error::AacsVidMac.code(), 7011);
    assert_eq!(Error::AacsVidRead.code(), 7012);
    assert_eq!(Error::HandshakeRejected.code(), 7013);
    assert_eq!(Error::VidUnavailable.code(), 7014);
    assert_eq!(
        Error::ShortTransfer {
            opcode: 0xA4,
            expected: 16,
            got: 4,
        }
        .code(),
        7015
    );
    assert_eq!(
        Error::Scsi {
            opcode: 0xA4,
            status: 0x02,
            sense: None,
        }
        .code(),
        7099
    );
}

/// `scsi_sense` returns the parsed sense for a `Scsi` error carrying one,
/// `None` when the `Scsi` error has none, and `None` for every non-`Scsi`
/// variant.
#[test]
fn scsi_sense_returns_the_parsed_sense_only_for_scsi_variant() {
    let sense = ScsiSense {
        sense_key: 0x05,
        asc: 0x20,
        ascq: 0x00,
    };
    let with_sense = Error::Scsi {
        opcode: 0xA4,
        status: 0x02,
        sense: Some(sense),
    };
    let sc = with_sense.scsi_sense().unwrap();
    assert_eq!(sc.sense_key, sense.sense_key);
    assert_eq!(sc.asc, sense.asc);
    assert_eq!(sc.ascq, sense.ascq);

    let without_sense = Error::Scsi {
        opcode: 0xA4,
        status: 0xFF,
        sense: None,
    };
    assert!(without_sense.scsi_sense().is_none());

    assert!(Error::AacsNoKeys.scsi_sense().is_none());
}

/// `is_scsi_transport_failure` is true only for a `Scsi` error with the
/// transport-failure status AND no sense; a drive CHECK CONDITION and
/// every non-`Scsi` variant are false.
#[test]
fn is_scsi_transport_failure_true_and_false_paths() {
    let transport = Error::Scsi {
        opcode: 0,
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: None,
    };
    assert!(transport.is_scsi_transport_failure());

    let check_condition = Error::Scsi {
        opcode: 0xA4,
        status: 0x02,
        sense: Some(ScsiSense {
            sense_key: 0x05,
            asc: 0x20,
            ascq: 0x00,
        }),
    };
    assert!(!check_condition.is_scsi_transport_failure());

    assert!(!Error::AacsNoKeys.is_scsi_transport_failure());
}

/// `From<ScsiError>` maps a raw transport-layer error into `Error::Scsi`,
/// parsing the sense buffer when present and leaving it `None` otherwise.
#[test]
fn from_scsi_error_maps_status_and_parses_sense() {
    let e = Error::from(crate::scsi::ScsiError {
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: None,
    });
    match e {
        Error::Scsi {
            opcode,
            status,
            sense,
        } => {
            assert_eq!(opcode, 0);
            assert_eq!(status, SCSI_STATUS_TRANSPORT_FAILURE);
            assert!(sense.is_none());
        }
        _ => panic!("expected Error::Scsi"),
    }

    let mut buf = [0u8; 32];
    buf[2] = 0x05;
    buf[12] = 0x24;
    buf[13] = 0x01;
    let e = Error::from(crate::scsi::ScsiError {
        status: 0x02,
        sense: Some(buf),
    });
    match e {
        Error::Scsi { status, sense, .. } => {
            assert_eq!(status, 0x02);
            let s = sense.expect("sense parsed");
            assert_eq!(s.sense_key, 0x05);
            assert_eq!(s.asc, 0x24);
            assert_eq!(s.ascq, 0x01);
        }
        _ => panic!("expected Error::Scsi"),
    }
}
