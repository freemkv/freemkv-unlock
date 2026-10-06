use super::*;
use crate::UnlockError;
use crate::scsi::{SCSI_STATUS_CHECK_CONDITION, SCSI_STATUS_TRANSPORT_FAILURE, ScsiError};

/// The abort/fall-through boundary, which had no test at all. Catches
/// widening `is_transport_failure` (every failure would abort every rip) or
/// narrowing it (a dead bus would be probed forever).
#[test]
fn only_a_senseless_transport_status_is_a_transport_failure() {
    let dead_bus = Error::Scsi {
        opcode: 0x3C,
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: None,
    };
    assert!(dead_bus.is_transport_failure());
    assert_eq!(UnlockError::from(dead_bus), UnlockError::Transport);

    // A CHECK CONDITION is the DRIVE refusing, not the bus dying.
    let refused = Error::Scsi {
        opcode: 0x3C,
        status: SCSI_STATUS_CHECK_CONDITION,
        sense: Some([0u8; 32]),
    };
    assert!(!refused.is_transport_failure());
    assert_eq!(UnlockError::from(refused), UnlockError::NotApplicable);

    // The transport-failure status WITH a sense is a drive that reported
    // 0xFF, not a bus fault — it must not abort the consumer.
    let odd = Error::Scsi {
        opcode: 0x3C,
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: Some([0u8; 32]),
    };
    assert!(!odd.is_transport_failure());

    for e in [
        Error::ProfileParse,
        Error::UnlockFailed,
        Error::SignatureMismatch {
            expected: [0; 4],
            got: [1; 4],
        },
    ] {
        assert!(!e.is_transport_failure(), "{e:?} is not a bus fault");
        assert_eq!(UnlockError::from(e), UnlockError::NotApplicable);
    }
}

/// `Display` is what shows up in logs — every variant must render without
/// panicking and the SCSI variant must carry the opcode/status through.
#[test]
fn display_renders_every_variant() {
    assert_eq!(Error::ProfileParse.to_string(), "drive profile parse error");
    assert_eq!(Error::UnlockFailed.to_string(), "firmware unlock failed");
    assert_eq!(
        Error::SignatureMismatch {
            expected: [0; 4],
            got: [1; 4],
        }
        .to_string(),
        "signature mismatch"
    );
    assert_eq!(
        Error::Scsi {
            opcode: 0x3C,
            status: 0x02,
            sense: None,
        }
        .to_string(),
        "SCSI error (opcode 0x3c, status 0x02)"
    );
}

/// `From<ScsiError>` must carry the status AND sense across the seam —
/// collapsing either one destroys the transport-vs-rejection distinction the
/// whole abort/fall-through split rests on.
#[test]
fn scsi_error_conversion_preserves_status_and_sense() {
    let e = Error::from(ScsiError {
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: None,
    });
    assert!(e.is_transport_failure());

    let e = Error::from(ScsiError {
        status: SCSI_STATUS_CHECK_CONDITION,
        sense: Some([0u8; 32]),
    });
    assert!(!e.is_transport_failure());
    assert_eq!(UnlockError::from(e), UnlockError::NotApplicable);
}

/// Error codes are stable and distinct — they are the numeric contract the
/// logs carry instead of English.
#[test]
fn error_codes_are_distinct_and_stable() {
    let codes = [
        Error::ProfileParse.code(),
        Error::UnlockFailed.code(),
        Error::SignatureMismatch {
            expected: [0; 4],
            got: [0; 4],
        }
        .code(),
        Error::Scsi {
            opcode: 0,
            status: 0,
            sense: None,
        }
        .code(),
    ];
    assert_eq!(codes, [7101, 7102, 7103, 7199]);
}
