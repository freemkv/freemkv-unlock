use super::*;
use crate::UnlockError;
use crate::scsi::{SCSI_STATUS_CHECK_CONDITION, SCSI_STATUS_TRANSPORT_FAILURE, ScsiError};

/// Catches restoring the `.map_err(|_| CssAuthFailed)` that made the
/// `Transport` arm unreachable: a dead bus must classify as `Transport`
/// (consumer aborts), a drive rejection as `NotApplicable` (fall through).
#[test]
fn transport_fault_survives_the_step_mapping() {
    let dead = step_err(ScsiError {
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: None,
    });
    assert!(dead.is_transport_failure());
    assert_eq!(UnlockError::from(dead), UnlockError::Transport);

    let refused = step_err(ScsiError {
        status: SCSI_STATUS_CHECK_CONDITION,
        sense: Some([0u8; 32]),
    });
    assert!(matches!(refused, Error::CssAuthFailed));
    assert_eq!(UnlockError::from(refused), UnlockError::NotApplicable);
}

/// Each variant has its own stable numeric code.
#[test]
fn code_is_stable_per_variant() {
    assert_eq!(Error::CssAuthFailed.code(), 7201);
    assert_eq!(
        Error::Scsi(ScsiError {
            status: SCSI_STATUS_CHECK_CONDITION,
            sense: Some([0u8; 32]),
        })
        .code(),
        7299
    );
}

// False for `CssAuthFailed` and for a `Scsi` error with a sense (a
// drive rejection, not a dead bus) even at transport-failure status;
// true only for the genuine transport fault (status + no sense).
#[test]
fn is_transport_failure_false_paths() {
    assert!(!Error::CssAuthFailed.is_transport_failure());

    let sensed = Error::Scsi(ScsiError {
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: Some([0u8; 32]),
    });
    assert!(!sensed.is_transport_failure());

    let refusal = Error::Scsi(ScsiError {
        status: SCSI_STATUS_CHECK_CONDITION,
        sense: None,
    });
    assert!(!refusal.is_transport_failure());

    let dead = Error::Scsi(ScsiError {
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: None,
    });
    assert!(dead.is_transport_failure());
}

/// `From<ScsiError>` wraps the transport error unchanged into `Error::Scsi`.
#[test]
fn from_scsi_error_wraps_into_scsi_variant() {
    let e = Error::from(ScsiError {
        status: SCSI_STATUS_CHECK_CONDITION,
        sense: Some([1u8; 32]),
    });
    match e {
        Error::Scsi(inner) => {
            assert_eq!(inner.status, SCSI_STATUS_CHECK_CONDITION);
            assert_eq!(inner.sense, Some([1u8; 32]));
        }
        _ => panic!("expected Error::Scsi"),
    }
}
