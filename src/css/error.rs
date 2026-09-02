//! css's internal error for the CSS bus-auth code. Distinct from
//! [`crate::UnlockError`] (the outcome the consumer sees).

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    /// The CSS bus-authentication challenge-response failed.
    CssAuthFailed,
    /// A SCSI transport-layer fault.
    Scsi(crate::scsi::ScsiError),
}

impl Error {
    /// Stable numeric code (logged). Values are local to this crate.
    pub fn code(&self) -> u16 {
        match self {
            Error::CssAuthFailed => 7201,
            Error::Scsi(_) => 7299,
        }
    }

    /// True if this is a transport-layer SCSI failure (bus dead).
    pub fn is_transport_failure(&self) -> bool {
        matches!(
            self,
            Error::Scsi(s)
                if s.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && s.sense.is_none()
        )
    }
}

/// Collapse a SCSI-layer failure from a bus-auth step onto the CSS auth code —
/// but NEVER a transport fault.
///
/// Every step used to do `.map_err(|_| Error::CssAuthFailed)?`, which discarded
/// the `ScsiError` whole. That made the `Transport` arm of the conversion below
/// UNREACHABLE from any real call site: a dead bus arrived at the consumer as
/// `NotApplicable`, so it fell through and kept probing a bus that was gone.
pub fn step_err(e: crate::scsi::ScsiError) -> Error {
    let err = Error::Scsi(e);
    if err.is_transport_failure() {
        err
    } else {
        Error::CssAuthFailed
    }
}

impl From<crate::scsi::ScsiError> for Error {
    fn from(e: crate::scsi::ScsiError) -> Self {
        Error::Scsi(e)
    }
}

/// CSS bus-auth either enables scrambled reads or it doesn't — any failure means
/// "this unlocker didn't apply" (a transport fault still surfaces as Transport).
impl From<Error> for crate::UnlockError {
    fn from(e: Error) -> Self {
        if e.is_transport_failure() {
            crate::UnlockError::Transport
        } else {
            crate::UnlockError::NotApplicable
        }
    }
}

#[cfg(test)]
mod tests {
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
}
