//! ld's internal error type for the firmware-unlock SCSI/handshake code.
//! Distinct from [`crate::UnlockError`] (the unlock OUTCOME the consumer sees);
//! this is the low-level error ld's code uses. Maps both ways: a generic
//! [`crate::scsi::ScsiError`] transport fault converts IN, and an `Error`
//! converts OUT to the contract's `UnlockError`.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A bundled drive profile could not be parsed (malformed hex / length).
    ProfileParse,
    /// A handshake completed but the device did not reach the expected state.
    UnlockFailed,
    /// A verify/handshake response did not match the expected signature.
    SignatureMismatch { expected: [u8; 4], got: [u8; 4] },
    /// A SCSI command failed. `status == SCSI_STATUS_TRANSPORT_FAILURE` with
    /// `sense: None` is a transport-layer fault (bridge crash / disconnect).
    Scsi {
        opcode: u8,
        status: u8,
        sense: Option<[u8; 32]>,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ProfileParse => write!(f, "drive profile parse error"),
            Error::UnlockFailed => write!(f, "firmware unlock failed"),
            Error::SignatureMismatch { .. } => write!(f, "signature mismatch"),
            Error::Scsi { opcode, status, .. } => {
                write!(f, "SCSI error (opcode {opcode:#04x}, status {status:#04x})")
            }
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Stable numeric code (logged). Values are local to this crate and share
    /// the crate-wide space with `aacs` (70xx) and `css` (72xx).
    pub fn code(&self) -> u16 {
        match self {
            Error::ProfileParse => 7101,
            Error::UnlockFailed => 7102,
            Error::SignatureMismatch { .. } => 7103,
            Error::Scsi { .. } => 7199,
        }
    }

    /// True if this is a transport-layer SCSI failure (bus dead), as opposed to a
    /// drive sense or a logical failure.
    pub(crate) fn is_transport_failure(&self) -> bool {
        matches!(
            self,
            Error::Scsi { status, sense: None, .. }
                if *status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE
        )
    }
}

/// A generic transport fault from the SCSI contract converts into ld's error
/// (the opcode is unknown at the transport level).
impl From<crate::scsi::ScsiError> for Error {
    fn from(e: crate::scsi::ScsiError) -> Self {
        Error::Scsi {
            opcode: 0,
            status: e.status,
            sense: e.sense,
        }
    }
}

/// ld's internal error converts OUT to the contract outcome: a dead bus is a
/// hard `Transport` abort; any other firmware failure means "this unlocker
/// didn't apply" → the consumer falls through to the next unlocker.
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
}
