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
    ScsiError {
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
            Error::ScsiError { opcode, status, .. } => {
                write!(f, "SCSI error (opcode {opcode:#04x}, status {status:#04x})")
            }
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// True if this is a transport-layer SCSI failure (bus dead), as opposed to a
    /// drive sense or a logical failure.
    pub(crate) fn is_transport_failure(&self) -> bool {
        matches!(
            self,
            Error::ScsiError { status, sense: None, .. }
                if *status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE
        )
    }
}

/// A generic transport fault from the SCSI contract converts into ld's error
/// (the opcode is unknown at the transport level).
impl From<crate::scsi::ScsiError> for Error {
    fn from(e: crate::scsi::ScsiError) -> Self {
        Error::ScsiError {
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
