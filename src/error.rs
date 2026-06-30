//! Internal error type shared by the unlocker modules (firmware / handshake /
//! bus-auth). Distinct from [`crate::UnlockError`], which is the unlock OUTCOME
//! the consumer sees; this is the low-level error the SCSI/crypto code uses.

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
