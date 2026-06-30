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
        match e {
            Error::Scsi(s) if s.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE => {
                crate::UnlockError::Transport
            }
            _ => crate::UnlockError::NotApplicable,
        }
    }
}
