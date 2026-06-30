//! aacs's internal error for the cert-handshake SCSI/crypto code. Mirrors the
//! handshake's original libfreemkv error surface (the specific Aacs* failure
//! points + a structured SCSI error), so the moved handshake body is unchanged.

use crate::scsi::{SCSI_STATUS_TRANSPORT_FAILURE, ScsiSense};

pub type Result<T> = std::result::Result<T, Error>;

// A few variants are matched (defensive arms in the handshake) but never
// constructed in the wired path — kept for completeness.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Error {
    AacsAgidAlloc,
    AacsCertRead,
    AacsCertRejected,
    AacsCertShort,
    AacsCertVerify,
    AacsDataKey,
    AacsKeyRead,
    AacsKeyRejected,
    AacsKeyVerify,
    AacsNoKeys,
    AacsVidMac,
    AacsVidRead,
    HandshakeRejected,
    VidUnavailable,
    /// A SCSI command failed. `status == SCSI_STATUS_TRANSPORT_FAILURE` with
    /// `sense: None` is a transport-layer fault; a CHECK CONDITION carries the
    /// parsed [`ScsiSense`].
    Scsi {
        /// CDB opcode that failed — diagnostic, carried for future logging.
        opcode: u8,
        status: u8,
        sense: Option<ScsiSense>,
    },
}

impl Error {
    /// Stable numeric code (logged). Values are local to this crate.
    pub fn code(&self) -> u16 {
        match self {
            Error::AacsAgidAlloc => 7001,
            Error::AacsCertRead => 7002,
            Error::AacsCertRejected => 7003,
            Error::AacsCertShort => 7004,
            Error::AacsCertVerify => 7005,
            Error::AacsDataKey => 7006,
            Error::AacsKeyRead => 7007,
            Error::AacsKeyRejected => 7008,
            Error::AacsKeyVerify => 7009,
            Error::AacsNoKeys => 7010,
            Error::AacsVidMac => 7011,
            Error::AacsVidRead => 7012,
            Error::HandshakeRejected => 7013,
            Error::VidUnavailable => 7014,
            Error::Scsi { .. } => 7099,
        }
    }

    /// The parsed sense for a CHECK CONDITION SCSI error, else `None`.
    pub fn scsi_sense(&self) -> Option<ScsiSense> {
        match self {
            Error::Scsi { sense, .. } => *sense,
            _ => None,
        }
    }

    /// True if this is a transport-layer SCSI failure (bus dead).
    pub fn is_scsi_transport_failure(&self) -> bool {
        matches!(
            self,
            Error::Scsi { status, sense: None, .. } if *status == SCSI_STATUS_TRANSPORT_FAILURE
        )
    }
}

/// A generic transport fault from the SCSI contract converts in (opcode unknown
/// at the transport level; sense parsed from the raw buffer when present).
impl From<crate::scsi::ScsiError> for Error {
    fn from(e: crate::scsi::ScsiError) -> Self {
        Error::Scsi {
            opcode: 0,
            status: e.status,
            sense: e.sense.map(|s| ScsiSense::from_buf(&s)),
        }
    }
}
