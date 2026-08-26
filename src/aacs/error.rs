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
    /// A handshake step returned FEWER bytes than the protocol step requires.
    /// The buffer the step would have parsed is the caller's own zero fill, so
    /// consuming it would turn a failed command into a "successful" handshake
    /// step built entirely out of zeros.
    ShortTransfer {
        opcode: u8,
        expected: usize,
        got: usize,
    },
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
            Error::ShortTransfer { .. } => 7015,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant has its own stable numeric code. Constructing all 16
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
}
