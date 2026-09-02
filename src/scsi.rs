//! The SCSI transport contract every unlocker issues CDBs through. The consumer
//! (libfreemkv) implements [`ScsiTransport`] over its own SCSI; the unlockers
//! never see a concrete transport. Common MMC/SPC opcodes live here too.

/// Direction of a SCSI data transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    None,
    FromDevice,
    ToDevice,
}

/// Result of a SCSI command: status byte, bytes transferred, raw sense.
#[derive(Debug, Clone)]
pub struct ScsiResult {
    pub status: u8,
    pub bytes_transferred: usize,
    pub sense: [u8; 32],
}

/// A transport-layer SCSI failure (the command could not complete — bridge
/// crash / disconnect), as opposed to a drive sense returned in [`ScsiResult`].
#[derive(Debug, Clone)]
pub struct ScsiError {
    pub status: u8,
    pub sense: Option<[u8; 32]>,
}

/// Transport-layer result.
pub type Result<T> = std::result::Result<T, ScsiError>;

/// The one capability an unlocker needs from the host: run a raw CDB. `Ok` even
/// on a SCSI sense (inspect `status`); `Err` only on a transport-layer fault.
pub trait ScsiTransport {
    fn execute(
        &mut self,
        cdb: &[u8],
        direction: DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<ScsiResult>;
}

/// Parsed SCSI sense (the diagnostic an unlocker reads off a failed command).
#[derive(Debug, Clone, Copy)]
pub struct ScsiSense {
    pub sense_key: u8,
    pub asc: u8,
    pub ascq: u8,
}

impl ScsiSense {
    /// Parse the fixed-format sense buffer (key at byte 2, ASC at 12, ASCQ at 13).
    pub fn from_buf(sense: &[u8; 32]) -> Self {
        ScsiSense {
            sense_key: sense[2] & 0x0F,
            asc: sense[12],
            ascq: sense[13],
        }
    }
    /// ILLEGAL REQUEST (sense key 0x05) — the drive won't honor the command.
    pub fn is_illegal_request(&self) -> bool {
        self.sense_key == 0x05
    }
}

/// SCSI status byte for a transport-layer failure (bridge crash / disconnect).
pub(crate) const SCSI_STATUS_TRANSPORT_FAILURE: u8 = 0xFF;
/// SCSI status byte CHECK CONDITION (a drive sense is available). Part of the
/// status contract; currently referenced only by tests asserting the
/// transport-vs-check-condition distinction.
#[allow(dead_code)]
pub(crate) const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;

// Common opcodes used by the unlocker modules.
pub(crate) const SCSI_SET_CD_SPEED: u8 = 0xBB;
pub(crate) const SCSI_SEND_KEY: u8 = 0xA3;
pub(crate) const SCSI_REPORT_KEY: u8 = 0xA4;
pub(crate) const SCSI_READ_DISC_STRUCTURE: u8 = 0xAD;
pub(crate) const SCSI_GET_CONFIGURATION: u8 = 0x46;
/// AACS key class selector used in REPORT/SEND KEY CDBs.
pub(crate) const AACS_KEY_CLASS: u8 = 0x02;

/// Build a SET CD SPEED (0xBB) CDB requesting `read_speed` (KB/s; 0xFFFF = max).
pub(crate) fn build_set_cd_speed(read_speed: u16) -> [u8; 12] {
    [
        SCSI_SET_CD_SPEED,
        0x00,
        (read_speed >> 8) as u8,
        read_speed as u8,
        0xFF,
        0xFF,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
}

// ── Test fixture ────────────────────────────────────────────────────────────
// Crate-wide mock transport, able to express all three transport outcomes.
// See docs/scsi-mock-fixture.md — why this fixture exists
#[cfg(test)]
#[allow(dead_code)] // a fixture: each helper is used by a subset of the modules
pub(crate) mod mock {
    use super::*;
    use std::collections::VecDeque;

    /// One scripted answer to one `execute()` call.
    #[derive(Debug, Clone)]
    pub(crate) enum Reply {
        /// `Ok` + GOOD status. `payload` is copied into the caller's buffer;
        /// `bytes_transferred` defaults to the number of bytes copied.
        Data {
            payload: Vec<u8>,
            bytes_transferred: Option<usize>,
        },
        /// `Ok` + a NON-ZERO SCSI status (CHECK CONDITION) with a drive sense.
        /// Per the contract at [`ScsiTransport::execute`] this is NOT a
        /// transport fault — the caller must inspect `status`, and a caller that
        /// doesn't will consume the caller's zero-filled buffer as drive data.
        Sense {
            status: u8,
            sense_key: u8,
            asc: u8,
            ascq: u8,
        },
        /// `Err` with the transport-failure status and no sense — a genuine
        /// transport-layer fault (bridge crash / disconnect). MUST abort.
        TransportFault,
        /// `Err` carrying a real status + parsed sense. This is what a
        /// NON-conforming transport does (libfreemkv's adapter returns `Err` for
        /// any non-zero SCSI status); classification must still treat it as a
        /// drive rejection, not a dead bus.
        ErrWithSense {
            status: u8,
            sense_key: u8,
            asc: u8,
            ascq: u8,
        },
    }

    impl Reply {
        /// `Ok`, GOOD status, full transfer of `payload`.
        pub(crate) fn good(payload: Vec<u8>) -> Reply {
            Reply::Data {
                payload,
                bytes_transferred: None,
            }
        }
        /// `Ok`, GOOD status, but the drive only delivered `n` bytes.
        pub(crate) fn short(payload: Vec<u8>, n: usize) -> Reply {
            Reply::Data {
                payload,
                bytes_transferred: Some(n),
            }
        }
        /// `Ok`, GOOD status, ZERO bytes delivered — the buffer the caller reads
        /// is entirely its own zero fill.
        pub(crate) fn zero_transfer(len: usize) -> Reply {
            Reply::Data {
                payload: vec![0u8; len],
                bytes_transferred: Some(0),
            }
        }
        /// `Ok` + CHECK CONDITION / ILLEGAL REQUEST (0x05, ASC 0x20 invalid
        /// command) — the ordinary way a drive refuses a vendor command.
        pub(crate) fn illegal_request() -> Reply {
            Reply::Sense {
                status: SCSI_STATUS_CHECK_CONDITION,
                sense_key: 0x05,
                asc: 0x20,
                ascq: 0x00,
            }
        }
        /// `Err` + CHECK CONDITION / ILLEGAL REQUEST — the same drive refusal as
        /// seen through a non-conforming transport.
        pub(crate) fn illegal_request_as_err() -> Reply {
            Reply::ErrWithSense {
                status: SCSI_STATUS_CHECK_CONDITION,
                sense_key: 0x05,
                asc: 0x20,
                ascq: 0x00,
            }
        }
    }

    fn sense_buf(sense_key: u8, asc: u8, ascq: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[2] = sense_key & 0x0F;
        b[12] = asc;
        b[13] = ascq;
        b
    }

    /// A scripted transport: answers each `execute()` from `script`, falling
    /// back to `default` once the script runs out, and records every CDB.
    pub(crate) struct MockTransport {
        pub(crate) script: VecDeque<Reply>,
        pub(crate) default: Reply,
        pub(crate) cdbs: Vec<Vec<u8>>,
    }

    impl MockTransport {
        /// Every command gets the same answer.
        pub(crate) fn always(reply: Reply) -> Self {
            MockTransport {
                script: VecDeque::new(),
                default: reply,
                cdbs: Vec::new(),
            }
        }
        /// The first N commands follow `script`; the rest get `default`.
        pub(crate) fn scripted(script: Vec<Reply>, default: Reply) -> Self {
            MockTransport {
                script: script.into(),
                default,
                cdbs: Vec::new(),
            }
        }
        /// How many CDBs were issued (lets a test assert a dead bus aborted
        /// instead of retrying).
        pub(crate) fn calls(&self) -> usize {
            self.cdbs.len()
        }
    }

    impl ScsiTransport for MockTransport {
        fn execute(
            &mut self,
            cdb: &[u8],
            _direction: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            self.cdbs.push(cdb.to_vec());
            let reply = self
                .script
                .pop_front()
                .unwrap_or_else(|| self.default.clone());
            match reply {
                Reply::Data {
                    payload,
                    bytes_transferred,
                } => {
                    let n = payload.len().min(data.len());
                    data[..n].copy_from_slice(&payload[..n]);
                    Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: bytes_transferred.unwrap_or(n),
                        sense: [0u8; 32],
                    })
                }
                Reply::Sense {
                    status,
                    sense_key,
                    asc,
                    ascq,
                } => Ok(ScsiResult {
                    status,
                    bytes_transferred: 0,
                    sense: sense_buf(sense_key, asc, ascq),
                }),
                Reply::TransportFault => Err(ScsiError {
                    status: SCSI_STATUS_TRANSPORT_FAILURE,
                    sense: None,
                }),
                Reply::ErrWithSense {
                    status,
                    sense_key,
                    asc,
                    ascq,
                } => Err(ScsiError {
                    status,
                    sense: Some(sense_buf(sense_key, asc, ascq)),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock::{MockTransport, Reply};

    /// The fixed-format sense layout the whole crate reads its diagnostics off
    /// (key at byte 2 low nibble, ASC at 12, ASCQ at 13). This file had no test
    /// at all, so nothing pinned the offsets.
    #[test]
    fn sense_parses_at_the_fixed_format_offsets() {
        let mut buf = [0u8; 32];
        buf[2] = 0xF5; // sense key is the LOW nibble only
        buf[12] = 0x24;
        buf[13] = 0x01;
        let s = ScsiSense::from_buf(&buf);
        assert_eq!(s.sense_key, 0x05);
        assert_eq!(s.asc, 0x24);
        assert_eq!(s.ascq, 0x01);
        assert!(s.is_illegal_request());

        buf[2] = 0x02; // NOT READY
        assert!(!ScsiSense::from_buf(&buf).is_illegal_request());
    }

    /// SET CD SPEED encodes the read speed big-endian at bytes 2-3 and leaves
    /// the write speed at 0xFFFF.
    #[test]
    fn set_cd_speed_encodes_the_read_speed_big_endian() {
        let cdb = build_set_cd_speed(0x1234);
        assert_eq!(cdb[0], SCSI_SET_CD_SPEED);
        assert_eq!([cdb[2], cdb[3]], [0x12, 0x34]);
        assert_eq!([cdb[4], cdb[5]], [0xFF, 0xFF]);
        assert_eq!(build_set_cd_speed(0xFFFF)[2..4], [0xFF, 0xFF]);
    }

    // The fixture must honour the contract it tests: a drive sense is `Ok`
    // with non-zero status, a bus fault is `Err`. If this drifts, every
    // transport-contract test built on it silently stops testing anything.
    #[test]
    fn mock_transport_expresses_the_three_contract_outcomes() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(vec![0xAB; 4]),
                Reply::illegal_request(),
                Reply::zero_transfer(4),
            ],
            Reply::TransportFault,
        );
        let mut buf = [0u8; 4];

        let r = t
            .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
            .expect("data reply is Ok");
        assert_eq!(r.status, 0);
        assert_eq!(r.bytes_transferred, 4);
        assert_eq!(buf, [0xAB; 4]);

        let r = t
            .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
            .expect("A DRIVE SENSE IS Ok, NOT Err — the load-bearing contract");
        assert_eq!(r.status, SCSI_STATUS_CHECK_CONDITION);
        assert!(ScsiSense::from_buf(&r.sense).is_illegal_request());

        let r = t
            .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
            .expect("a zero-length transfer is still Ok");
        assert_eq!(r.bytes_transferred, 0);

        let e = t
            .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
            .expect_err("a transport fault is Err");
        assert_eq!(e.status, SCSI_STATUS_TRANSPORT_FAILURE);
        assert!(e.sense.is_none(), "a bus fault carries no drive sense");

        assert_eq!(t.calls(), 4);
    }
}
