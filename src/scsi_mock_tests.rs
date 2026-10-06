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

/// One transport call as seen by [`StopFake`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ev {
    /// `execute` reached the drive.
    Exec(Vec<u8>),
    /// `execute` refused because the operation was cancelled.
    Refused(Vec<u8>),
    /// `execute_cleanup` reached the drive.
    Cleanup(Vec<u8>),
    Pause(std::time::Duration),
    PauseRefused(std::time::Duration),
    Begin,
    BeginRefused,
    End,
}

/// A cancellable host, as libfreemkv's adapter behaves (stop-design-v5 §2.3,
/// §2.4): after a cancel, `execute` refuses with 0xFF / no sense unless a
/// critical span opened BEFORE the cancel is still open; `begin_critical` and
/// `pause` fail; `execute_cleanup` still runs. Wraps a drive emulator `inner`.
pub(crate) struct StopFake<T> {
    pub(crate) inner: T,
    pub(crate) cancelled: bool,
    critical: u32,
    /// Cancel right after a CDB matching this predicate reaches the drive
    /// (a Stop that lands while that CDB is in flight).
    pub(crate) cancel_after: Option<fn(&[u8]) -> bool>,
    /// Cancel when the next `pause` starts (a Stop during the wait).
    pub(crate) cancel_on_pause: bool,
    pub(crate) log: Vec<Ev>,
}

fn refused() -> ScsiError {
    ScsiError {
        status: SCSI_STATUS_TRANSPORT_FAILURE,
        sense: None,
    }
}

impl<T> StopFake<T> {
    pub(crate) fn new(inner: T) -> Self {
        StopFake {
            inner,
            cancelled: false,
            critical: 0,
            cancel_after: None,
            cancel_on_pause: false,
            log: Vec::new(),
        }
    }
    /// CDBs that reached the drive through `execute`.
    pub(crate) fn execs(&self) -> Vec<&Vec<u8>> {
        self.log
            .iter()
            .filter_map(|e| match e {
                Ev::Exec(c) => Some(c),
                _ => None,
            })
            .collect()
    }
    /// CDBs that reached the drive through `execute_cleanup`.
    pub(crate) fn cleanups(&self) -> Vec<&Vec<u8>> {
        self.log
            .iter()
            .filter_map(|e| match e {
                Ev::Cleanup(c) => Some(c),
                _ => None,
            })
            .collect()
    }
}

impl<T: ScsiTransport> ScsiTransport for StopFake<T> {
    fn execute(
        &mut self,
        cdb: &[u8],
        dir: DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<ScsiResult> {
        if self.cancelled && self.critical == 0 {
            self.log.push(Ev::Refused(cdb.to_vec()));
            return Err(refused());
        }
        self.log.push(Ev::Exec(cdb.to_vec()));
        let r = self.inner.execute(cdb, dir, data, timeout_ms);
        if self.cancel_after.is_some_and(|p| p(cdb)) {
            self.cancelled = true;
        }
        r
    }
    fn pause(&mut self, d: std::time::Duration) -> Result<()> {
        if self.cancel_on_pause {
            self.cancelled = true;
        }
        if self.cancelled {
            self.log.push(Ev::PauseRefused(d));
            return Err(refused());
        }
        self.log.push(Ev::Pause(d)); // no real sleep: tests run in microseconds
        Ok(())
    }
    fn begin_critical(&mut self) -> Result<()> {
        if self.cancelled {
            self.log.push(Ev::BeginRefused);
            return Err(refused());
        }
        self.critical += 1;
        self.log.push(Ev::Begin);
        Ok(())
    }
    fn end_critical(&mut self) {
        self.critical -= 1;
        self.log.push(Ev::End);
    }
    fn execute_cleanup(
        &mut self,
        cdb: &[u8],
        dir: DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<ScsiResult> {
        self.log.push(Ev::Cleanup(cdb.to_vec()));
        self.inner.execute(cdb, dir, data, timeout_ms)
    }
}

/// REPORT KEY (0xA4) key format 0x3F (AGID invalidate / release).
pub(crate) fn is_agid_release(cdb: &[u8]) -> bool {
    cdb.first() == Some(&SCSI_REPORT_KEY) && cdb.get(10).is_some_and(|b| b & 0x3F == 0x3F)
}
/// REPORT KEY (0xA4) key format 0x00 (AGID allocation).
pub(crate) fn is_agid_alloc(cdb: &[u8]) -> bool {
    cdb.first() == Some(&SCSI_REPORT_KEY) && cdb.get(10).is_some_and(|b| b & 0x3F == 0x00)
}

/// SS-7 (evidence): every allocated AGID is released exactly once, through
/// `execute_cleanup`, before the next allocation; `execute` never releases a
/// held AGID (it only invalidates beforehand). Returns (allocations, held at end).
pub(crate) fn agid_ledger(log: &[Ev]) -> (usize, bool) {
    let (mut allocs, mut held) = (0usize, false);
    for (i, e) in log.iter().enumerate() {
        match e {
            Ev::Exec(c) if is_agid_alloc(c) => {
                assert!(!held, "event {i}: allocated while still holding an AGID");
                held = true;
                allocs += 1;
            }
            Ev::Exec(c) if is_agid_release(c) => {
                assert!(!held, "event {i}: a held AGID was released via execute");
            }
            Ev::Cleanup(c) => {
                assert!(
                    is_agid_release(c),
                    "event {i}: cleanup of a non-release CDB"
                );
                assert!(held, "event {i}: released an AGID that was not held");
                held = false;
            }
            _ => {}
        }
    }
    (allocs, held)
}
