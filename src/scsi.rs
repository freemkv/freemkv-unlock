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
///
/// **Stop (cancellation).** The host may cancel the operation. After a cancel,
/// [`execute`](Self::execute) refuses with a dead-bus [`ScsiError`] (status 0xFF,
/// no sense), so every unlocker aborts through its existing transport-fault path.
/// The four defaulted methods let a cancellable host keep the drive safe. A host
/// with no cancellation keeps the defaults: plain sleep, no-op critical spans, and
/// cleanup CDBs that run as ordinary CDBs.
pub trait ScsiTransport {
    fn execute(
        &mut self,
        cdb: &[u8],
        direction: DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<ScsiResult>;

    /// Wait `d` between drive attempts. A cancellable host returns `Err` (dead
    /// bus) as soon as the operation is cancelled, instead of finishing the wait.
    fn pause(&mut self, d: std::time::Duration) -> Result<()> {
        std::thread::sleep(d);
        Ok(())
    }

    /// Open a critical span (see [`CriticalGuard`]): until the matching
    /// [`end_critical`](Self::end_critical), `execute` must run even if the
    /// operation is cancelled meanwhile. `Err` if it is already cancelled.
    fn begin_critical(&mut self) -> Result<()> {
        Ok(())
    }

    /// Close the span opened by [`begin_critical`](Self::begin_critical).
    fn end_critical(&mut self) {}

    /// Run a clean-up CDB that must reach the drive even after a cancel (the
    /// host allows only an AGID release it recorded, never an arbitrary CDB).
    fn execute_cleanup(
        &mut self,
        cdb: &[u8],
        direction: DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<ScsiResult> {
        self.execute(cdb, direction, data, timeout_ms)
    }
}

/// A critical span on a transport: [`CriticalGuard::enter`] calls
/// [`ScsiTransport::begin_critical`] and `Drop` calls
/// [`ScsiTransport::end_critical`], on every exit including unwind. Used where
/// abandoning a CDB sequence midway could leave the drive unusable (a firmware
/// upload): a cancel that lands inside the span takes effect when it closes.
pub struct CriticalGuard<'a> {
    t: &'a mut (dyn ScsiTransport + 'a),
}

impl<'a> CriticalGuard<'a> {
    /// Open the span; `Err` (and no span) if the operation is already cancelled.
    pub fn enter(t: &'a mut (dyn ScsiTransport + 'a)) -> Result<Self> {
        t.begin_critical()?;
        Ok(CriticalGuard { t })
    }
}

impl Drop for CriticalGuard<'_> {
    fn drop(&mut self) {
        self.t.end_critical();
    }
}

impl<'a> std::ops::Deref for CriticalGuard<'a> {
    type Target = dyn ScsiTransport + 'a;
    fn deref(&self) -> &Self::Target {
        &*self.t
    }
}

impl<'a> std::ops::DerefMut for CriticalGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.t
    }
}

/// Timeout for the AGID release CDB (the 5 s every AACS/CSS key CDB uses).
const AGID_RELEASE_TIMEOUT_MS: u32 = 5_000;

/// An allocated AGID (Authentication Grant ID) on a transport. `Drop` releases it
/// with its REPORT KEY key-format 3Fh CDB, sent through
/// [`ScsiTransport::execute_cleanup`] so a cancelled operation still frees it.
/// [`AgidGuard::defuse`] instead hands the still-held AGID to the caller.
/// Exactly one release per allocation: the guard is the only releaser.
pub struct AgidGuard<'a> {
    t: &'a mut (dyn ScsiTransport + 'a),
    agid: u8,
    release: [u8; 12],
    armed: bool,
}

impl<'a> AgidGuard<'a> {
    /// Guard `agid`. `release` is its REPORT KEY (0xA4) key-format 3Fh CDB, built
    /// by the caller so each scheme (AACS key class 2, CSS) keeps its exact bytes.
    pub fn new(t: &'a mut (dyn ScsiTransport + 'a), agid: u8, release: [u8; 12]) -> Self {
        // SS-7 (evidence, not spec): REPORT KEY key format 3Fh invalidates the AGID
        // carried in CDB byte 10 bits 7-6 (libaacs mmc.c; the unlock AGID tests).
        debug_assert!(
            release[0] == SCSI_REPORT_KEY && release[10] == ((agid & 0x03) << 6) | 0x3F,
            "AgidGuard needs this AGID's REPORT KEY format-3Fh CDB"
        );
        AgidGuard {
            t,
            agid,
            release,
            armed: true,
        }
    }

    /// The guarded AGID.
    pub fn agid(&self) -> u8 {
        self.agid
    }

    /// Hand the AGID over to the caller, still allocated: nothing is released.
    pub fn defuse(mut self) -> u8 {
        self.armed = false;
        self.agid
    }
}

// Manual Debug: the transport is not `Debug`; the AGID and whether it is still
// armed (will be released on drop) are what a failure message needs.
impl std::fmt::Debug for AgidGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgidGuard")
            .field("agid", &self.agid)
            .field("armed", &self.armed)
            .finish()
    }
}

impl Drop for AgidGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Buffer = the CDB's allocation length (AACS: 2), or 8 when it names none (CSS).
        let alloc = ((self.release[8] as usize) << 8) | self.release[9] as usize;
        let mut buf = vec![0u8; if alloc == 0 { 8 } else { alloc }];
        // Best-effort: a failed release is not a failure of the operation.
        let r = self.t.execute_cleanup(
            &self.release,
            DataDirection::FromDevice,
            &mut buf,
            AGID_RELEASE_TIMEOUT_MS,
        );
        tracing::debug!(
            target: "freemkv::disc",
            phase = "agid_released",
            agid = self.agid,
            ok = r.as_ref().is_ok_and(|r| r.status == 0),
            "AGID release (REPORT KEY format 3Fh) sent"
        );
    }
}

impl<'a> std::ops::Deref for AgidGuard<'a> {
    type Target = dyn ScsiTransport + 'a;
    fn deref(&self) -> &Self::Target {
        &*self.t
    }
}

impl<'a> std::ops::DerefMut for AgidGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.t
    }
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
/// Whether a transport error is a genuine dead bus (a senseless transport-failure
/// status) rather than a drive rejection surfaced through a non-conforming
/// transport (`Err` carrying a sense).
pub(crate) fn is_dead_bus(e: &ScsiError) -> bool {
    e.status == SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none()
}

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

// ── Test fixture ──────────────────────────────────────────────────────────── Crate-wide mock
// transport, able to express all three transport outcomes.
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

    // UT1 (stop-design-v5 §5.2; §2.3 "`enter` calls `begin_critical()?`. `Drop` calls
    // `end_critical`"): refused after a cancel; closed on drop AND on unwind.
    #[test]
    fn critical_guard_refused_after_cancel_and_ends_on_unwind() {
        use mock::{Ev, StopFake};
        let mut t = StopFake::new(MockTransport::always(Reply::good(vec![0u8; 4])));
        {
            let mut g = CriticalGuard::enter(&mut t).expect("not cancelled: opens");
            g.execute(&[0x3B], DataDirection::ToDevice, &mut [0u8; 4], 0)
                .expect("inside the span");
        }
        assert_eq!(t.log[0], Ev::Begin);
        assert_eq!(t.log.last(), Some(&Ev::End), "closed on drop");

        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = CriticalGuard::enter(&mut t).expect("opens");
            panic!("unwind inside the span");
        }));
        assert!(r.is_err());
        assert_eq!(t.log.last(), Some(&Ev::End), "closed on unwind");

        t.cancelled = true;
        let e = CriticalGuard::enter(&mut t)
            .err()
            .expect("refused after a cancel");
        assert!(is_dead_bus(&e), "a refusal is the dead-bus shape");
        assert_eq!(t.log.last(), Some(&Ev::BeginRefused), "no span, so no End");
        let begins = t.log.iter().filter(|e| **e == Ev::Begin).count();
        let ends = t.log.iter().filter(|e| **e == Ev::End).count();
        assert_eq!(begins, ends, "every opened span closed exactly once");
    }

    // The defaults keep all 32 existing transports compiling and behaving as
    // before: pause sleeps, spans are no-ops, cleanup is a plain execute.
    #[test]
    fn default_stop_methods_preserve_plain_transport_behaviour() {
        let mut t = MockTransport::always(Reply::good(vec![0u8; 2]));
        let t0 = std::time::Instant::now();
        t.pause(std::time::Duration::from_millis(20))
            .expect("plain sleep");
        assert!(t0.elapsed() >= std::time::Duration::from_millis(20));
        t.begin_critical().expect("no-op");
        t.end_critical();
        t.execute_cleanup(&[0xA4], DataDirection::FromDevice, &mut [0u8; 2], 0)
            .expect("plain execute");
        assert_eq!(t.cdbs, vec![vec![0xA4]], "cleanup reached the drive once");
    }

    // SS-7 (evidence): the guard's drop sends its REPORT KEY 3Fh CDB once, via
    // execute_cleanup, even after a cancel; `defuse` sends nothing.
    #[test]
    fn agid_guard_releases_once_via_cleanup_and_defuse_keeps_it() {
        use mock::{Ev, StopFake};
        let mut rel = [0u8; 12];
        rel[0] = SCSI_REPORT_KEY;
        rel[10] = (2 << 6) | 0x3F;
        let mut t = StopFake::new(MockTransport::always(Reply::good(vec![0u8; 8])));
        t.cancelled = true;
        drop(AgidGuard::new(&mut t, 2, rel));
        assert_eq!(t.log, vec![Ev::Cleanup(rel.to_vec())]);

        t.log.clear();
        let g = AgidGuard::new(&mut t, 2, rel);
        assert_eq!(g.agid(), 2);
        assert_eq!(g.defuse(), 2);
        assert!(t.log.is_empty(), "defuse hands the AGID over unreleased");
    }
}
