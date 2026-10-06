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
#[path = "scsi_mock_tests.rs"]
pub(crate) mod mock;

#[cfg(test)]
#[path = "scsi_tests.rs"]
mod tests;
