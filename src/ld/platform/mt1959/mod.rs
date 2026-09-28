//! MT1959 platform — shared logic for both variants.

mod variant_a;
mod variant_b;

use super::PlatformDriver;
use crate::ld::error::{Error, Result};
use crate::ld::profile::DriveProfile;
use crate::scsi::{self, DataDirection, ScsiSense, ScsiTransport};
use std::time::Duration;

// ── Variant constants ──────────────────────────────────────────────────
// Every vendor command: 3C [mode] [buffer_id] [sub_cmd] [addr] ...
const MODE_A: u8 = 0x01;
const MODE_B: u8 = 0x02;
const BUFFER_ID_A: u8 = 0x44;
const BUFFER_ID_B: u8 = 0x77;

// ── SCSI opcodes ──────────────────────────────────────────────────────
const SCSI_READ_BUFFER: u8 = 0x3C;
const SCSI_READ_CAPACITY: u8 = 0x25;
const SCSI_TEST_UNIT_READY: u8 = 0x00;
/// Shared by both firmware-upload variants (see `variant_a` / `variant_b`).
pub(super) const SCSI_WRITE_BUFFER: u8 = 0x3B;

// ── Sub-commands (shared A/B) ─────────────────────────────────────────
const SUB_CMD_UNLOCK: u8 = 0x00;
const SUB_CMD_INIT: u8 = 0x12;
const SUB_CMD_PROBE: u8 = 0x14;
const UNLOCK_RESPONSE_SIZE: u8 = 64;
const VALIDATE_RESPONSE_SIZE: u8 = 4;
/// Primary mode marker at bytes [12..16] of the unlock response — set
/// by the platform firmware when the runtime image is loaded and the
/// extended-access surface is live.
const FIRMWARE_ACTIVE_OFFSET: usize = 12;
const FIRMWARE_ACTIVE_SIG: [u8; 4] = [0x4D, 0x4D, 0x6B, 0x76];
/// Secondary mode marker repeated through bytes [16..64] of the unlock
/// response. Confirms the runtime firmware is the one driving the
/// response, not a stale image's residual buffer.
const FIRMWARE_MODE_OFFSET: usize = 16;
const FIRMWARE_MODE_SIG: [u8; 4] = [0x4C, 0x62, 0x44, 0x72];
/// Fewest bytes an unlock response must carry before ANY of its three checks
/// mean anything — through the secondary marker at [16..20].
const MIN_UNLOCK_RESPONSE: usize = FIRMWARE_MODE_OFFSET + 4;

// ── Post-upload readiness poll (T6, stop-design-v5 §2.11 / §3.1) ──────
/// Between TEST UNIT READY polls; libfreemkv `wait_ready` polls at 500 ms too.
const READY_POLL: Duration = Duration::from_millis(500);
/// T6: fail only after this long with no progress in the not-ready answers.
const READY_STALL: Duration = Duration::from_secs(60);
const TUR_TIMEOUT_MS: u32 = 5_000;
/// Consecutive 02/3A answers, with no 02/04/01 seen, that mean an empty drive
/// (~5 s); libfreemkv `wait_ready`'s `WAIT_READY_MAX_EMPTY_POLLS`.
const READY_MAX_EMPTY_POLLS: u32 = 10;
/// START STOP UNIT (1Bh), LoEj 0 / Start 1 (MMC-6 Table 631, byte 4 bit 0).
const START_UNIT: [u8; 6] = [0x1B, 0x00, 0x00, 0x00, 0x01, 0x00];
/// libfreemkv's START UNIT timeout (T4).
const START_UNIT_TIMEOUT_MS: u32 = 30_000;

// ── Init address (per disc type) ──────────────────────────────────────
const INIT_ADDR_BD: u16 = 0x0100;
const INIT_ADDR_UHD: u16 = 0x0200;

// ── Probe scan ranges ─────────────────────────────────────────────────
const PROBE_COARSE_END: u16 = 0x5800;
const PROBE_FINE_END: u32 = 0x10000;
const PROBE_STEP: u16 = 0x0100;
const PROBE_RESPONSE_SIZE: u8 = 4;

// ── Disc type threshold ───────────────────────────────────────────────
const UHD_SECTOR_THRESHOLD: u32 = 25_000_000; // ~50 GB
const READ_CAPACITY_RESPONSE_SIZE: usize = 8;

pub struct Mt1959 {
    pub(crate) profile: DriveProfile,
    pub(crate) mode: u8,
    pub(crate) buffer_id: u8,
    /// True after `run_init` has completed the unlock handshake (and any
    /// required firmware upload). Gates probe + downstream control
    /// commands; says nothing about whether the drive is in
    /// extended-access mode.
    pub(crate) init_complete: bool,
    /// True when the unlock response carried both the per-drive
    /// signature AND the primary mode marker at offset 12 AND the
    /// secondary mode marker at offset 16. When true the drive is in
    /// the extended-access state — host can issue the per-drive
    /// OEM CDBs and read sectors without the cert-based AACS bus
    /// encryption / mutual-auth gate.
    unlocked: bool,
    probed: bool,
}

impl Mt1959 {
    pub fn new(profile: DriveProfile, is_variant_b: bool) -> Self {
        let (mode, buffer_id) = if is_variant_b {
            (MODE_B, BUFFER_ID_B)
        } else {
            (MODE_A, BUFFER_ID_A)
        };
        Mt1959 {
            profile,
            mode,
            buffer_id,
            init_complete: false,
            unlocked: false,
            probed: false,
        }
    }

    // ── SCSI helpers (shared by both variants) ─────────────────────────

    pub(crate) fn read_buffer_sub(&self, sub_cmd: u8, address: u16, length: u8) -> [u8; 10] {
        [
            SCSI_READ_BUFFER,
            self.mode,
            self.buffer_id,
            sub_cmd,
            (address >> 8) as u8,
            address as u8,
            0x00,
            0x00,
            length,
            0x00,
        ]
    }

    pub(crate) fn read_buffer_probe(
        &self,
        scsi: &mut dyn ScsiTransport,
        sub_cmd: u8,
        address: u16,
        buf: &mut [u8],
        expected: usize,
    ) -> Result<usize> {
        // The READ_BUFFER CDB transfer-length is a single byte; an
        // `expected` above 255 would silently truncate. Guard the
        // invariant rather than emit a malformed CDB.
        debug_assert!(
            expected <= u8::MAX as usize,
            "read_buffer_probe expected exceeds 1-byte CDB length field"
        );
        let cdb = self.read_buffer_sub(sub_cmd, address, expected as u8);
        let result = scsi.execute(&cdb, DataDirection::FromDevice, buf, 5_000)?;
        // A drive sense arrives as `Ok` with a non-zero status; a merely
        // SHORT response is the drive answering badly — neither is a dead
        // bus.
        if result.status != 0 || result.bytes_transferred != expected {
            return Err(Error::Scsi {
                opcode: SCSI_READ_BUFFER,
                status: result.status,
                sense: Some(result.sense),
            });
        }
        Ok(result.bytes_transferred)
    }

    pub(crate) fn set_cd_speed_max(&self, scsi: &mut dyn ScsiTransport) -> Result<()> {
        let cdb = scsi::build_set_cd_speed(0xFFFF);
        let mut dummy = [0u8; 0];
        scsi.execute(&cdb, DataDirection::None, &mut dummy, 5_000)?;
        Ok(())
    }

    // ── Unlock (shared) ────────────────────────────────────────────────

    pub(crate) fn do_unlock(&mut self, scsi: &mut dyn ScsiTransport) -> Result<Vec<u8>> {
        let cdb = [
            0x3C,
            self.mode,
            self.buffer_id,
            SUB_CMD_UNLOCK,
            0x00,
            0x00,
            0x00,
            0x00,
            UNLOCK_RESPONSE_SIZE,
            0x00,
        ];
        let mut response = vec![0u8; UNLOCK_RESPONSE_SIZE as usize];
        let result = scsi.execute(&cdb, DataDirection::FromDevice, &mut response, 30_000)?;

        // A drive sense arrives as `Ok` with a non-zero status; treating it as
        // a successful unlock would validate the caller's own zero fill.
        if result.status != 0 {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "mt1959_unlock_check_condition",
                status = result.status,
                "unlock READ_BUFFER returned a drive sense"
            );
            return Err(Error::Scsi {
                opcode: SCSI_READ_BUFFER,
                status: result.status,
                sense: Some(result.sense),
            });
        }

        // `response` is a fixed 64-byte buffer; the meaningful bound is how
        // many bytes the drive actually delivered. Require enough bytes to
        // validate before checking markers, up front.
        let n = result.bytes_transferred.min(response.len());
        if n < MIN_UNLOCK_RESPONSE {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "mt1959_unlock_short_response",
                bytes_transferred = result.bytes_transferred,
                "unlock response too short to validate"
            );
            return Err(Error::UnlockFailed);
        }

        if response[0..4] != self.profile.signature {
            return Err(Error::SignatureMismatch {
                expected: self.profile.signature,
                got: response[0..4].try_into().unwrap_or([0; 4]),
            });
        }

        if response[FIRMWARE_ACTIVE_OFFSET..FIRMWARE_ACTIVE_OFFSET + 4] != FIRMWARE_ACTIVE_SIG {
            return Err(Error::UnlockFailed);
        }

        // Extended-access state requires the signature match AND both the
        // primary marker at [12..16] AND the secondary marker at [16..20].
        self.unlocked =
            response[FIRMWARE_MODE_OFFSET..FIRMWARE_MODE_OFFSET + 4] == FIRMWARE_MODE_SIG;

        self.init_complete = true;
        Ok(response)
    }

    fn validate(&self, scsi: &mut dyn ScsiTransport) -> Result<()> {
        for _attempt in 0..5 {
            let cdb = [
                0x3C,
                self.mode,
                self.buffer_id,
                SUB_CMD_UNLOCK,
                0x00,
                0x00,
                0x00,
                0x00,
                VALIDATE_RESPONSE_SIZE,
                0x00,
            ];
            let mut resp = [0u8; 4];
            match scsi.execute(&cdb, DataDirection::FromDevice, &mut resp, 5_000) {
                // A drive sense arrives as `Ok`; only a GOOD status is a pass.
                Ok(r) if r.status == 0 => return Ok(()),
                Ok(r) => {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "mt1959_validate_check_condition",
                        status = r.status,
                        "validate READ_BUFFER returned a drive sense"
                    );
                }
                // A dead bus will not recover across five more retries, and
                // labelling every other failure "transport" made the consumer
                // abort rips it could have completed. Propagate the real fault.
                Err(e) => {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "mt1959_validate_transport_fault",
                        "transport fault during validate; aborting"
                    );
                    return Err(Error::from(e));
                }
            }
        }
        Err(Error::UnlockFailed)
    }

    // ── Init (unlock + firmware) ───────────────────────────────────────

    fn run_init(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()> {
        let mut last_err = Error::UnlockFailed;
        for attempt in 0..3 {
            match self.do_unlock(scsi) {
                Ok(_) => {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "mt1959_unlock_ok",
                        attempt,
                        unlocked = self.unlocked,
                        "MT1959 unlock handshake completed"
                    );
                    return Ok(());
                }
                Err(Error::SignatureMismatch { .. }) => {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "mt1959_signature_mismatch",
                        attempt,
                        "unlock response carried another drive's signature"
                    );
                    return Err(Error::UnlockFailed);
                }
                // A dead bus must abort here, not be retried three times as
                // firmware reloads.
                Err(e) if e.is_transport_failure() => {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "mt1959_transport_fault",
                        attempt,
                        "transport fault during unlock; aborting"
                    );
                    return Err(e);
                }
                // Every exit below returns or overwrites `last_err` with the reload's error.
                Err(e) => {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "mt1959_unlock_failed_reloading",
                        attempt,
                        error = %e,
                        "unlock failed; reloading firmware"
                    );
                    let loaded = if self.mode == MODE_A {
                        variant_a::load_firmware(self, scsi)
                    } else {
                        variant_b::load_firmware(self, scsi)
                    };
                    match loaded {
                        // Same rule on the upload path: a dead bus aborts.
                        Err(e) if e.is_transport_failure() => {
                            tracing::warn!(
                                target: "freemkv::disc",
                                phase = "mt1959_transport_fault",
                                attempt,
                                "transport fault during firmware upload; aborting"
                            );
                            return Err(e);
                        }
                        Err(e) => {
                            tracing::debug!(
                                target: "freemkv::disc",
                                phase = "mt1959_firmware_upload_failed",
                                attempt,
                                error = %e,
                                "firmware upload failed; retrying unlock"
                            );
                            last_err = e;
                            continue;
                        }
                        // D10 (stop-design-v5 §1): "`run_init` must `return Ok(())` as soon as
                        // `load_firmware` confirms the unlock" — its own do_unlock already did.
                        // Looping re-ran it after a 10 s settle and discarded it on attempt 2.
                        Ok(()) => {
                            tracing::debug!(
                                target: "freemkv::disc",
                                phase = "mt1959_unlock_ok_after_upload",
                                attempt,
                                unlocked = self.unlocked,
                                "MT1959 unlock confirmed by the firmware upload"
                            );
                            // The upload reset the drive; the unlock proves only the vendor
                            // path answers. Hand it back once the media is ready (T6). Any
                            // readiness outcome keeps the unlock; only a dead bus / Stop fails.
                            await_media_ready(scsi, &mut *ready_clock())?;
                            return Ok(());
                        }
                    }
                }
            }
        }
        tracing::warn!(
            target: "freemkv::disc",
            phase = "mt1959_unlock_exhausted",
            "MT1959 unlock did not succeed after 3 attempts"
        );
        Err(last_err)
    }

    // ── Probe disc ─────────────────────────────────────────────────────

    /// Probe the disc surface so the drive firmware learns optimal speeds
    /// per region. Two passes, then SET_CD_SPEED(max). After this the
    /// drive manages per-zone speeds internally.
    fn run_probe(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()> {
        if !self.init_complete {
            self.do_unlock(scsi)?;
        }

        // Detect disc type from capacity to select probe mode (BD vs UHD
        // init address).
        let cap_cdb = [
            SCSI_READ_CAPACITY,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        let mut cap_buf = [0u8; READ_CAPACITY_RESPONSE_SIZE];
        // A transport fault here is a dead bus: propagate it. A drive
        // sense or short reply just means "capacity unknown" -> assume BD.
        let cap = scsi.execute(&cap_cdb, DataDirection::FromDevice, &mut cap_buf, 5_000)?;
        let disc_sectors = if cap.status == 0 && cap.bytes_transferred >= 4 {
            // last_lba + 1 = sector count; saturate on the 32-bit-overflow
            // sentinel rather than wrap to 0.
            u32::from_be_bytes([cap_buf[0], cap_buf[1], cap_buf[2], cap_buf[3]]).saturating_add(1)
        } else {
            0
        };
        let init_addr = if disc_sectors > UHD_SECTOR_THRESHOLD {
            INIT_ADDR_UHD
        } else {
            INIT_ADDR_BD
        };
        let mut init_resp = [0u8; PROBE_RESPONSE_SIZE as usize];
        let _ = self.read_buffer_probe(
            scsi,
            SUB_CMD_INIT,
            init_addr,
            &mut init_resp,
            PROBE_RESPONSE_SIZE as usize,
        );

        self.validate(scsi)?;

        // Pass 1: coarse scan
        let mut addr: u16 = 0;
        while addr < PROBE_COARSE_END {
            let mut resp = [0u8; PROBE_RESPONSE_SIZE as usize];
            if let Err(e) = self
                .read_buffer_probe(
                    scsi,
                    SUB_CMD_PROBE,
                    addr,
                    &mut resp,
                    PROBE_RESPONSE_SIZE as usize,
                )
                .inspect_err(|e| {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "mt1959_probe_failed",
                        addr,
                        error = %e,
                        "coarse speed probe failed"
                    );
                })
            {
                // A dead bus MUST keep its transport classification; a
                // short/rejected reply is the drive's own failure and stays
                // `UnlockFailed`.
                if e.is_transport_failure() {
                    return Err(e);
                }
                return Err(Error::UnlockFailed);
            }
            addr = addr.wrapping_add(PROBE_STEP);
        }

        // Pass 2: continue past the coarse range (do not restart at 0).
        let mut addr: u32 = PROBE_COARSE_END as u32;
        while addr < PROBE_FINE_END {
            let mut resp = [0u8; PROBE_RESPONSE_SIZE as usize];
            if let Err(e) = self.read_buffer_probe(
                scsi,
                SUB_CMD_PROBE,
                addr as u16,
                &mut resp,
                PROBE_RESPONSE_SIZE as usize,
            ) {
                // Fine probing is best-effort — a short/rejected reply just ends
                // the sweep early, but a transport fault must keep its
                // classification and abort.
                if e.is_transport_failure() {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "mt1959_probe_transport_fault",
                        addr,
                        "transport fault during fine speed probe; aborting"
                    );
                    return Err(e);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "mt1959_probe_failed",
                    addr,
                    error = %e,
                    "fine speed probe ended early"
                );
                break;
            }
            addr += PROBE_STEP as u32;
        }

        // Set max speed — drive manages zones from here
        let _ = self.set_cd_speed_max(scsi);

        self.probed = true;
        Ok(())
    }
}

/// Time and waiting for [`await_media_ready`]: a seam so tests run the 60 s
/// stall window on a virtual clock.
pub(crate) trait ReadyClock {
    /// Time since the poll began.
    fn elapsed(&self) -> Duration;
    /// Wait `d` before the next poll.
    fn wait(&mut self, scsi: &mut dyn ScsiTransport, d: Duration) -> scsi::Result<()>;
}

/// The poll's clock: [`WallClock`], or a test's virtual clock (a per-thread seam,
/// so an [`crate::LdUnlocker`] test can stall the poll without waiting 60 s).
fn ready_clock() -> Box<dyn ReadyClock> {
    #[cfg(test)]
    if let Some(make) = tests::TEST_READY_CLOCK.get() {
        return make();
    }
    Box::new(WallClock::start())
}

/// The production clock: real time, a plain sleep between polls.
struct WallClock(std::time::Instant);

impl WallClock {
    fn start() -> Self {
        WallClock(std::time::Instant::now())
    }
}

impl ReadyClock for WallClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn wait(&mut self, _scsi: &mut dyn ScsiTransport, d: Duration) -> scsi::Result<()> {
        std::thread::sleep(d);
        Ok(())
    }
}

/// How the post-upload readiness poll ended. Every outcome keeps the unlock; the
/// non-`Ready` ones are logged at warn and left to the caller's next command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaReady {
    Ready,
    /// 10 consecutive 02/3A/xx with no 02/04/01 first: an empty drive.
    NoMedium,
    /// 02/30/xx: a medium that will never become ready.
    Incompatible {
        asc: u8,
        ascq: u8,
    },
    /// Sense key 3, 4 or 5: not a readiness answer.
    DriveError {
        sense_key: u8,
        asc: u8,
        ascq: u8,
    },
    /// T6: no progress for [`READY_STALL`]; carries the last answer.
    Stalled {
        sense_key: u8,
        asc: u8,
        ascq: u8,
    },
}

/// Poll TEST UNIT READY until the drive answers ready, following libfreemkv
/// `wait_ready`'s terminal states but always keeping the unlock (it succeeded).
/// T6 (stop-design-v5 §2.11): progress is an answer (sense key, ASC, ASCQ) not
/// yet seen in this poll, or the one START STOP UNIT; [`READY_STALL`] without
/// progress ends it. No total cap. `Err` only for a dead bus or a Stop.
fn await_media_ready(
    scsi: &mut dyn ScsiTransport,
    clock: &mut dyn ReadyClock,
) -> Result<MediaReady> {
    let tur = [SCSI_TEST_UNIT_READY, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut seen: Vec<(u8, u8, u8)> = Vec::new();
    let mut last_progress = clock.elapsed();
    let (mut start_sent, mut empty_run, mut becoming_ready_seen) = (false, 0u32, false);
    for polls in 1u64.. {
        // A drive answer arrives as `Ok` + status, or (libfreemkv's adapter) as an
        // `Err` carrying the sense; only a senseless `Err` is a dead bus or a Stop.
        let sense = match scsi.execute(&tur, DataDirection::None, &mut [], TUR_TIMEOUT_MS) {
            Ok(r) if r.status == 0 => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "mt1959_media_ready",
                    polls,
                    elapsed_ms = clock.elapsed().as_millis() as u64,
                    "drive ready after the firmware upload"
                );
                return Ok(MediaReady::Ready);
            }
            Ok(r) => r.sense,
            Err(e) => match e.sense {
                Some(sense) => sense,
                None => return Err(Error::from(e)),
            },
        };
        let s = ScsiSense::from_buf(&sense);
        let answer = (s.sense_key, s.asc, s.ascq);
        // MMC-6 Table F.3: "2 3A 00 MEDIUM NOT PRESENT"; "2 04 01 LOGICAL UNIT IS IN
        // PROCESS OF BECOMING READY" first means the 3A run is not final.
        empty_run = if (s.sense_key, s.asc) == (0x02, 0x3A) {
            empty_run + 1
        } else {
            0
        };
        becoming_ready_seen |= answer == (0x02, 0x04, 0x01);
        let outcome = match answer {
            _ if !becoming_ready_seen && empty_run >= READY_MAX_EMPTY_POLLS => {
                Some(MediaReady::NoMedium)
            }
            // Table F.3: "2 30 00 INCOMPATIBLE MEDIUM INSTALLED" (30/xx never ready).
            (0x02, 0x30, ascq) => Some(MediaReady::Incompatible { asc: 0x30, ascq }),
            // MEDIUM ERROR; HARDWARE ERROR (F.3.8 "reported when SK = HARDWARE ERROR");
            // ILLEGAL REQUEST (F.3.2 Table F.2): no readiness to wait for.
            (sense_key @ 0x03..=0x05, asc, ascq) => Some(MediaReady::DriveError {
                sense_key,
                asc,
                ascq,
            }),
            _ => None,
        };
        if let Some(outcome) = outcome {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "mt1959_media_not_ready",
                polls,
                outcome = ?outcome,
                "drive not ready after the firmware upload; keeping the unlock"
            );
            return Ok(outcome);
        }
        // Table F.3: "2 04 02 LOGICAL UNIT NOT READY, INITIALIZING CMD. REQUIRED" →
        // one START STOP UNIT, Table 633 LoEj 0 Start 1: "Start the disc and make
        // ready for access". Counted as progress.
        if answer == (0x02, 0x04, 0x02) && !start_sent {
            start_sent = true;
            last_progress = clock.elapsed();
            let r = scsi.execute(
                &START_UNIT,
                DataDirection::None,
                &mut [],
                START_UNIT_TIMEOUT_MS,
            );
            if let Err(e @ crate::scsi::ScsiError { sense: None, .. }) = r {
                return Err(Error::from(e));
            }
        }
        // Everything else (04/xx, 06/29/00 and 06/28/00 UNIT ATTENTION after the
        // upload's reset, …) keeps polling under the T6 rule.
        if !seen.contains(&answer) {
            // TODO(T6 part 2, stop-design-v5 §2.11): also count a rising SKSV progress
            // indicator (sense bytes 15-17) as progress, once SS-1 is quoted here.
            seen.push(answer);
            last_progress = clock.elapsed();
        } else if clock.elapsed().saturating_sub(last_progress) >= READY_STALL {
            let (sense_key, asc, ascq) = answer;
            tracing::warn!(
                target: "freemkv::disc",
                phase = "mt1959_media_ready_stalled",
                polls,
                sense_key,
                asc,
                ascq,
                "drive not ready after the firmware upload, no progress for 60 s; \
                 keeping the unlock"
            );
            return Ok(MediaReady::Stalled {
                sense_key,
                asc,
                ascq,
            });
        }
        clock.wait(scsi, READY_POLL)?;
    }
    unreachable!("the poll returns from inside the loop")
}

// ── PlatformDriver trait ───────────────────────────────────────────────

impl PlatformDriver for Mt1959 {
    fn init(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()> {
        if self.init_complete {
            return Ok(());
        }
        self.run_init(scsi)
    }

    fn probe_disc(&mut self, scsi: &mut dyn ScsiTransport) -> Result<()> {
        if !self.init_complete {
            // Don't retry init here — if init() failed, probing can't work either.
            // Retrying causes repeated USB bus resets on BU40N.
            return Ok(());
        }
        if self.probed {
            return Ok(());
        }
        self.run_probe(scsi)
    }

    fn is_ready(&self) -> bool {
        self.init_complete
    }

    fn is_unlocked(&self) -> bool {
        self.unlocked
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) type ClockFactory = fn() -> Box<dyn ReadyClock>;

    thread_local! {
        /// Per-thread override of the poll's clock (see [`ready_clock`]).
        pub(crate) static TEST_READY_CLOCK: std::cell::Cell<Option<ClockFactory>> =
            const { std::cell::Cell::new(None) };
    }
    use crate::ld::profile::{DriveProfile, Identity};
    use crate::scsi::{DataDirection, ScsiResult, ScsiTransport};

    /// Minimal mock transport that returns a scripted response to the
    /// next `execute()` call. Only used for verifying that `do_unlock`
    /// classifies the response correctly — no general SCSI coverage.
    struct ScriptedTransport {
        response: Vec<u8>,
    }

    impl ScsiTransport for ScriptedTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            let n = self.response.len().min(data.len());
            data[..n].copy_from_slice(&self.response[..n]);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }

    /// Records every CDB issued, so a test can assert which bytes hit the wire.
    struct RecordingTransport {
        cdbs: Vec<Vec<u8>>,
    }

    impl ScsiTransport for RecordingTransport {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            _data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            self.cdbs.push(cdb.to_vec());
            // Empty response → do_unlock's signature check fails, so the unlock
            // loop exhausts — but the firmware-load CDBs (incl. the F1 verify)
            // are already recorded by then.
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: 0,
                sense: [0u8; 32],
            })
        }
    }

    /// variant_b must issue the PROFILE's per-drive `fw_verify_cdb`, not the
    /// hardcoded fallback const — the bug that broke ~139 of 140 B drives.
    #[test]
    fn variant_b_issues_profile_fw_verify_cdb_not_const() {
        let drive_f1 = [0xF1, 0x01, 0x02, 0x00, 0x0C, 0xF0, 0x01, 0xFB, 0xC9, 0x93];
        // variant_b's hardcoded fallback const (a different drive's token).
        let fallback_f1 = [0xF1, 0x01, 0x02, 0x00, 0x0D, 0x30, 0x01, 0xF3, 0xAD, 0x23];
        let mut profile = fixture_profile([0x9a, 0xa9, 0x3a, 0xe2]);
        profile.firmware = vec![0u8; 2208]; // a real per-drive length, != old 0x9C0
        profile.fw_verify_cdb = Some(drive_f1);

        let mut mt = Mt1959::new(profile, true);
        let mut t = RecordingTransport { cdbs: Vec::new() };
        let _ = variant_b::load_firmware(&mut mt, &mut t);

        assert!(
            t.cdbs.iter().any(|c| c.as_slice() == drive_f1),
            "must send the profile's F1 verify CDB"
        );
        assert!(
            !t.cdbs.iter().any(|c| c.as_slice() == fallback_f1),
            "must NOT send the hardcoded fallback const when the profile has its own"
        );
        // MODE SELECT must encode the real per-drive length (2208), not 0x9C0.
        let ms = t
            .cdbs
            .iter()
            .find(|c| c.first() == Some(&0x55))
            .expect("MODE SELECT issued");
        let len = ((ms[7] as usize) << 8) | ms[8] as usize;
        assert_eq!(len, 2208, "MODE SELECT length = firmware.len(), not 2496");
    }

    // Byte-for-byte pin of variant_b's Step-2 metadata-read (READ_BUFFER offset
    // 0x3000 at cdb[4]=0x30, length 0x10 at cdb[8]) and Step-3 write-extra CDBs.
    #[test]
    fn variant_b_meta_read_and_write_extra_cdbs_are_exact_bytes() {
        let mut profile = fixture_profile([0x11, 0x22, 0x33, 0x44]);
        profile.firmware = vec![0u8; 2208];
        let mut mt = Mt1959::new(profile, true);
        let mut t = RecordingTransport { cdbs: Vec::new() };
        let _ = variant_b::load_firmware(&mut mt, &mut t);

        // Step 2: READ_BUFFER mode 6, offset 0x3000, length 0x10.
        let meta = t
            .cdbs
            .iter()
            .find(|c| c.first() == Some(&SCSI_READ_BUFFER) && c.get(4) == Some(&0x30))
            .expect("Step-2 metadata READ_BUFFER issued");
        assert_eq!(
            meta.as_slice(),
            &[0x3C, 0x06, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x10, 0x00]
        );

        // Step 3: WRITE_BUFFER of the 0x10-byte extra block. Distinguish from
        // the Step-1 firmware upload (WRITE_BUFFER too) by its length byte.
        let extra = t
            .cdbs
            .iter()
            .find(|c| c.first() == Some(&SCSI_WRITE_BUFFER) && c.get(8) == Some(&0x10))
            .expect("Step-3 write-extra WRITE_BUFFER issued");
        assert_eq!(
            extra.as_slice(),
            &[0x3B, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00]
        );
    }

    // Pins variant_a's upload sequence: WRITE_BUFFER at the real per-drive
    // length in the CDB's 24-bit length field, then the 0x45 verify
    // READ_BUFFER whose result used to be discarded outright.
    #[test]
    fn variant_a_uploads_at_the_real_length_and_issues_the_verify_read() {
        let mut profile = fixture_profile([0x11, 0x22, 0x33, 0x44]);
        profile.firmware = vec![0u8; 2208];

        let mut mt = Mt1959::new(profile, false);
        let mut t = RecordingTransport { cdbs: Vec::new() };
        let _ = variant_a::load_firmware(&mut mt, &mut t);

        let wb = t
            .cdbs
            .iter()
            .find(|c| c.first() == Some(&SCSI_WRITE_BUFFER))
            .expect("WRITE_BUFFER issued");
        let len = ((wb[6] as usize) << 16) | ((wb[7] as usize) << 8) | wb[8] as usize;
        assert_eq!(len, 2208, "24-bit CDB length must be firmware.len()");

        assert!(
            t.cdbs
                .iter()
                .any(|c| c.first() == Some(&SCSI_READ_BUFFER) && c.get(2) == Some(&0x45)),
            "the 0x45 verify READ_BUFFER must be issued"
        );
    }

    // Byte-for-byte pin of variant_a's two firmware-upload CDBs (not just the
    // length field): the WRITE_BUFFER (mode cdb[1]=0x06, reserved, 24-bit len,
    // control byte 9) and the whole 0x45 verify READ_BUFFER CDB.
    #[test]
    fn variant_a_write_buffer_and_verify_cdbs_are_exact_bytes() {
        let mut profile = fixture_profile([0x11, 0x22, 0x33, 0x44]);
        profile.firmware = vec![0u8; 2208]; // 0x0008A0
        let mut mt = Mt1959::new(profile, false);
        let mut t = RecordingTransport { cdbs: Vec::new() };
        let _ = variant_a::load_firmware(&mut mt, &mut t);

        let wb = t
            .cdbs
            .iter()
            .find(|c| c.first() == Some(&SCSI_WRITE_BUFFER))
            .expect("WRITE_BUFFER issued");
        // 3B [mode 06] [rsvd 00 00 00 00] [len 24-bit BE = 0008A0] [control 00]
        assert_eq!(
            wb.as_slice(),
            &[0x3B, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xA0, 0x00]
        );

        let verify = t
            .cdbs
            .iter()
            .find(|c| c.first() == Some(&SCSI_READ_BUFFER) && c.get(2) == Some(&0x45))
            .expect("0x45 verify READ_BUFFER issued");
        // 3C [MODE_A 01] [buffer_id 45] [rsvd ×5] [alloc len 04] [control 00]
        assert_eq!(
            verify.as_slice(),
            &[0x3C, 0x01, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00]
        );
    }

    /// An EMPTY firmware blob cannot be uploaded — catches a profile whose
    /// firmware failed to decode being pushed at the drive as a zero-length
    /// WRITE_BUFFER.
    #[test]
    fn variant_a_refuses_an_empty_firmware_blob() {
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        let mut t = RecordingTransport { cdbs: Vec::new() };
        let e = variant_a::load_firmware(&mut mt, &mut t).expect_err("no firmware");
        assert!(matches!(e, Error::UnlockFailed));
        assert!(t.cdbs.is_empty(), "no CDB may reach the drive");
    }

    // THE defect-15 test: a zero-byte response used to skip every marker
    // check (each individually `n >= ..` guarded) and report a fully
    // unlocked drive.
    #[test]
    fn do_unlock_rejects_a_zero_length_response() {
        let sig = [0x99, 0x9E, 0xC3, 0x75];
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::zero_transfer(64));
        let mut mt = Mt1959::new(fixture_profile(sig), false);
        let e = mt.do_unlock(&mut t).expect_err("no bytes is not an unlock");
        assert!(matches!(e, Error::UnlockFailed));
        assert!(!mt.init_complete);
        assert!(!mt.is_unlocked());
    }

    /// A response truncated just below the secondary marker is equally
    /// unverifiable — the checks must not run against the caller's zero fill.
    #[test]
    fn do_unlock_rejects_a_response_too_short_to_validate() {
        let sig = [0x99, 0x9E, 0xC3, 0x75];
        let response = build_response(sig, FIRMWARE_ACTIVE_SIG, FIRMWARE_MODE_SIG);
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::short(response, 19));
        let mut mt = Mt1959::new(fixture_profile(sig), false);
        let e = mt
            .do_unlock(&mut t)
            .expect_err("19 bytes cannot carry the markers");
        assert!(matches!(e, Error::UnlockFailed));
    }

    /// A CHECK CONDITION arrives as `Ok` per the transport contract; treating it
    /// as an unlock would validate the caller's own zero fill.
    #[test]
    fn do_unlock_rejects_a_check_condition() {
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::illegal_request());
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        let e = mt
            .do_unlock(&mut t)
            .expect_err("a drive sense is not an unlock");
        assert!(!e.is_transport_failure(), "a sense is not a dead bus");
    }

    // THE defect-16 test: a merely short probe response used to be
    // fabricated into a transport-failure status, hard-aborting a rip
    // that would otherwise have succeeded.
    #[test]
    fn short_probe_response_is_not_a_transport_failure() {
        let mut t = crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::short(
            vec![0u8; 4],
            2,
        ));
        let mt = Mt1959::new(fixture_profile([0; 4]), false);
        let mut buf = [0u8; 4];
        let e = mt
            .read_buffer_probe(&mut t, SUB_CMD_PROBE, 0, &mut buf, 4)
            .expect_err("short probe");
        assert!(
            !e.is_transport_failure(),
            "a short probe response must not abort the rip"
        );
        assert_eq!(
            crate::UnlockError::from(e),
            crate::UnlockError::NotApplicable
        );
    }

    /// A genuine transport fault on the probe still propagates as one.
    #[test]
    fn transport_fault_on_probe_is_a_transport_failure() {
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::TransportFault);
        let mt = Mt1959::new(fixture_profile([0; 4]), false);
        let mut buf = [0u8; 4];
        let e = mt
            .read_buffer_probe(&mut t, SUB_CMD_PROBE, 0, &mut buf, 4)
            .expect_err("dead bus");
        assert!(e.is_transport_failure());
    }

    // THE defect-4 test: a dead bus must abort `run_init` at once, not
    // re-upload firmware on all three attempts and return the generic
    // `UnlockFailed`.
    #[test]
    fn run_init_aborts_on_a_transport_fault_without_reloading_firmware() {
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::TransportFault);
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        let e = mt.init(&mut t).expect_err("dead bus");
        assert!(e.is_transport_failure());
        assert_eq!(crate::UnlockError::from(e), crate::UnlockError::Transport);
        assert_eq!(t.calls(), 1, "one command, then abort — no firmware reload");
    }

    /// THE defect-14 test. The two probe passes used to walk the SAME addresses
    /// at the SAME step: pass 2 restarted at 0 and re-issued all 88 pass-1
    /// probes verbatim. Catches restoring the overlap.
    #[test]
    fn probe_passes_do_not_reissue_the_same_addresses() {
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::good(vec![0u8; 8]));
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let _ = mt.run_probe(&mut t);

        // Every SUB_CMD_PROBE CDB carries its address at bytes 4-5.
        let mut probes: Vec<u16> = t
            .cdbs
            .iter()
            .filter(|c| c.first() == Some(&SCSI_READ_BUFFER) && c.get(3) == Some(&SUB_CMD_PROBE))
            .map(|c| ((c[4] as u16) << 8) | c[5] as u16)
            .collect();
        let issued = probes.len();
        probes.sort_unstable();
        probes.dedup();
        assert_eq!(
            issued,
            probes.len(),
            "no probe address may be issued twice ({} duplicates)",
            issued - probes.len()
        );
    }

    /// Answers every command GOOD except the speed probe (READ_BUFFER /
    /// SUB_CMD_PROBE) at address >= `fault_at`, which returns a transport fault —
    /// a bus that dies partway through disc-speed calibration.
    struct ProbeFaultsTransport {
        fault_at: u16,
    }
    impl ScsiTransport for ProbeFaultsTransport {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            if cdb.first() == Some(&SCSI_READ_BUFFER) && cdb.get(3) == Some(&SUB_CMD_PROBE) {
                let addr = ((cdb[4] as u16) << 8) | cdb[5] as u16;
                if addr >= self.fault_at {
                    return Err(crate::scsi::ScsiError {
                        status: crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                        sense: None,
                    });
                }
            }
            for b in data.iter_mut() {
                *b = 0;
            }
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: data.len(),
                sense: [0u8; 32],
            })
        }
    }

    // A drive SENSE (not a dead bus) during the coarse probe is the
    // drive's own failure — `run_probe` must report `UnlockFailed`, not
    // `Transport`. Sibling of the pass-1 transport-fault test below.
    #[test]
    fn drive_sense_during_pass1_probe_is_unlock_failed_not_transport() {
        struct SenseAtFirstProbe;
        impl ScsiTransport for SenseAtFirstProbe {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                if cdb.first() == Some(&SCSI_READ_BUFFER) && cdb.get(3) == Some(&SUB_CMD_PROBE) {
                    return Ok(ScsiResult {
                        status: 0x02,
                        bytes_transferred: 0,
                        sense: [0u8; 32],
                    });
                }
                for b in data.iter_mut() {
                    *b = 0;
                }
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: data.len(),
                    sense: [0u8; 32],
                })
            }
        }
        let mut t = SenseAtFirstProbe;
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let e = mt
            .run_probe(&mut t)
            .expect_err("drive-refused pass-1 probe");
        assert!(!e.is_transport_failure(), "a sense is not a dead bus");
        assert!(matches!(e, Error::UnlockFailed));
    }

    // THE probe pass-1 dead-bus test: a bus that dies during the coarse
    // probe must keep its transport classification so the caller aborts
    // with `Transport`.
    #[test]
    fn transport_fault_during_pass1_probe_stays_a_transport_failure() {
        let mut t = ProbeFaultsTransport { fault_at: 0 };
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let e = mt
            .run_probe(&mut t)
            .expect_err("dead bus during pass-1 probe");
        assert!(e.is_transport_failure(), "pass-1 fault must stay transport");
        assert_eq!(crate::UnlockError::from(e), crate::UnlockError::Transport);
    }

    // THE probe pass-2 dead-bus test: the loop used to `break` on ANY
    // error and return `Ok(())`, swallowing a dead bus mid-pass-2. It
    // must now propagate.
    #[test]
    fn transport_fault_during_pass2_probe_stays_a_transport_failure() {
        let mut t = ProbeFaultsTransport {
            fault_at: PROBE_COARSE_END,
        };
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let e = mt
            .run_probe(&mut t)
            .expect_err("dead bus during pass-2 probe");
        assert!(e.is_transport_failure(), "pass-2 fault must stay transport");
        assert_eq!(crate::UnlockError::from(e), crate::UnlockError::Transport);
    }

    // `validate`'s transport-abort branch: a dead bus must propagate on
    // the first attempt, not be retried five times.
    #[test]
    fn validate_propagates_a_transport_fault_without_retrying() {
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::TransportFault);
        let mt = Mt1959::new(fixture_profile([0; 4]), false);
        let e = mt.validate(&mut t).expect_err("dead bus");
        assert!(e.is_transport_failure());
        assert_eq!(t.calls(), 1, "abort on the first fault, no 5× retry");
    }

    /// `validate`'s drive-sense path: a CHECK CONDITION is `Ok` per the contract,
    /// so validate retries and finally returns `UnlockFailed` — NOT a transport
    /// abort (which would wrongly kill a rip the drive merely stalled on).
    #[test]
    fn validate_drive_sense_exhausts_to_unlock_failed() {
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::illegal_request());
        let mt = Mt1959::new(fixture_profile([0; 4]), false);
        let e = mt.validate(&mut t).expect_err("five senses, no pass");
        assert!(!e.is_transport_failure(), "a sense is not a dead bus");
        assert!(matches!(e, Error::UnlockFailed));
        assert_eq!(t.calls(), 5, "retries the full five attempts");
    }

    // variant_a's firmware-verify-read transport-abort branch: WRITE_BUFFER
    // succeeds, the 0x45 verify read faults — a dead bus must abort there,
    // not be swallowed into the unlock retries.
    #[test]
    fn variant_a_verify_read_transport_fault_aborts() {
        let mut profile = fixture_profile([0; 4]);
        profile.firmware = vec![0u8; 64];
        let mut mt = Mt1959::new(profile, false);
        // call 1 WRITE_BUFFER → good; call 2 verify read → dead bus; later
        // do_unlock calls (only reached if the fix is absent) → good.
        let mut t = crate::scsi::mock::MockTransport::scripted(
            vec![
                crate::scsi::mock::Reply::good(vec![0u8; 4]),
                crate::scsi::mock::Reply::TransportFault,
            ],
            crate::scsi::mock::Reply::good(vec![0u8; 64]),
        );
        let e = variant_a::load_firmware(&mut mt, &mut t).expect_err("dead bus at verify");
        assert!(
            e.is_transport_failure(),
            "verify-read dead bus must surface"
        );
    }

    /// A firmware blob larger than WRITE_BUFFER's 24-bit CDB length field
    /// cannot be uploaded — encoding it would silently disagree with the
    /// bytes actually sent. Must reject before issuing any CDB.
    #[test]
    fn variant_a_refuses_firmware_over_the_24bit_write_buffer_length() {
        let mut profile = fixture_profile([0; 4]);
        profile.firmware = vec![0u8; 0x0100_0000]; // one past WRITE_BUFFER_MAX_LEN
        let mut mt = Mt1959::new(profile, false);
        let mut t = RecordingTransport { cdbs: Vec::new() };
        let e = variant_a::load_firmware(&mut mt, &mut t).expect_err("blob too large to encode");
        assert!(matches!(e, Error::UnlockFailed));
        assert!(t.cdbs.is_empty(), "no CDB may reach the drive");
    }

    // THE full success path: WRITE_BUFFER upload, a fully-good verify
    // read, then both `do_unlock` calls succeed. The only variant_a test
    // that reaches `load_firmware`'s final `Ok(())`.
    #[test]
    fn variant_a_load_firmware_succeeds_end_to_end() {
        let sig = [0x11, 0x22, 0x33, 0x44];
        let mut profile = fixture_profile(sig);
        profile.firmware = vec![0u8; 64];
        let mut mt = Mt1959::new(profile, false);
        let unlock_response = build_response(sig, FIRMWARE_ACTIVE_SIG, FIRMWARE_MODE_SIG);
        let mut t = crate::scsi::mock::MockTransport::scripted(
            vec![
                crate::scsi::mock::Reply::good(vec![]), // WRITE_BUFFER upload
                crate::scsi::mock::Reply::good(vec![0u8; VALIDATE_RESPONSE_SIZE as usize]), // verify read, full
                crate::scsi::mock::Reply::good(unlock_response.clone()), // do_unlock #1
                crate::scsi::mock::Reply::good(unlock_response), // do_unlock #2 (best-effort)
            ],
            crate::scsi::mock::Reply::TransportFault,
        );
        variant_a::load_firmware(&mut mt, &mut t).expect("upload + verify + double unlock all ok");
        assert!(mt.init_complete, "do_unlock #1 must have set init_complete");
    }

    // variant_b's firmware-upload step (here the metadata read) hitting a
    // dead bus must abort via `trace_step`, not be swallowed into the
    // unlock retries.
    #[test]
    fn variant_b_upload_step_transport_fault_aborts() {
        let mut profile = fixture_profile([0; 4]);
        profile.firmware = vec![0u8; 64];
        let mut mt = Mt1959::new(profile, true);
        // call 1 MODE SELECT → good; call 2 metadata read → dead bus; rest good.
        let mut t = crate::scsi::mock::MockTransport::scripted(
            vec![
                crate::scsi::mock::Reply::good(vec![0u8; 16]),
                crate::scsi::mock::Reply::TransportFault,
            ],
            crate::scsi::mock::Reply::good(vec![0u8; 64]),
        );
        let e = variant_b::load_firmware(&mut mt, &mut t).expect_err("dead bus mid-upload");
        assert!(
            e.is_transport_failure(),
            "an upload-step dead bus must surface"
        );
    }

    fn fixture_profile(signature: [u8; 4]) -> DriveProfile {
        DriveProfile {
            identity: Identity {
                vendor_id: "TEST".into(),
                product_id: String::new(),
                product_revision: String::new(),
                vendor_specific: String::new(),
                firmware_date: String::new(),
            },
            signature,
            firmware: Vec::new(),
            unlock_init_value: 0,
            unlock_response_size: 0,
            read_vid_cdb: None,
            read_disc_keys_cdb: None,
            drive_nominal_speed_cdb: None,
            set_speed_max_cdb: None,
            read10_raw_2sec_cdb: None,
            read10_raw_1sec_cdb: None,
            read_buffer_verify_cdb: None,
            write_buffer_cdb: None,
            read_buffer_unlock_cdb: None,
            fw_verify_cdb: None,
            speed_zone_table: None,
            speed_calc_table: None,
        }
    }

    // Build a synthetic 64-byte unlock response. `mode_marker` fills
    // bytes [12..16]; `id_marker` fills bytes [16..20] (repeated through
    // [20..64] in real responses; only [16..20] is checked).
    fn build_response(signature: [u8; 4], mode_marker: [u8; 4], id_marker: [u8; 4]) -> Vec<u8> {
        let mut r = vec![0u8; 64];
        r[0..4].copy_from_slice(&signature);
        // bytes [4..12] left as zeros (version + reserved per format)
        r[12..16].copy_from_slice(&mode_marker);
        // Real firmware repeats the secondary marker through [16..64];
        // the parser only checks [16..20], so we just write the marker
        // once.
        r[16..20].copy_from_slice(&id_marker);
        r
    }

    #[test]
    fn do_unlock_sets_unlocked_when_both_markers_present() {
        let sig = [0x99, 0x9E, 0xC3, 0x75];
        let response = build_response(sig, FIRMWARE_ACTIVE_SIG, FIRMWARE_MODE_SIG);
        let mut transport = ScriptedTransport { response };
        let mut mt = Mt1959::new(fixture_profile(sig), false);

        let raw = mt.do_unlock(&mut transport).expect("unlock should succeed");
        assert_eq!(raw.len(), 64);
        assert!(mt.init_complete, "init_complete set after success");
        assert!(
            mt.is_unlocked(),
            "both markers present -> extended-access state"
        );
    }

    #[test]
    fn do_unlock_init_complete_but_not_unlocked_when_id_marker_missing() {
        // Primary mode marker present (so init passes) but the
        // secondary marker is replaced with zeros — drive isn't in
        // extended-access state.
        let sig = [0x99, 0x9E, 0xC3, 0x75];
        let response = build_response(sig, FIRMWARE_ACTIVE_SIG, [0u8; 4]);
        let mut transport = ScriptedTransport { response };
        let mut mt = Mt1959::new(fixture_profile(sig), false);

        mt.do_unlock(&mut transport).expect("unlock should succeed");
        assert!(mt.init_complete);
        assert!(
            !mt.is_unlocked(),
            "missing secondary marker -> not in extended-access state"
        );
    }

    #[test]
    fn do_unlock_rejects_signature_mismatch() {
        let response = build_response(
            [0xAA, 0xBB, 0xCC, 0xDD],
            FIRMWARE_ACTIVE_SIG,
            FIRMWARE_MODE_SIG,
        );
        let mut transport = ScriptedTransport { response };
        let mut mt = Mt1959::new(fixture_profile([0x99, 0x9E, 0xC3, 0x75]), false);

        let err = mt.do_unlock(&mut transport).unwrap_err();
        assert!(matches!(err, Error::SignatureMismatch { .. }));
        assert!(!mt.init_complete);
        assert!(!mt.is_unlocked());
    }

    // ── run_init (the retry loop itself, not the leaf steps) ───────────────

    /// A signature mismatch on the unlock response is another drive's token —
    /// retrying accomplishes nothing, so `run_init` must abort on the FIRST
    /// attempt with `UnlockFailed`, not retry three times.
    #[test]
    fn run_init_signature_mismatch_aborts_without_retry() {
        let response = build_response(
            [0xAA, 0xBB, 0xCC, 0xDD],
            FIRMWARE_ACTIVE_SIG,
            FIRMWARE_MODE_SIG,
        );
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::good(response));
        let mut mt = Mt1959::new(fixture_profile([0x99, 0x9E, 0xC3, 0x75]), false);
        let e = mt.init(&mut t).expect_err("signature mismatch");
        assert!(matches!(e, Error::UnlockFailed));
        assert_eq!(t.calls(), 1, "must not retry a signature mismatch");
    }

    // `run_init`'s retry loop: a generic `do_unlock` failure plus a
    // generic firmware-reload failure must `continue` and retry three
    // times before exhausting to the last error.
    #[test]
    fn run_init_exhausts_after_three_generic_failures() {
        let mut t = crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::short(
            vec![0u8; 64],
            10,
        ));
        // Empty firmware -> variant_a::load_firmware fails immediately with
        // no CDB, so each attempt costs exactly one do_unlock call.
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        let e = mt.init(&mut t).expect_err("never validates, never uploads");
        assert!(matches!(e, Error::UnlockFailed));
        assert!(!e.is_transport_failure());
        assert_eq!(
            t.calls(),
            3,
            "one do_unlock call per attempt, three attempts, no firmware CDBs"
        );
    }

    // Same shape as the mode-A generic-failure test, but for a MODE_B
    // drive — pins that `run_init`'s dispatch actually reaches
    // `variant_b::load_firmware`, not just its variant_a sibling.
    #[test]
    fn run_init_exhausts_after_three_generic_failures_mode_b() {
        let mut t = crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::short(
            vec![0u8; 64],
            10,
        ));
        let mut mt = Mt1959::new(fixture_profile([0; 4]), true);
        let e = mt.init(&mut t).expect_err("never validates, never uploads");
        assert!(matches!(e, Error::UnlockFailed));
        assert!(!e.is_transport_failure());
        assert_eq!(
            t.calls(),
            3,
            "one do_unlock call per attempt, three attempts, no firmware CDBs"
        );
    }

    // Same generic `do_unlock` failure, but the firmware-reload fallback
    // itself hits a dead bus — must abort `run_init` immediately, not be
    // folded into `last_err` and retried.
    #[test]
    fn run_init_firmware_reload_transport_fault_aborts() {
        let mut profile = fixture_profile([0; 4]);
        profile.firmware = vec![0u8; 64]; // non-empty: load_firmware issues a CDB
        let mut t = crate::scsi::mock::MockTransport::scripted(
            vec![crate::scsi::mock::Reply::short(vec![0u8; 64], 10)], // do_unlock: generic fail
            crate::scsi::mock::Reply::TransportFault,                 // WRITE_BUFFER: dead bus
        );
        let mut mt = Mt1959::new(profile, false);
        let e = mt
            .init(&mut t)
            .expect_err("dead bus during firmware reload");
        assert!(e.is_transport_failure());
        assert_eq!(crate::UnlockError::from(e), crate::UnlockError::Transport);
        assert_eq!(
            t.calls(),
            2,
            "one do_unlock call, then the WRITE_BUFFER that dies"
        );
    }

    // UT10 (stop-design-v5 §5.2, D10): "`run_init` must `return Ok(())` as soon as
    // `load_firmware` confirms the unlock. The final upload is kept." GUARD G3 too;
    // per design D10, do not change without a design citation proving otherwise.
    #[test]
    fn run_init_returns_ok_once_load_firmware_confirms() {
        use crate::scsi::mock::{MockTransport, Reply};
        let sig = [0x11, 0x22, 0x33, 0x44];
        let unlock_ok = build_response(sig, FIRMWARE_ACTIVE_SIG, FIRMWARE_MODE_SIG);
        let short = || Reply::short(vec![0u8; 64], 10); // a generic do_unlock failure
        let upload_ok = || {
            vec![
                Reply::good(vec![]),                                     // WRITE_BUFFER
                Reply::good(vec![0u8; VALIDATE_RESPONSE_SIZE as usize]), // 0x45 verify
            ]
        };
        // Case 1: attempt 0 reloads and load_firmware's own do_unlock confirms.
        // Case 2: attempts 0-1 reload but fail; attempt 2 (the LAST) confirms,
        // which the retry loop used to discard as `Err(last_err)`.
        for failed_reloads in [0usize, 2] {
            let mut script = Vec::new();
            for _ in 0..failed_reloads {
                script.push(short()); // run_init's do_unlock
                script.extend(upload_ok());
                script.push(short()); // load_firmware's do_unlock fails
            }
            script.push(short()); // run_init's do_unlock
            script.extend(upload_ok());
            script.push(Reply::good(unlock_ok.clone())); // load_firmware do_unlock #1
            script.push(Reply::good(unlock_ok.clone())); // do_unlock #2 (best-effort)
            script.push(Reply::good(vec![])); // TEST UNIT READY: ready at once
            let expected_calls = script.len();
            // Anything past the script is a further retry, which must not happen.
            let mut t = MockTransport::scripted(script, Reply::TransportFault);
            let mut profile = fixture_profile(sig);
            profile.firmware = vec![0u8; 64];
            let mut mt = Mt1959::new(profile, false);
            let t0 = std::time::Instant::now();
            mt.init(&mut t)
                .unwrap_or_else(|e| panic!("{failed_reloads} failed reloads: {e:?}"));
            assert_eq!(
                t.calls(),
                expected_calls,
                "no retry after a confirmed unlock"
            );
            assert!(mt.is_ready() && mt.is_unlocked(), "the unlock is kept");
            let uploads = t.cdbs.iter().filter(|c| c[0] == SCSI_WRITE_BUFFER).count();
            assert_eq!(
                uploads,
                failed_reloads + 1,
                "the final upload is still issued"
            );
            assert_eq!(t.cdbs.last().map(|c| c[0]), Some(SCSI_TEST_UNIT_READY));
            assert!(
                t0.elapsed() < std::time::Duration::from_secs(5),
                "no fixed 10 s settle: a ready drive returns at once"
            );
        }
    }

    // The upload reset the drive: a confirmed unlock does not prove the media is
    // ready, so run_init polls TEST UNIT READY until it is (coordinator review of
    // ST-D10; the T6 rule, stop-design-v5 §2.11) before handing the drive back.
    #[test]
    fn run_init_waits_for_media_ready_after_upload() {
        use crate::scsi::mock::{MockTransport, Reply};
        let sig = [0x11, 0x22, 0x33, 0x44];
        let unlock_ok = build_response(sig, FIRMWARE_ACTIVE_SIG, FIRMWARE_MODE_SIG);
        let becoming_ready = || Reply::Sense {
            status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
            sense_key: 0x02,
            asc: 0x04,
            ascq: 0x01,
        };
        let script = vec![
            Reply::short(vec![0u8; 64], 10), // run_init's do_unlock
            Reply::good(vec![]),             // WRITE_BUFFER
            Reply::good(vec![0u8; VALIDATE_RESPONSE_SIZE as usize]), // 0x45 verify
            Reply::good(unlock_ok.clone()),  // do_unlock #1
            Reply::good(unlock_ok),          // do_unlock #2
            becoming_ready(),                // TUR: 02/04/01
            becoming_ready(),                // TUR: 02/04/01
            Reply::good(vec![]),             // TUR: ready
        ];
        let expected = script.len();
        let mut t = MockTransport::scripted(script, Reply::TransportFault);
        let mut profile = fixture_profile(sig);
        profile.firmware = vec![0u8; 64];
        let mut mt = Mt1959::new(profile, false);
        mt.init(&mut t).expect("ready after two not-ready polls");
        assert_eq!(t.calls(), expected, "polled until ready, then stopped");
        let turs = t.cdbs.iter().filter(|c| c[0] == SCSI_TEST_UNIT_READY);
        assert_eq!(turs.count(), 3, "three TEST UNIT READY polls");
    }

    /// A virtual clock: `wait` advances time instantly and counts the waits.
    pub(crate) struct FakeClock {
        now: Duration,
        waits: usize,
    }

    impl FakeClock {
        pub(crate) fn new() -> Self {
            FakeClock {
                now: Duration::ZERO,
                waits: 0,
            }
        }
    }

    impl ReadyClock for FakeClock {
        fn elapsed(&self) -> Duration {
            self.now
        }
        fn wait(&mut self, _scsi: &mut dyn ScsiTransport, d: Duration) -> crate::scsi::Result<()> {
            self.now += d;
            self.waits += 1;
            Ok(())
        }
    }

    /// A NOT READY TEST UNIT READY answer (status CHECK CONDITION).
    fn not_ready(asc: u8, ascq: u8) -> crate::scsi::mock::Reply {
        crate::scsi::mock::Reply::Sense {
            status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
            sense_key: 0x02,
            asc,
            ascq,
        }
    }

    // T6 (stop-design-v5 §2.11): NOT READY "becoming ready" for a few polls, then
    // ready → Ok, having waited only between polls (no fixed settle).
    #[test]
    fn media_ready_poll_returns_once_ready() {
        use crate::scsi::mock::{MockTransport, Reply};
        let script = vec![
            not_ready(0x04, 0x01),
            not_ready(0x04, 0x01),
            not_ready(0x04, 0x01),
        ];
        let mut t = MockTransport::scripted(script, Reply::good(vec![]));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("ready on the 4th poll");
        assert_eq!(r, MediaReady::Ready);
        assert_eq!(t.calls(), 4);
        assert!(t.cdbs.iter().all(|c| c.as_slice() == [0u8; 6]), "TUR only");
        assert_eq!((clock.waits, clock.now), (3, READY_POLL * 3));
    }

    // Review of ST-D10: a stall after a confirmed upload must not undo the unlock.
    // The SAME not-ready answer for 60 s (T6) → warn and return Ok, exactly at 60 s.
    #[test]
    fn media_ready_poll_stall_keeps_the_unlock() {
        use crate::scsi::mock::MockTransport;
        let mut t = MockTransport::always(not_ready(0x04, 0x01));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("a stall keeps the unlock");
        let want = MediaReady::Stalled {
            sense_key: 0x02,
            asc: 0x04,
            ascq: 0x01,
        };
        assert_eq!(r, want);
        assert_eq!(
            clock.now, READY_STALL,
            "gives up exactly at 60 s without progress"
        );
        assert_eq!(
            t.calls(),
            121,
            "one poll per 500 ms, then the 61st second's poll"
        );
    }

    // MMC-6 Table F.3 "2 3A 00 MEDIUM NOT PRESENT": 10 consecutive answers (~5 s,
    // libfreemkv WAIT_READY_MAX_EMPTY_POLLS) with no 04/01 → Ok (empty drive).
    #[test]
    fn media_ready_poll_no_medium_returns_after_the_grace() {
        use crate::scsi::mock::MockTransport;
        let mut t = MockTransport::always(not_ready(0x3A, 0x00));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("empty drive");
        assert_eq!(r, MediaReady::NoMedium);
        assert_eq!(
            (t.calls(), clock.waits),
            (10, 9),
            "10 × 3A, ~4.5 s of waits"
        );
    }

    // Table F.3 "2 04 01 LOGICAL UNIT IS IN PROCESS OF BECOMING READY" seen first:
    // a later 3A run is not final, so the poll keeps going past 10 × 3A.
    #[test]
    fn media_ready_poll_keeps_polling_3a_after_04_01() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut script = vec![not_ready(0x04, 0x01)];
        script.extend((0..20).map(|_| not_ready(0x3A, 0x00)));
        let mut t = MockTransport::scripted(script, Reply::good(vec![]));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("ready");
        assert_eq!(r, MediaReady::Ready, "not cut off as an empty drive");
        assert_eq!(t.calls(), 22, "polled through 20 × 3A to ready");
    }

    // Table F.3 "2 04 02 LOGICAL UNIT NOT READY, INITIALIZING CMD. REQUIRED" →
    // exactly one START STOP UNIT, Table 633 "0 1 Start the disc and make ready".
    #[test]
    fn media_ready_poll_04_02_sends_one_start_unit() {
        use crate::scsi::mock::{MockTransport, Reply};
        let script = vec![
            not_ready(0x04, 0x02),
            not_ready(0x04, 0x02),
            not_ready(0x04, 0x02),
        ];
        let mut t = MockTransport::scripted(script, Reply::good(vec![]));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("ready");
        assert_eq!(r, MediaReady::Ready);
        let starts: Vec<_> = t.cdbs.iter().filter(|c| c[0] == 0x1B).collect();
        assert_eq!(
            starts,
            vec![&vec![0x1B, 0x00, 0x00, 0x00, 0x01, 0x00]],
            "one START UNIT"
        );
        assert_eq!(t.cdbs[1][0], 0x1B, "sent right after the first 04/02");
    }

    // Table F.3 "2 30 00 INCOMPATIBLE MEDIUM INSTALLED" never becomes ready:
    // return Ok at once (the unlock stands), with no wait.
    #[test]
    fn media_ready_poll_incompatible_medium_returns_at_once() {
        use crate::scsi::mock::MockTransport;
        let mut t = MockTransport::always(not_ready(0x30, 0x00));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("unlock kept");
        assert_eq!(
            r,
            MediaReady::Incompatible {
                asc: 0x30,
                ascq: 0x00
            }
        );
        assert_eq!((t.calls(), clock.waits), (1, 0));
    }

    // Table F.1: "6 29 00 POWER ON, RESET, OR BUS DEVICE RESET OCCURRED" and
    // "6 28 00 NOT READY TO READY CHANGE…" after the upload's reset: keep polling.
    #[test]
    fn media_ready_poll_unit_attention_then_ready() {
        use crate::scsi::mock::{MockTransport, Reply};
        let ua = |asc| Reply::Sense {
            status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
            sense_key: 0x06,
            asc,
            ascq: 0x00,
        };
        let mut t = MockTransport::scripted(vec![ua(0x29), ua(0x28)], Reply::good(vec![]));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("ready");
        assert_eq!(r, MediaReady::Ready);
        assert_eq!((t.calls(), clock.waits), (3, 2));
    }

    // MEDIUM ERROR (3), HARDWARE ERROR (4, MMC-6 F.3.8 "reported when SK = HARDWARE
    // ERROR"), ILLEGAL REQUEST (5, F.3.2) are not readiness answers: Ok at once.
    #[test]
    fn media_ready_poll_error_sense_keys_return_at_once() {
        use crate::scsi::mock::{MockTransport, Reply};
        for sense_key in [0x03, 0x04, 0x05] {
            let mut t = MockTransport::always(Reply::Sense {
                status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
                sense_key,
                asc: 0x00,
                ascq: 0x00,
            });
            let mut clock = FakeClock::new();
            let r = await_media_ready(&mut t, &mut clock).expect("unlock kept");
            let want = MediaReady::DriveError {
                sense_key,
                asc: 0,
                ascq: 0,
            };
            assert_eq!(r, want, "SK {sense_key}");
            assert_eq!((t.calls(), clock.waits), (1, 0), "SK {sense_key}");
        }
    }

    // libfreemkv's adapter returns `Err` carrying the sense for a non-zero status:
    // that is a drive answer, not a dead bus, so the poll must keep going.
    #[test]
    fn media_ready_poll_err_with_sense_is_an_answer() {
        use crate::scsi::mock::{MockTransport, Reply};
        let err_nr = || Reply::ErrWithSense {
            status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
            sense_key: 0x02,
            asc: 0x04,
            ascq: 0x01,
        };
        let mut t = MockTransport::scripted(vec![err_nr(), err_nr()], Reply::good(vec![]));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("an answer, not a dead bus");
        assert_eq!(r, MediaReady::Ready);
        assert_eq!(t.calls(), 3);
    }

    // T6: a NEW answer is progress and re-arms the window, so a drive that keeps
    // moving through new states is never cut off by a total (150 s here).
    #[test]
    fn media_ready_poll_new_answers_rearm_the_window() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut script = Vec::new();
        for ascq in [0x01, 0x04, 0x07] {
            script.extend((0..100).map(|_| not_ready(0x04, ascq))); // 50 s each
        }
        let mut t = MockTransport::scripted(script, Reply::good(vec![]));
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut t, &mut clock).expect("progressing drive");
        assert_eq!(r, MediaReady::Ready);
        assert_eq!(clock.now, READY_POLL * 300, "waited 150 s in total");
    }

    // T6 stricter reading (§2.11): two KNOWN answers alternating is not progress,
    // so a flapping drive stalls 60 s after its last new answer (unlock kept).
    #[test]
    fn media_ready_poll_flapping_answers_still_stall() {
        struct Flap(usize);
        impl ScsiTransport for Flap {
            fn execute(
                &mut self,
                _cdb: &[u8],
                _dir: DataDirection,
                _data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                self.0 += 1;
                let mut sense = [0u8; 32];
                sense[2] = 0x02;
                sense[12] = 0x04;
                sense[13] = if self.0.is_multiple_of(2) { 0x01 } else { 0x04 };
                Ok(ScsiResult {
                    status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
                    bytes_transferred: 0,
                    sense,
                })
            }
        }
        let mut clock = FakeClock::new();
        let r = await_media_ready(&mut Flap(0), &mut clock).expect("unlock kept");
        assert!(matches!(r, MediaReady::Stalled { .. }), "{r:?}");
        assert_eq!(
            clock.now,
            READY_POLL + READY_STALL,
            "60 s after the 2nd answer"
        );
    }

    // A dead bus on TEST UNIT READY aborts at once: no wait, no retry.
    #[test]
    fn media_ready_poll_aborts_on_a_dead_bus() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::TransportFault);
        let mut clock = FakeClock::new();
        let e = await_media_ready(&mut t, &mut clock).expect_err("dead bus");
        assert!(e.is_transport_failure());
        assert_eq!((t.calls(), clock.waits), (1, 0));
    }

    // A Stop during the post-upload readiness poll ends it at the next wait:
    // the production clock waits via the transport's cancellable `pause`, and
    // the refusal is the dead-bus shape libfreemkv reclassifies as Halted (§2.3).
    #[test]
    fn media_ready_poll_stop_during_wait_ends_it() {
        use crate::scsi::mock::{Ev, MockTransport, StopFake};
        let mut t = StopFake::new(MockTransport::always(not_ready(0x04, 0x01)));
        t.cancel_after = Some(|c| c[0] == SCSI_TEST_UNIT_READY);
        let t0 = std::time::Instant::now();
        let e = await_media_ready(&mut t, &mut WallClock::start()).expect_err("stopped");
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "no real sleep after a Stop"
        );
        assert!(
            e.is_transport_failure(),
            "the refusal shape (Halted in libfreemkv)"
        );
        assert_eq!(
            t.log,
            vec![Ev::Exec(vec![0u8; 6]), Ev::PauseRefused(READY_POLL)],
            "the wait itself observed the Stop; no further TUR"
        );
    }

    /// A Stop that lands during the upload, through `run_init` on `mode`: the
    /// first do_unlock fails generically (so the firmware reloads), and the
    /// cancel arrives once a CDB matching `stop_at` reaches the drive.
    fn stop_during_upload(
        is_variant_b: bool,
        stop_at: fn(&[u8]) -> bool,
    ) -> (Result<()>, Vec<crate::scsi::mock::Ev>) {
        use crate::scsi::mock::{MockTransport, Reply, StopFake};
        let sig = [0x11, 0x22, 0x33, 0x44];
        let mut profile = fixture_profile(sig);
        profile.firmware = vec![0u8; 64];
        let unlock_ok = build_response(sig, FIRMWARE_ACTIVE_SIG, FIRMWARE_MODE_SIG);
        let inner = MockTransport::scripted(
            vec![Reply::short(vec![0u8; 64], 10)], // run_init's do_unlock
            Reply::good(unlock_ok),
        );
        let mut t = StopFake::new(inner);
        t.cancel_after = Some(stop_at);
        let mut mt = Mt1959::new(profile, is_variant_b);
        let r = mt.init(&mut t);
        (r, t.log)
    }

    fn is_unlock_cdb(c: &[u8]) -> bool {
        c[0] == SCSI_READ_BUFFER && c[2] == BUFFER_ID_A && c[3] == SUB_CMD_UNLOCK
            || c[0] == SCSI_READ_BUFFER && c[2] == BUFFER_ID_B && c[3] == SUB_CMD_UNLOCK
    }

    // UT7 (stop-design-v5 §5.2; §2.3 D8 "the WRITE BUFFER at 30 s … and its verify
    // run inside a `CriticalGuard`. C_max = 35 s"): the verify still executes
    // after a Stop mid-upload, and the next do_unlock is refused.
    #[test]
    fn mt1959_a_upload_completes_after_cancel_then_stops() {
        use crate::scsi::mock::Ev;
        let (r, log) = stop_during_upload(false, |c| c[0] == SCSI_WRITE_BUFFER);
        let e = r.expect_err("the Stop ends the init");
        assert!(e.is_transport_failure(), "a refusal is the dead-bus shape");
        let shape: Vec<String> = log
            .iter()
            .map(|e| match e {
                Ev::Exec(c) if is_unlock_cdb(c) => "unlock".into(),
                Ev::Refused(c) if is_unlock_cdb(c) => "unlock refused".into(),
                Ev::Exec(c) => format!("{:02X}/{:02X}", c[0], c[2]),
                other => format!("{other:?}"),
            })
            .collect();
        let want = ["unlock", "Begin", "3B/00", "3C/45", "End", "unlock refused"];
        assert_eq!(shape, want, "upload + verify complete; then stopped");
    }

    // UT7, cancel before the span: no WRITE BUFFER is ever started.
    #[test]
    fn mt1959_a_stop_before_upload_never_starts_it() {
        use crate::scsi::mock::Ev;
        let (r, log) = stop_during_upload(false, is_unlock_cdb);
        assert!(r.expect_err("stopped").is_transport_failure());
        assert_eq!(log.len(), 2, "{log:?}");
        assert_eq!(
            log[1],
            Ev::BeginRefused,
            "the span refuses to open after a Stop"
        );
    }

    // UT8 (stop-design-v5 §5.2; §2.3 "MODE SELECT at 30 s …, READ BUFFER, WRITE
    // BUFFER and F1 run inside a `CriticalGuard`. C_max = 45 s"), as UT7 for B.
    #[test]
    fn mt1959_b_upload_completes_after_cancel_then_stops() {
        use crate::scsi::mock::Ev;
        let (r, log) = stop_during_upload(true, |c| c[0] == 0x55);
        assert!(r.expect_err("stopped").is_transport_failure());
        let shape: Vec<String> = log
            .iter()
            .map(|e| match e {
                Ev::Exec(c) if is_unlock_cdb(c) => "unlock".into(),
                Ev::Refused(c) if is_unlock_cdb(c) => "unlock refused".into(),
                Ev::Exec(c) => format!("{:02X}", c[0]),
                other => format!("{other:?}"),
            })
            .collect();
        let want = [
            "unlock",
            "Begin",
            "55",
            "3C",
            "3B",
            "F1",
            "End",
            "unlock refused",
        ];
        assert_eq!(
            shape, want,
            "MODE SELECT, READ/WRITE BUFFER, F1; then stopped"
        );
    }

    // UT8, cancel before the span: no MODE SELECT is ever started.
    #[test]
    fn mt1959_b_stop_before_upload_never_starts_it() {
        use crate::scsi::mock::Ev;
        let (r, log) = stop_during_upload(true, is_unlock_cdb);
        assert!(r.expect_err("stopped").is_transport_failure());
        assert_eq!(log.len(), 2, "{log:?}");
        assert_eq!(log[1], Ev::BeginRefused);
    }

    // ── run_probe entry / disc-type detection ───────────────────────────────

    /// `run_probe` called before `init_complete` runs `do_unlock` itself
    /// first (rather than assuming the caller already did).
    #[test]
    fn run_probe_runs_do_unlock_when_not_yet_initialized() {
        let sig = [0x99, 0x9E, 0xC3, 0x75];
        let response = build_response(sig, FIRMWARE_ACTIVE_SIG, FIRMWARE_MODE_SIG);
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::good(response));
        let mut mt = Mt1959::new(fixture_profile(sig), false);
        assert!(!mt.init_complete);
        let r = mt.run_probe(&mut t);
        assert!(r.is_ok(), "probe completes: {r:?}");
        assert!(mt.init_complete, "run_probe must do_unlock itself first");
    }

    // A READ CAPACITY drive sense means "capacity unknown" -> falls back
    // to 0 sectors, which is below the UHD threshold, so probing
    // continues with the BD init address rather than aborting.
    #[test]
    fn run_probe_capacity_check_condition_falls_back_to_zero_sectors() {
        struct CapacitySenseTransport;
        impl ScsiTransport for CapacitySenseTransport {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                if cdb.first() == Some(&SCSI_READ_CAPACITY) {
                    return Ok(ScsiResult {
                        status: 0x02,
                        bytes_transferred: 0,
                        sense: [0u8; 32],
                    });
                }
                for b in data.iter_mut() {
                    *b = 0;
                }
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: data.len(),
                    sense: [0u8; 32],
                })
            }
        }
        let mut t = CapacitySenseTransport;
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let r = mt.run_probe(&mut t);
        assert!(
            r.is_ok(),
            "a capacity sense must not abort the probe: {r:?}"
        );
    }

    /// A disc reporting more than `UHD_SECTOR_THRESHOLD` sectors selects the
    /// UHD init address (0x0200) rather than the BD one (0x0100).
    #[test]
    fn run_probe_selects_uhd_init_addr_for_a_large_disc() {
        struct BigDiscTransport {
            init_addr_seen: std::cell::RefCell<Option<u16>>,
        }
        impl ScsiTransport for BigDiscTransport {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                if cdb.first() == Some(&SCSI_READ_CAPACITY) {
                    // last_lba = UHD_SECTOR_THRESHOLD (well above threshold
                    // once +1'd), well past the 25M-sector cutoff.
                    let last_lba: u32 = UHD_SECTOR_THRESHOLD + 1_000_000;
                    data[..4].copy_from_slice(&last_lba.to_be_bytes());
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: 4,
                        sense: [0u8; 32],
                    });
                }
                if cdb.first() == Some(&SCSI_READ_BUFFER) && cdb.get(3) == Some(&SUB_CMD_INIT) {
                    let addr = ((cdb[4] as u16) << 8) | cdb[5] as u16;
                    *self.init_addr_seen.borrow_mut() = Some(addr);
                }
                for b in data.iter_mut() {
                    *b = 0;
                }
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: data.len(),
                    sense: [0u8; 32],
                })
            }
        }
        let mut t = BigDiscTransport {
            init_addr_seen: std::cell::RefCell::new(None),
        };
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let _ = mt.run_probe(&mut t);
        assert_eq!(
            *t.init_addr_seen.borrow(),
            Some(INIT_ADDR_UHD),
            "a >25M-sector disc must probe-init at the UHD address"
        );
    }

    // The fine (pass-2) probe sweep ends early on a merely-rejected
    // probe reply (not a transport fault) — it must `break` and let
    // `run_probe` still return `Ok`.
    #[test]
    fn run_probe_pass2_ends_early_on_a_rejected_probe_without_failing() {
        struct Pass2RejectsTransport {
            fault_at: u32,
        }
        impl ScsiTransport for Pass2RejectsTransport {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                if cdb.first() == Some(&SCSI_READ_BUFFER) && cdb.get(3) == Some(&SUB_CMD_PROBE) {
                    let addr = ((cdb[4] as u32) << 8) | cdb[5] as u32;
                    if addr >= self.fault_at {
                        return Ok(ScsiResult {
                            status: 0x02,
                            bytes_transferred: 0,
                            sense: [0u8; 32],
                        });
                    }
                }
                for b in data.iter_mut() {
                    *b = 0;
                }
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: data.len(),
                    sense: [0u8; 32],
                })
            }
        }
        let mut t = Pass2RejectsTransport {
            fault_at: PROBE_COARSE_END as u32,
        };
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let r = mt.run_probe(&mut t);
        assert!(
            r.is_ok(),
            "a rejected fine probe must end the sweep, not fail run_probe: {r:?}"
        );
        assert!(mt.probed);
    }

    // ── PlatformDriver trait guard clauses ──────────────────────────────────

    /// `init()` is a no-op once `init_complete` is already set — it must not
    /// re-run the handshake.
    #[test]
    fn init_is_a_noop_once_already_complete() {
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::TransportFault);
        assert!(mt.init(&mut t).is_ok());
        assert_eq!(t.calls(), 0, "already-complete init must issue no CDBs");
    }

    /// `probe_disc()` before `init()` succeeded is a deliberate no-op (not a
    /// retry of init): it must return `Ok(())` without touching the bus.
    #[test]
    fn probe_disc_is_a_noop_before_init_completes() {
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::TransportFault);
        assert!(mt.probe_disc(&mut t).is_ok());
        assert_eq!(t.calls(), 0);
    }

    /// `probe_disc()` is a no-op once already probed.
    #[test]
    fn probe_disc_is_a_noop_once_already_probed() {
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        mt.init_complete = true;
        mt.probed = true;
        let mut t =
            crate::scsi::mock::MockTransport::always(crate::scsi::mock::Reply::TransportFault);
        assert!(mt.probe_disc(&mut t).is_ok());
        assert_eq!(t.calls(), 0);
    }

    /// `is_ready()` mirrors `init_complete`.
    #[test]
    fn is_ready_mirrors_init_complete() {
        let mut mt = Mt1959::new(fixture_profile([0; 4]), false);
        assert!(!mt.is_ready());
        mt.init_complete = true;
        assert!(mt.is_ready());
    }

    #[test]
    fn do_unlock_rejects_inactive_mode_marker() {
        // Signature matches but the primary marker at [12..16] is
        // missing -> drive is not in active mode; init_complete and the
        // unlocked flag must both stay false.
        let sig = [0x99, 0x9E, 0xC3, 0x75];
        let response = build_response(sig, [0u8; 4], FIRMWARE_MODE_SIG);
        let mut transport = ScriptedTransport { response };
        let mut mt = Mt1959::new(fixture_profile(sig), false);

        let err = mt.do_unlock(&mut transport).unwrap_err();
        assert!(matches!(err, Error::UnlockFailed));
        assert!(!mt.init_complete);
        assert!(!mt.is_unlocked());
    }
}
