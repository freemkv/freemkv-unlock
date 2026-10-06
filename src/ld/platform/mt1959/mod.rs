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

/// The production clock: real time, and the transport's cancellable `pause`
/// between polls (stop-design-v5 §2.3), so a Stop ends the wait at once.
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
    fn wait(&mut self, scsi: &mut dyn ScsiTransport, d: Duration) -> scsi::Result<()> {
        scsi.pause(d)
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
#[path = "mod_tests.rs"]
pub(crate) mod tests;
