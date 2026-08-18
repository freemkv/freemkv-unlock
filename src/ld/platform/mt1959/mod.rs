//! MT1959 platform — shared logic for both variants.

mod variant_a;
mod variant_b;

use super::PlatformDriver;
use crate::ld::error::{Error, Result};
use crate::ld::profile::DriveProfile;
use crate::scsi::{self, DataDirection, ScsiTransport};

// ── Variant constants ──────────────────────────────────────────────────
// Every vendor command: 3C [mode] [buffer_id] [sub_cmd] [addr] ...
const MODE_A: u8 = 0x01;
const MODE_B: u8 = 0x02;
const BUFFER_ID_A: u8 = 0x44;
const BUFFER_ID_B: u8 = 0x77;

// ── SCSI opcodes ──────────────────────────────────────────────────────
const SCSI_READ_BUFFER: u8 = 0x3C;
const SCSI_READ_CAPACITY: u8 = 0x25;
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
        // `expected` above 255 cannot be expressed and would silently
        // truncate. All in-crate callers pass small fixed sizes (4); guard
        // the invariant rather than emit a malformed CDB.
        debug_assert!(
            expected <= u8::MAX as usize,
            "read_buffer_probe expected exceeds 1-byte CDB length field"
        );
        let cdb = self.read_buffer_sub(sub_cmd, address, expected as u8);
        let result = scsi.execute(&cdb, DataDirection::FromDevice, buf, 5_000)?;
        // A drive sense arrives as `Ok` with a non-zero status (the transport
        // contract), and a merely SHORT response is the drive answering badly —
        // neither is a dead bus. Fabricating a transport-failure status here
        // turned a short probe reply into a hard abort of a rip that would
        // otherwise have succeeded; a real transport fault still propagates
        // through the `?` above with its own status.
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

        // `response` is a fixed 64-byte buffer, so `response.len()` is
        // always >= every offset below — the meaningful bound is how many
        // bytes the drive actually delivered. Every marker check MUST be
        // reachable: when the checks were each guarded by their own `n >= ..`
        // the drive delivering ZERO bytes skipped all three and `do_unlock`
        // returned `Ok` on a buffer the drive never wrote. Require enough bytes
        // to actually validate, up front.
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

        // Extended-access state is active when BOTH the per-drive
        // signature matched AND the response carries the secondary
        // marker at offset 16 (repeated through bytes 16..64) AND the
        // primary mode marker at [12..16] is present. The active-mode
        // marker at [12..16] is the primary gate; the [16..20] marker
        // is the redundant confirmation the firmware writes through
        // the rest of the response. Requiring both before we tell the
        // upper layer "OEM path is live" keeps any partial / corrupted
        // response from steering us off the cert-auth fallback.
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
                // A transport fault means the bus is gone. Re-uploading firmware
                // into a dead bus three times accomplishes nothing and the
                // generic UnlockFailed it used to end on is classified as
                // "unlocker not applicable", so the consumer kept probing a dead
                // drive instead of aborting. Surface the fault unchanged.
                Err(e) if e.is_transport_failure() => {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "mt1959_transport_fault",
                        attempt,
                        "transport fault during unlock; aborting"
                    );
                    return Err(e);
                }
                Err(e) => {
                    last_err = e;
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
                        Ok(()) => {
                            // Firmware upload resets the drive. Give it time to
                            // fully recover before retrying unlock.
                            std::thread::sleep(std::time::Duration::from_secs(10));
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

        // Detect disc type from capacity to select probe mode.
        // BD:  3C 01 44 12 01 00 00 00 04 00  (init_addr = 0x0100)
        // UHD: 3C 01 44 12 02 00 00 00 04 00  (init_addr = 0x0200)
        // Empirically verified via SCSI capture: BD and UHD use different init addresses.
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
        // A transport fault here is a dead bus: propagate it (the caller
        // classifies it as `Transport` and aborts) instead of silently
        // defaulting the disc type. A drive sense (`Ok`, non-zero status) or a
        // short reply just means "capacity unknown" -> assume BD.
        let cap = scsi.execute(&cap_cdb, DataDirection::FromDevice, &mut cap_buf, 5_000)?;
        let disc_sectors = if cap.status == 0 && cap.bytes_transferred >= 4 {
            // last_lba + 1 = sector count. A 0xFFFFFFFF last-LBA is the
            // READ CAPACITY(10) "capacity exceeds 32 bits" sentinel; saturate
            // rather than wrap to 0 (which would misclassify a huge disc as
            // BD). A saturated count stays above the UHD threshold -> UHD.
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
            if self
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
                .is_err()
            {
                // Surface the drive's OWN failure. Re-labelling it as a
                // transport failure turned a short/rejected probe response into
                // a hard abort of the whole rip.
                return Err(Error::UnlockFailed);
            }
            addr = addr.wrapping_add(PROBE_STEP);
        }

        // Pass 2: continue past the coarse range. It used to restart at 0 with
        // the SAME PROBE_STEP, re-issuing all 88 pass-1 addresses verbatim — 88
        // redundant SCSI round-trips per disc, which dominates drive prep at
        // real bus latency and teaches the drive's speed table nothing new.
        let mut addr: u32 = PROBE_COARSE_END as u32;
        while addr < PROBE_FINE_END {
            let mut resp = [0u8; PROBE_RESPONSE_SIZE as usize];
            if self
                .read_buffer_probe(
                    scsi,
                    SUB_CMD_PROBE,
                    addr as u16,
                    &mut resp,
                    PROBE_RESPONSE_SIZE as usize,
                )
                .is_err()
            {
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
mod tests {
    use super::*;
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

    /// variant_a had no direct test at all (variant_b did). Pins its upload
    /// sequence: WRITE_BUFFER carrying the firmware at its real per-drive
    /// length in the CDB's 24-bit length field, then the 0x45 verify READ_BUFFER
    /// whose result used to be discarded outright.
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

    /// THE defect-15 test. A drive that returns ZERO bytes used to skip the
    /// signature check, the firmware-active check AND the mode check — every
    /// gate was individually guarded by its own `n >= ..` — so `do_unlock`
    /// returned `Ok(vec![0u8; 64])` and (with the old `drive_unlocked: true`)
    /// reported a fully unlocked drive. Catches restoring those per-check
    /// guards.
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

    /// THE defect-16 test (the inverse misclassification). A merely SHORT probe
    /// response used to be fabricated into a transport-failure status, which
    /// hard-aborts a rip that would otherwise have succeeded. Catches
    /// reintroducing the fabricated 0xFF.
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

    /// THE defect-4 test. A dead bus must abort `run_init` at once. It used to
    /// match `Err(_)` and re-upload firmware into the dead bus on all three
    /// attempts, then return the generic `UnlockFailed`, which classifies as
    /// `NotApplicable` — so the consumer kept probing. Catches removing the
    /// `is_transport_failure` arm.
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

    /// Build a synthetic 64-byte unlock response.
    ///
    /// `mode_marker`: bytes [12..16]. Pass `FIRMWARE_ACTIVE_SIG` for the
    /// active-mode primary marker.
    /// `id_marker`:   bytes [16..20] (and repeated through [20..64] in
    /// real responses; only [16..20] is checked).
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
