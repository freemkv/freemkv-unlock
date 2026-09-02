//! renesas — Renesas-platform detection (Pioneer + HL-DT-ST Renesas drives).
//!
//! Optical drives split into two controller families: MediaTek (handled by
//! [`crate::ld`]) and Renesas. This module identifies the Renesas side via a
//! single vendor identity probe (see [`is_renesas`]) and reports the match so a
//! Renesas drive is named honestly. It does not modify drive state; AACS bus
//! decryption is handled by the host cert.

use crate::scsi::{DataDirection, ScsiTransport};
use crate::{UnlockCtx, UnlockError, Unlocked, Unlocker};

/// READ_BUFFER mode 0x02, buffer 0xF1 — the Renesas vendor identity buffer.
const RB_F1_CDB: [u8; 10] = [0x3C, 0x02, 0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00];
const RB_F1_LEN: usize = 48;
/// The ASCII interface marker a Renesas controller returns at `[16..19]`.
const RENESAS_MARKER: &[u8] = b"SAT";
const RENESAS_MARKER_OFFSET: usize = 16;

/// `Ok(true)` if `scsi` is a Renesas-platform drive (Pioneer or HL-DT-ST
/// Renesas).
///
/// Issues the vendor READ_BUFFER 0x02/0xF1 probe: a Renesas controller serves
/// a 48-byte identity block whose bytes `[16..19]` are the ASCII `SAT`
/// interface tag. A rejection (CHECK CONDITION or `Err` with a sense) is
/// `Ok(false)`: not a Renesas drive.
///
/// `Err(Transport)` on a dead bus. See docs/renesas-mod.md for why a
/// transport fault must not be folded into `Ok(false)`.
pub fn is_renesas(scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
    let mut buf = [0u8; RB_F1_LEN];
    match scsi.execute(&RB_F1_CDB, DataDirection::FromDevice, &mut buf, 5_000) {
        Ok(r) => {
            let end = RENESAS_MARKER_OFFSET + RENESAS_MARKER.len();
            Ok(r.status == 0
                && r.bytes_transferred >= end
                && &buf[RENESAS_MARKER_OFFSET..end] == RENESAS_MARKER)
        }
        // Only a senseless transport-failure status is a dead bus; anything
        // else the transport reports as `Err` is the drive refusing.
        Err(e) => {
            if e.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none() {
                tracing::warn!(
                    target: "freemkv::disc",
                    phase = "renesas_probe_transport_fault",
                    "transport fault on the Renesas identity probe; aborting"
                );
                return Err(UnlockError::Transport);
            }
            tracing::debug!(
                target: "freemkv::disc",
                phase = "renesas_probe_rejected",
                status = e.status,
                "Renesas identity probe rejected by the drive; not a Renesas platform"
            );
            Ok(false)
        }
    }
}

/// The Renesas-platform unlocker. `pub(crate)` — reached only through
/// [`crate::all_unlockers`].
pub(crate) struct Renesas;

impl Renesas {
    pub(crate) fn new() -> Self {
        Renesas
    }

    // MakeMKV's vendor "open" sequence: primary read (A), and on refusal a
    // knock + second read (B). See docs/renesas-mod.md for the full sequence
    // and why we run A→knock→B rather than bailing after A.
    fn vendor_open(scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
        const RB_B0_04_CDB: [u8; 10] = [0x3C, 0x02, 0xB0, 0x00, 0x00, 0x04, 0x00, 0x00, 0xA4, 0x00];
        const KNOCK_A5AAAA_CDB: [u8; 10] =
            [0x3B, 0x02, 0x41, 0xA5, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00];
        const RB_B0_500000_CDB: [u8; 10] =
            [0x3C, 0x02, 0xB0, 0x50, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x00];

        // A: primary open read.
        if read_is_good(scsi, &RB_B0_04_CDB)? {
            return Ok(true);
        }
        // B: MakeMKV's fallback — knock, then the second-window read. The knock is
        // fire-and-forget (payload-less); its own status is not the signal.
        match scsi.execute(&KNOCK_A5AAAA_CDB, DataDirection::None, &mut [], 5_000) {
            Ok(_) => {}
            Err(e)
                if e.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none() =>
            {
                return Err(UnlockError::Transport);
            }
            Err(_) => {} // a drive that refuses the knock still gets the B read tried
        }
        read_is_good(scsi, &RB_B0_500000_CDB)
    }
}

/// Issue a 164-byte vendor READ_BUFFER; `Ok(true)` on GOOD status, `Ok(false)`
/// on CHECK CONDITION (drive refused), `Err(Transport)` on a senseless
/// transport failure (dead bus).
fn read_is_good(
    scsi: &mut dyn ScsiTransport,
    cdb: &[u8; 10],
) -> std::result::Result<bool, UnlockError> {
    let mut buf = [0u8; 164];
    match scsi.execute(cdb, DataDirection::FromDevice, &mut buf, 5_000) {
        Ok(r) => Ok(r.status == 0),
        Err(e) => {
            if e.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none() {
                return Err(UnlockError::Transport);
            }
            Ok(false)
        }
    }
}

impl Unlocker for Renesas {
    fn name(&self) -> &'static str {
        "Renesas"
    }

    // Gate on the `0xF1` SAT identity, then the vendor open read `0xB0@0x04`;
    // `drive_unlocked: false` since AACS bus decryption is the cert's job.
    // See docs/renesas-mod.md for the full MakeMKV-parity rationale.
    fn unlock_features(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        if !is_renesas(scsi)? {
            return Err(UnlockError::NotApplicable);
        }
        if !Self::vendor_open(scsi)? {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "renesas_open_rejected",
                "Renesas drive recognized but RB 0xB0@0x04 refused; deferring to next unlocker"
            );
            return Err(UnlockError::NotApplicable);
        }
        tracing::debug!(
            target: "freemkv::disc",
            phase = "renesas_opened",
            "Renesas drive opened (RB 0xB0@0x04 GOOD); bus handled by cert"
        );
        Ok(Unlocked {
            vid: None,
            bus_key: None,
            drive_unlocked: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscKind;
    use crate::scsi::{DataDirection, Result, ScsiError, ScsiResult, ScsiTransport};

    /// Serves a fixed READ_BUFFER payload (Renesas-like) with a Good status.
    struct RenesasTransport {
        payload: Vec<u8>,
    }
    impl ScsiTransport for RenesasTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            let n = self.payload.len().min(data.len());
            data[..n].copy_from_slice(&self.payload[..n]);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }

    // Rejects like a MediaTek drive: ILLEGAL REQUEST with a sense, which is
    // what distinguishes this from a dead bus. See docs/renesas-mod.md.
    struct RejectingTransport;
    impl ScsiTransport for RejectingTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            _data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            let mut sense = [0u8; 32];
            sense[2] = 0x05; // ILLEGAL REQUEST
            sense[12] = 0x20; // invalid command operation code
            Err(ScsiError {
                status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
                sense: Some(sense),
            })
        }
    }

    fn renesas_payload() -> Vec<u8> {
        // 48-byte RB 0xF1 block with "SAT" at [16..19] (the real S13JX shape).
        let mut p = vec![0x20u8; 48];
        p[16..19].copy_from_slice(b"SAT");
        p
    }

    #[test]
    fn is_renesas_true_on_sat_marker() {
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        assert!(is_renesas(&mut t).expect("no transport fault"));
    }

    #[test]
    fn is_renesas_false_when_command_rejected() {
        let mut t = RejectingTransport;
        assert!(!is_renesas(&mut t).expect("a drive rejection is not a bus fault"));
    }

    #[test]
    fn is_renesas_false_on_missing_marker() {
        // Good status but no "SAT" at [16..19] (e.g. a stray buffer).
        let mut t = RenesasTransport {
            payload: vec![0u8; 48],
        };
        assert!(!is_renesas(&mut t).expect("no transport fault"));
    }

    #[test]
    fn is_renesas_false_on_short_response() {
        // Fewer than 19 bytes returned — can't carry the marker.
        let mut t = RenesasTransport {
            payload: vec![0x20u8; 8],
        };
        assert!(!is_renesas(&mut t).expect("no transport fault"));
    }

    #[test]
    fn features_report_match_without_bus_removal_on_renesas() {
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown, &[]);
        // Recognized → Ok, but a feature-only unlock: bus NOT removed, no VID.
        let u = Renesas::new()
            .unlock_features(&mut t, &ctx)
            .expect("renesas → Ok");
        assert!(
            !u.drive_unlocked,
            "renesas does not remove the bus (cert does)"
        );
        assert_eq!(u.vid, None);
        assert_eq!(u.bus_key, None);
    }

    /// A drive REJECTION (ILLEGAL REQUEST, with a sense) is "not a Renesas
    /// drive" → fall through to the next unlocker.
    #[test]
    fn features_not_applicable_on_non_renesas() {
        let mut t = RejectingTransport;
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown, &[]);
        let err = Renesas::new().unlock_features(&mut t, &ctx).unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }

    // Same rejection via a CONFORMING transport (`Ok` + CHECK CONDITION);
    // must reach the same answer. See docs/renesas-mod.md.
    #[test]
    fn check_condition_is_not_a_renesas_drive() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::illegal_request());
        assert!(!is_renesas(&mut t).expect("a drive sense is not a bus fault"));
    }

    /// THE defect-8 test: a dead bus on the FIRST command the unlocker issues
    /// must abort the consumer, not be reported as "not a Renesas drive".
    /// Catches restoring the `Err(_) => false` arm.
    #[test]
    fn transport_fault_aborts_instead_of_declining() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(is_renesas(&mut t).unwrap_err(), UnlockError::Transport);

        let mut t = MockTransport::always(Reply::TransportFault);
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown, &[]);
        assert_eq!(
            Renesas::new().unlock_features(&mut t, &ctx).unwrap_err(),
            UnlockError::Transport
        );
    }

    // A recognized Renesas drive that REFUSES the vendor open read must
    // defer to the next unlocker, not claim the drive. See docs/renesas-mod.md.
    #[test]
    fn open_rejection_defers_to_next_unlocker() {
        struct GateOkOpenRefused;
        impl ScsiTransport for GateOkOpenRefused {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> Result<ScsiResult> {
                if cdb.get(2) == Some(&0xF1) {
                    // Serve the SAT identity so is_renesas() matches.
                    let p = renesas_payload();
                    let n = p.len().min(data.len());
                    data[..n].copy_from_slice(&p[..n]);
                    Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: n,
                        sense: [0u8; 32],
                    })
                } else {
                    // RB 0xB0@0x04 (the open read) → CHECK CONDITION.
                    let mut sense = [0u8; 32];
                    sense[2] = 0x05; // ILLEGAL REQUEST
                    sense[12] = 0x20; // invalid command operation code
                    Err(ScsiError {
                        status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
                        sense: Some(sense),
                    })
                }
            }
        }
        let mut t = GateOkOpenRefused;
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown, &[]);
        assert_eq!(
            Renesas::new().unlock_features(&mut t, &ctx).unwrap_err(),
            UnlockError::NotApplicable
        );
    }

    #[test]
    fn does_not_provide_bus_removal() {
        // Renesas leaves bus encryption to the cert: unlock_bus is the default.
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Aacs, &[]);
        let err = Renesas::new().unlock_bus(&mut t, &ctx).unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }
}
