//! renesis — Renesas-platform detection (Pioneer + HL-DT-ST Renesas drives).
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

/// True if `scsi` is a Renesas-platform drive (Pioneer or HL-DT-ST Renesas).
///
/// Issues the vendor READ_BUFFER 0x02/0xF1 probe: a Renesas controller serves a
/// 48-byte identity block whose bytes `[16..19]` are the ASCII `SAT` interface
/// tag. A MediaTek drive rejects it (ILLEGAL REQUEST → `Err`), and a transport
/// fault also yields `Err`; both return `false`. This is the definitive
/// Renesas-vs-MediaTek split.
pub fn is_renesas(scsi: &mut dyn ScsiTransport) -> bool {
    let mut buf = [0u8; RB_F1_LEN];
    match scsi.execute(&RB_F1_CDB, DataDirection::FromDevice, &mut buf, 5_000) {
        Ok(r) => {
            let end = RENESAS_MARKER_OFFSET + RENESAS_MARKER.len();
            r.status == 0
                && r.bytes_transferred >= end
                && &buf[RENESAS_MARKER_OFFSET..end] == RENESAS_MARKER
        }
        Err(_) => false,
    }
}

/// The Renesas-platform unlocker. `pub(crate)` — reached only through
/// [`crate::all_unlockers`].
pub(crate) struct Renesis;

impl Renesis {
    pub(crate) fn new() -> Self {
        Renesis
    }
}

impl Unlocker for Renesis {
    fn name(&self) -> &'static str {
        "Renesas"
    }

    /// Report whether the drive is a Renesas platform. On a match, returns `Ok`
    /// with `drive_unlocked: false` — the drive is recognized but its state is
    /// not modified here (AACS bus decryption is handled by the host cert). A
    /// non-Renesas drive → `NotApplicable`.
    fn unlock_features(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        if !is_renesas(scsi) {
            return Err(UnlockError::NotApplicable);
        }
        tracing::debug!(
            target: "freemkv::disc",
            phase = "renesas_recognized",
            "Renesas drive recognized; bus handled by cert"
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

    /// Rejects the command (a MediaTek drive → ILLEGAL REQUEST → transport `Err`).
    struct RejectingTransport;
    impl ScsiTransport for RejectingTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            _data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            Err(ScsiError {
                status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
                sense: None,
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
        assert!(is_renesas(&mut t));
    }

    #[test]
    fn is_renesas_false_when_command_rejected() {
        let mut t = RejectingTransport;
        assert!(!is_renesas(&mut t));
    }

    #[test]
    fn is_renesas_false_on_missing_marker() {
        // Good status but no "SAT" at [16..19] (e.g. a stray buffer).
        let mut t = RenesasTransport {
            payload: vec![0u8; 48],
        };
        assert!(!is_renesas(&mut t));
    }

    #[test]
    fn is_renesas_false_on_short_response() {
        // Fewer than 19 bytes returned — can't carry the marker.
        let mut t = RenesasTransport {
            payload: vec![0x20u8; 8],
        };
        assert!(!is_renesas(&mut t));
    }

    #[test]
    fn features_report_match_without_bus_removal_on_renesas() {
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown, &[]);
        // Recognized → Ok, but a feature-only unlock: bus NOT removed, no VID.
        let u = Renesis::new()
            .unlock_features(&mut t, &ctx)
            .expect("renesas → Ok");
        assert!(
            !u.drive_unlocked,
            "renesis does not remove the bus (cert does)"
        );
        assert_eq!(u.vid, None);
        assert_eq!(u.bus_key, None);
    }

    #[test]
    fn features_not_applicable_on_non_renesas() {
        let mut t = RejectingTransport;
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown, &[]);
        let err = Renesis::new().unlock_features(&mut t, &ctx).unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }

    #[test]
    fn does_not_provide_bus_removal() {
        // Renesas leaves bus encryption to the cert: unlock_bus is the default.
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Aacs, &[]);
        let err = Renesis::new().unlock_bus(&mut t, &ctx).unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }
}
