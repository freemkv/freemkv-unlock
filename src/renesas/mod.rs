//! renesas — Renesas-platform detection (Pioneer + HL-DT-ST Renesas drives).
//!
//! Optical drives split into two controller families: MediaTek (handled by
//! [`crate::ld`]) and Renesas. This module identifies the Renesas side via a
//! single vendor identity probe (see [`is_renesas`]). Renesas drives are
//! OEM-unlocked: identity establishes unlocked status without a host certificate.
//! Vendor register access is used only for optional VID retrieval; a read
//! miss preserves unlocked status, while transport faults and cancellation abort.

use crate::scsi::{DataDirection, ScsiTransport, is_dead_bus};
use crate::{UnlockCtx, UnlockError, Unlocked, Unlocker};

/// The Renesas vendor identity block length (READ_BUFFER 0x02/0xF1).
const RB_F1_LEN: usize = pioneer_optical::IDENTITY_LEN;
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
/// `Err(Transport)` on a dead bus.
pub fn is_renesas(scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
    let mut buf = [0u8; RB_F1_LEN];
    let cdb = pioneer_optical::cdb::vendor_identity();
    match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
        Ok(r) => {
            let end = RENESAS_MARKER_OFFSET + RENESAS_MARKER.len();
            Ok(r.status == 0
                && (end..=buf.len()).contains(&r.bytes_transferred)
                && &buf[RENESAS_MARKER_OFFSET..end] == RENESAS_MARKER)
        }
        // Only a senseless transport-failure status is a dead bus; anything
        // else the transport reports as `Err` is the drive refusing.
        Err(e) => {
            if is_dead_bus(&e) {
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

/// Recognizes OEM-unlocked Renesas drives and optionally reads their VID from
/// hardware registers. This does not enable standard AACS VID reads.
#[derive(Default)]
pub struct Renesas;

impl Renesas {
    pub fn new() -> Self {
        Renesas
    }
}

// Selector 0x92 maps offset - 0x2000 to high CPU memory; no AAAA gate.
const VID_STATUS_CDB: [u8; 10] = [0x3c, 2, 0x92, 0, 0x0d, 0x3c, 0, 0, 1, 0];
const VID_CDB: [u8; 10] = [0x3c, 2, 0x92, 0, 0x0d, 0x20, 0, 0, 16, 0];

fn get_vid(scsi: &mut dyn ScsiTransport) -> std::result::Result<Option<[u8; 16]>, UnlockError> {
    // Mirror the OEM hardware-copy gate. Other status bits are not interpreted.
    let mut status = [0];
    let result = scsi.execute(
        &VID_STATUS_CDB,
        DataDirection::FromDevice,
        &mut status,
        5_000,
    );
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_status",
        cdb = ?VID_STATUS_CDB, requested = 1, ?result, payload = ?status,
        "Reading Renesas VID hardware status");
    match result {
        Ok(r) if r.status == 0 && r.bytes_transferred == 1 && status[0] & 2 != 0 => {}
        Err(e) if is_dead_bus(&e) => return Err(UnlockError::Transport),
        _ => return Ok(None),
    }
    let mut vid = [0u8; 16];
    let cdb = VID_CDB;
    let address = 0xffff_ed20u32;
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_request",
        address = format_args!("{address:#x}"), cdb = format_args!("{cdb:02x?}"), requested = vid.len(), "Reading VID from Renesas hardware registers");
    let result = match scsi.execute(&cdb, DataDirection::FromDevice, &mut vid, 5_000) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_error",
                address = format_args!("{address:#x}"), status = e.status, sense = ?e.sense,
                dead_bus = is_dead_bus(&e),
                "Renesas hardware VID read failed");
            return if is_dead_bus(&e) {
                Err(UnlockError::Transport)
            } else {
                Ok(None)
            };
        }
    };
    let rejection = if result.status != 0 {
        Some("scsi_status")
    } else if result.bytes_transferred != vid.len() {
        Some("transfer_length")
    } else if vid.iter().all(|&b| b == 0) {
        Some("all_zero")
    } else if vid.iter().all(|&b| b == 0xff) {
        Some("all_ff")
    } else {
        None
    };
    let valid = rejection.is_none();
    // Only show bytes the transport reports receiving, never buffer padding.
    let payload = &vid[..result.bytes_transferred.min(vid.len())];
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_result",
        address = format_args!("{address:#x}"), status = result.status,
        bytes_transferred = result.bytes_transferred, sense = ?result.sense,
        payload = format_args!("{payload:02x?}"), valid, rejection,
        "Renesas hardware VID response");
    Ok(valid.then_some(vid))
}

impl Unlocker for Renesas {
    fn name(&self) -> &'static str {
        "Renesas"
    }

    /// SAT identity establishes OEM-unlocked status. Hardware VID reads are
    /// best-effort; a missing VID preserves success, dead buses abort.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        if !is_renesas(scsi)? {
            return Ok(None);
        }
        let vid = get_vid(scsi)?;
        tracing::debug!(
            target: "freemkv::disc",
            phase = "renesas_opened",
            has_vid = vid.is_some(),
            "Renesas VID discovery completed"
        );
        Ok(Some(Unlocked { vid, bus_key: None }))
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;
