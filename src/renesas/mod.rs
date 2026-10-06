//! renesas — Renesas-platform detection (Pioneer + HL-DT-ST Renesas drives).
//!
//! Optical drives split into two controller families: MediaTek (handled by
//! [`crate::ld`]) and Renesas. This module identifies the Renesas side via a
//! single vendor identity probe (see [`is_renesas`]). Renesas drives are
//! OEM-unlocked: identity establishes unlocked status without a host certificate.
//! Vendor memory access is used only for optional VID discovery; a discovery
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
/// vendor memory. Extended memory access does not enable standard AACS VID reads.
#[derive(Default)]
pub struct Renesas;

impl Renesas {
    pub fn new() -> Self {
        Renesas
    }
}

fn get_vid(
    scsi: &mut dyn ScsiTransport,
    address: u32,
) -> std::result::Result<Option<[u8; 16]>, UnlockError> {
    let mut vid = [0u8; 16];
    let cdb = pioneer_optical::cdb::read_memory(address, vid.len() as u32);
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_request",
        address = format_args!("{address:#x}"), cdb = format_args!("{cdb:02x?}"), requested = vid.len(), "Reading VID from Renesas memory");
    let result = match scsi.execute(&cdb, DataDirection::FromDevice, &mut vid, 5_000) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_error",
                address = format_args!("{address:#x}"), status = e.status, sense = ?e.sense,
                dead_bus = is_dead_bus(&e),
                "Renesas memory VID read failed");
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
        "Renesas memory VID response");
    Ok(valid.then_some(vid))
}

impl Unlocker for Renesas {
    fn name(&self) -> &'static str {
        "Renesas"
    }

    /// SAT identity establishes OEM-unlocked status. Extended reads and RAM VID
    /// discovery are best-effort; a missing VID preserves success, dead buses abort.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        if !is_renesas(scsi)? {
            return Ok(None);
        }
        let vid = if enable_memory_reads(scsi)? {
            match find_vid_addr(scsi)? {
                Some(address) => get_vid(scsi, address)?,
                None => None,
            }
        } else {
            None
        };
        tracing::debug!(
            target: "freemkv::disc",
            phase = "renesas_opened",
            has_vid = vid.is_some(),
            "Renesas VID discovery completed"
        );
        Ok(Some(Unlocked { vid, bus_key: None }))
    }
}

const FIRMWARE_BASE: u32 = 0x41_0000;
const WINDOW_START: u32 = 0x55_a000;
const WINDOW_LEN: usize = 0x20000;
const CHUNK: usize = 0x8000;

/// Locate the source operand of the known 16-byte VID response copy loop.
/// Uniqueness is within this window; this is not a general H8 disassembler.
fn find_slot(code: &[u8]) -> Option<u32> {
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let mut found = None;
    for (offset, op) in code.windows(26).enumerate().step_by(2) {
        if op[..8] != [0x19, 0x33, 0x0d, 0x31, 0x17, 0x71, 0x6e, 0x1c]
            || op[10..14] != [0x78, 0x10, 0x6a, 0xac]
            || op[18..] != [0x0b, 0x53, 0x79, 0x23, 0, 0x10, 0x45, 0xe8]
        {
            continue;
        }
        let address = u16::from_be_bytes([op[8], op[9]]) as u32;
        let pre = &code[offset.saturating_sub(80)..offset];
        let post = &code[offset + 26..(offset + 26 + 240).min(code.len())];
        let work = [0x7a, 0, op[14], op[15], op[16], op[17]];
        let checks = [
            pre.windows(12).any(|w| {
                w[..2] == [0x79, 1] && w[4..] == [0x69, 0xf1, 0x18, 0x99, 0x6e, 0xf9, 0, 2]
            }),
            contains(post, &[0x79, 8, 0, 0x10]),
            contains(post, &work),
            contains(post, &[0x79, 0x24, 0, 0x20]),
            contains(post, &[0x7a, 3, 0, 0x22, 0, 0]),
            contains(post, &[0x1a, 0x80, 0xf8, 0x24, 1, 0, 0x6f, 0xa0, 0, 4]),
            (1..=0x7ff0).contains(&address),
        ];
        tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_signature",
            offset, address, ?checks, instruction = ?op, before = ?pre, after = ?post);
        if checks.iter().all(|&v| v) {
            if found.is_some() {
                tracing::debug!(target: "freemkv::disc", "Ambiguous Renesas VID signature");
                return None;
            }
            found = Some(address);
        }
    }
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_slot", ?found);
    found
}

fn read_exact(
    scsi: &mut dyn ScsiTransport,
    address: u32,
    buf: &mut [u8],
) -> Result<bool, UnlockError> {
    let cdb = pioneer_optical::cdb::read_memory(address, buf.len() as u32);
    for attempt in 1..=3 {
        buf.fill(0);
        let result = scsi.execute(&cdb, DataDirection::FromDevice, buf, 5_000);
        tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_firmware_read",
            address, requested = buf.len(), attempt, ?cdb, ?result);
        match result {
            Ok(r) if r.status == 0 && r.bytes_transferred == buf.len() => return Ok(true),
            Ok(r) if r.status == 0 && r.bytes_transferred < buf.len() && attempt < 3 => continue,
            Err(e) if is_dead_bus(&e) => return Err(UnlockError::Transport),
            _ => return Ok(false),
        }
    }
    Ok(false)
}

/// Called once at unlock entry, after identifying the OEM-unlocked platform.
fn enable_memory_reads(scsi: &mut dyn ScsiTransport) -> Result<bool, UnlockError> {
    let result = scsi.execute(
        &pioneer_optical::cdb::knock(),
        DataDirection::None,
        &mut [],
        5_000,
    );
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_enable", ?result);
    match result {
        Ok(r) => Ok(r.status == 0 && r.bytes_transferred == 0),
        Err(e) if is_dead_bus(&e) => Err(UnlockError::Transport),
        Err(_) => Ok(false),
    }
}

/// Discover the slot using memory access already enabled by the caller.
fn find_vid_addr(scsi: &mut dyn ScsiTransport) -> Result<Option<u32>, UnlockError> {
    let mut header = [0; 24];
    if !read_exact(scsi, FIRMWARE_BASE, &mut header)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(header[20..24].try_into().unwrap());
    // The advertised image must contain the entire discovery window.
    let minimum_length = WINDOW_START - FIRMWARE_BASE + WINDOW_LEN as u32;
    let valid = header[..8] == *b"PIONEER "
        && (minimum_length..=0x3f0000).contains(&length)
        && length % 256 == 0;
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_header", ?header, length, valid);
    if !valid {
        return Ok(None);
    }
    let mut code = vec![0; WINDOW_LEN];
    for (i, chunk) in code.chunks_mut(CHUNK).enumerate() {
        if !read_exact(scsi, WINDOW_START + (i * CHUNK) as u32, chunk)? {
            return Ok(None);
        }
    }
    Ok(find_slot(&code))
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;
