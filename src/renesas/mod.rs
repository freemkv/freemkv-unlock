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
        let vid = match find_vid_addr(scsi)? {
            Some(address) => get_vid(scsi, address)?,
            None => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscKind;
    use crate::scsi::{DataDirection, Result, ScsiError, ScsiResult, ScsiTransport};

    #[test]
    fn memory_vid_rejects_invalid_responses_and_propagates_dead_bus() {
        use crate::scsi::mock::{MockTransport, Reply};
        for reply in [
            Reply::zero_transfer(16),
            Reply::short(vec![0x25; 16], 15),
            Reply::good(vec![0; 16]),
            Reply::good(vec![0xff; 16]),
            Reply::illegal_request(),
            Reply::illegal_request_as_err(),
        ] {
            let mut t = MockTransport::always(reply.clone());
            assert_eq!(get_vid(&mut t, 0x2a10).unwrap(), None);
        }
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(get_vid(&mut t, 0x2a10).unwrap_err(), UnlockError::Transport);
    }

    #[test]
    fn memory_vid_rejects_failed_status_with_payload_and_impossible_length() {
        struct Response {
            status: u8,
            transferred: usize,
        }
        impl ScsiTransport for Response {
            fn execute(
                &mut self,
                _: &[u8],
                dir: DataDirection,
                data: &mut [u8],
                timeout: u32,
            ) -> Result<ScsiResult> {
                assert_eq!(dir, DataDirection::FromDevice);
                assert_eq!(data.len(), 16);
                assert_eq!(timeout, 5_000);
                data.fill(0x25);
                Ok(ScsiResult {
                    status: self.status,
                    bytes_transferred: self.transferred,
                    sense: [0; 32],
                })
            }
        }
        for (status, transferred) in [(2, 16), (0, 17), (0, usize::MAX)] {
            assert_eq!(
                get_vid(
                    &mut Response {
                        status,
                        transferred
                    },
                    0x2a10
                )
                .unwrap(),
                None
            );
        }
    }

    #[test]
    fn cancellation_after_identity_aborts_before_enable() {
        use crate::scsi::mock::{MockTransport, Reply, StopFake};
        let mut t = StopFake::new(MockTransport::always(Reply::good(renesas_payload())));
        t.cancel_after = Some(|cdb| cdb == pioneer_optical::cdb::vendor_identity());
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        assert_eq!(
            Renesas::new().unlock(&mut t, &ctx).unwrap_err(),
            UnlockError::Transport
        );
        assert_eq!(t.inner.calls(), 1);
    }

    #[test]
    fn vendor_cdbs_are_the_wire_bytes() {
        assert_eq!(
            pioneer_optical::cdb::vendor_identity(),
            [0x3C, 0x02, 0xF1, 0, 0, 0, 0, 0, 0x30, 0]
        );
        assert_eq!(
            pioneer_optical::cdb::read_memory(0x50_0000, 0x10),
            [0x3C, 0x02, 0xB0, 0x50, 0, 0, 0, 0, 0x10, 0]
        );
        assert_eq!(
            pioneer_optical::cdb::knock(),
            [0x3B, 0x02, 0x41, 0xA5, 0xAA, 0xAA, 0, 0, 0, 0]
        );
        assert_eq!(RB_F1_LEN, 48);
    }

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
    // what distinguishes this from a dead bus.
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
    fn opened_renesas_reports_unlocked_and_reads_vid() {
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        // Recognized, but the served bytes do not contain a supported firmware header.
        let out = Renesas::new()
            .unlock(&mut t, &ctx)
            .expect("no fault")
            .expect("renesas → unlocked");
        assert!(
            out.vid.is_none(),
            "unknown firmware must not fabricate a VID"
        );
        assert_eq!(out.bus_key, None, "raw-read route needs no bus key");
    }

    /// A drive REJECTION (ILLEGAL REQUEST, with a sense) is "not a Renesas
    /// drive" → `Ok(false)`, fall through to the next unlocker.
    #[test]
    fn declines_non_renesas() {
        let mut t = RejectingTransport;
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        assert!(
            Renesas::new()
                .unlock(&mut t, &ctx)
                .expect("non-renesas declines")
                .is_none()
        );
    }

    // Same rejection via a CONFORMING transport (`Ok` + CHECK CONDITION);
    // must reach the same answer.
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
        let ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        assert_eq!(
            Renesas::new().unlock(&mut t, &ctx).unwrap_err(),
            UnlockError::Transport
        );
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

fn find_vid_addr(scsi: &mut dyn ScsiTransport) -> Result<Option<u32>, UnlockError> {
    let result = scsi.execute(
        &pioneer_optical::cdb::knock(),
        DataDirection::None,
        &mut [],
        5_000,
    );
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_enable", ?result);
    match result {
        Ok(r) if r.status == 0 && r.bytes_transferred == 0 => {}
        Err(e) if is_dead_bus(&e) => return Err(UnlockError::Transport),
        _ => return Ok(None),
    }
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
mod discovery_tests {
    use super::*;
    use crate::scsi::mock::{MockTransport, Reply};

    fn fixture(address: u16) -> Vec<u8> {
        let mut code = vec![0; WINDOW_LEN];
        let mut block = vec![0x79, 1, 1, 0x3a, 0x69, 0xf1, 0x18, 0x99, 0x6e, 0xf9, 0, 2];
        block.extend([0x19, 0x33, 0x0d, 0x31, 0x17, 0x71, 0x6e, 0x1c]);
        block.extend(address.to_be_bytes());
        block.extend([
            0x78, 0x10, 0x6a, 0xac, 0, 0xa0, 0x27, 0xf4, 0x0b, 0x53, 0x79, 0x23, 0, 0x10, 0x45,
            0xe8,
        ]);
        block.extend([
            0x79, 8, 0, 0x10, 0x7a, 0, 0, 0xa0, 0x27, 0xf4, 0x79, 0x24, 0, 0x20, 0x7a, 3, 0, 0x22,
            0, 0, 0x1a, 0x80, 0xf8, 0x24, 1, 0, 0x6f, 0xa0, 0, 4,
        ]);
        // Deliberately straddles a transport chunk boundary.
        code[CHUNK - 20..CHUNK - 20 + block.len()].copy_from_slice(&block);
        code
    }

    #[test]
    fn validates_context_and_requires_unique_positive_slot() {
        for address in [0x2832, 0x2a10, 0x2aa2] {
            assert_eq!(find_slot(&fixture(address)), Some(address as u32));
        }
        for address in [0, 0x8000, 0xfffe] {
            assert_eq!(find_slot(&fixture(address)), None);
        }
        for relative in [10, 38, 42, 48, 52, 58] {
            let mut code = fixture(0x2a10);
            code[CHUNK - 20 + relative] ^= 1;
            assert_eq!(find_slot(&code), None, "context mutation {relative}");
        }
        let mut code = fixture(0x2a10);
        code.copy_within(CHUNK - 20..CHUNK + 100, 1000);
        assert_eq!(find_slot(&code), None);
        assert_eq!(find_slot(&[]), None);
    }

    fn script(vid: [u8; 16]) -> Vec<Reply> {
        let mut header = vec![0; 24];
        header[..8].copy_from_slice(b"PIONEER ");
        header[20..].copy_from_slice(&0x1c7500u32.to_be_bytes());
        let mut replies = vec![Reply::good(vec![]), Reply::good(header)];
        replies.extend(
            fixture(0x2aa2)
                .chunks(CHUNK)
                .map(|c| Reply::good(c.to_vec())),
        );
        replies.push(Reply::good(vid.to_vec()));
        replies
    }

    #[test]
    fn unlock_discovers_address_then_get_vid_only_reads_ram() {
        let vid = [0x25; 16];
        let mut identity = vec![0x20; 48];
        identity[16..19].copy_from_slice(b"SAT");
        let mut replies = vec![Reply::good(identity)];
        replies.extend(script(vid));
        let mut t = MockTransport::scripted(replies, Reply::TransportFault);
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
        let unlocker = Renesas::new();
        assert_eq!(
            unlocker.unlock(&mut t, &ctx).unwrap().unwrap().vid,
            Some(vid)
        );
        assert_eq!(t.cdbs.len(), 8);
        assert_eq!(t.cdbs[1], pioneer_optical::cdb::knock());
        for i in 0..4 {
            assert_eq!(
                t.cdbs[i + 3],
                pioneer_optical::cdb::read_memory(WINDOW_START + (i * CHUNK) as u32, CHUNK as u32)
            );
        }
        assert_eq!(t.cdbs[7], pioneer_optical::cdb::read_memory(0x2aa2, 16));
        let mut t = MockTransport::always(Reply::good(vid.to_vec()));
        assert_eq!(get_vid(&mut t, 0x2aa2).unwrap(), Some(vid));
        assert_eq!(t.cdbs, vec![pioneer_optical::cdb::read_memory(0x2aa2, 16)]);
    }

    #[test]
    fn discovery_failures_stop_and_short_reads_retry_boundedly() {
        for step in 0..6 {
            let mut replies = script([0x25; 16]);
            replies[step] = Reply::TransportFault;
            let mut t = MockTransport::scripted(replies, Reply::TransportFault);
            assert_eq!(find_vid_addr(&mut t).unwrap_err(), UnlockError::Transport);
            assert_eq!(t.calls(), step + 1);
            let mut replies = script([0x25; 16]);
            replies[step] = Reply::illegal_request();
            assert_eq!(
                find_vid_addr(&mut MockTransport::scripted(replies, Reply::TransportFault))
                    .unwrap(),
                None
            );
        }
        let mut replies = script([0x25; 16]);
        replies.insert(2, Reply::short(vec![0; CHUNK], 1));
        let mut t = MockTransport::scripted(replies, Reply::TransportFault);
        assert!(find_vid_addr(&mut t).unwrap().is_some());
        assert_eq!(t.calls(), 7);
        let mut replies = script([0x25; 16]);
        replies.splice(
            2..3,
            [
                Reply::zero_transfer(CHUNK),
                Reply::zero_transfer(CHUNK),
                Reply::zero_transfer(CHUNK),
            ],
        );
        let mut t = MockTransport::scripted(replies, Reply::TransportFault);
        assert_eq!(find_vid_addr(&mut t).unwrap(), None);
        assert_eq!(t.calls(), 5);
    }
    fn with_identity(replies: Vec<Reply>) -> MockTransport {
        let mut identity = vec![0; RB_F1_LEN];
        identity[16..19].copy_from_slice(b"SAT");
        let mut all = vec![Reply::good(identity)];
        all.extend(replies);
        MockTransport::scripted(all, Reply::TransportFault)
    }

    #[test]
    fn oem_unlock_survives_rejection_at_every_optional_step() {
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
        for step in 0..7 {
            for refusal in [Reply::illegal_request(), Reply::illegal_request_as_err()] {
                let mut replies = script([0x25; 16]);
                replies[step] = refusal;
                let mut t = with_identity(replies);
                let out = Renesas::new()
                    .unlock(&mut t, &ctx)
                    .unwrap()
                    .expect("OEM unlocked");
                assert_eq!(out.vid, None);
                assert_eq!(out.bus_key, None);
                assert_eq!(t.calls(), step + 2, "no commands after rejection at {step}");
            }
        }
        for vid in [[0; 16], [0xff; 16]] {
            let out = Renesas::new()
                .unlock(&mut with_identity(script(vid)), &ctx)
                .unwrap()
                .unwrap();
            assert_eq!(out.vid, None);
        }
    }

    #[test]
    fn transport_faults_abort_full_unlock_at_every_optional_step() {
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
        for step in 0..7 {
            let mut replies = script([0x25; 16]);
            replies[step] = Reply::TransportFault;
            let mut t = with_identity(replies);
            assert_eq!(
                Renesas::new().unlock(&mut t, &ctx).unwrap_err(),
                UnlockError::Transport
            );
            assert_eq!(t.calls(), step + 2);
        }
    }

    #[test]
    fn cancellation_during_firmware_read_prevents_further_commands() {
        use crate::scsi::mock::StopFake;
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
        let mut t = StopFake::new(with_identity(script([0x25; 16])));
        t.cancel_after =
            Some(|cdb| cdb == pioneer_optical::cdb::read_memory(WINDOW_START, CHUNK as u32));
        assert_eq!(
            Renesas::new().unlock(&mut t, &ctx).unwrap_err(),
            UnlockError::Transport
        );
        assert_eq!(t.inner.calls(), 4);
    }

    #[test]
    fn invalid_headers_never_read_firmware_and_preserve_oem_unlock() {
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
        for length in [0, 0x169f00, 0x16a001, 0x3f0100, u32::MAX] {
            let mut replies = script([0x25; 16]);
            let mut header = vec![0; 24];
            header[..8].copy_from_slice(b"PIONEER ");
            header[20..].copy_from_slice(&length.to_be_bytes());
            replies[1] = Reply::good(header);
            let mut t = with_identity(replies);
            assert!(
                Renesas::new()
                    .unlock(&mut t, &ctx)
                    .unwrap()
                    .unwrap()
                    .vid
                    .is_none()
            );
            assert_eq!(t.calls(), 3);
        }
    }

    #[test]
    fn missing_or_ambiguous_signature_preserves_oem_unlock_without_ram_read() {
        let id = crate::DriveId::default();
        let ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
        let mut ambiguous = fixture(0x2aa2);
        ambiguous.copy_within(CHUNK - 20..CHUNK + 100, 1000);
        for code in [vec![0; WINDOW_LEN], ambiguous] {
            let mut replies = script([0x25; 16]);
            for (i, chunk) in code.chunks(CHUNK).enumerate() {
                replies[i + 2] = Reply::good(chunk.to_vec());
            }
            let mut t = with_identity(replies);
            assert!(
                Renesas::new()
                    .unlock(&mut t, &ctx)
                    .unwrap()
                    .unwrap()
                    .vid
                    .is_none()
            );
            assert_eq!(t.calls(), 7);
        }
    }

    #[test]
    fn identity_rejects_overreported_transfer() {
        let mut identity = vec![0; RB_F1_LEN];
        identity[16..19].copy_from_slice(b"SAT");
        let mut t = MockTransport::always(Reply::short(identity, RB_F1_LEN + 1));
        assert!(!is_renesas(&mut t).unwrap());
    }
}
