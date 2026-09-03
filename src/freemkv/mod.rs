//! freemkv — the self-identifying custom-firmware unlocker.
//!
//! Detects a freemkv-firmware drive by issuing the vendor Identity command
//! (sub-function `0x01` of the `0x3C` READ BUFFER "knock" ABI) and checking
//! that the response starts `b"freemkv"` — no bundled profile database is
//! needed, unlike [`crate::ld`], because the firmware self-identifies.
//!
//! The full knock CDB layout, sub-function table, fixed-length reply rules,
//! and toggle-polarity details are documented in `docs/freemkv-abi.md`.

use crate::scsi::{DataDirection, ScsiTransport};
use crate::{UnlockCtx, UnlockError, Unlocked, Unlocker};

/// READ BUFFER (0x3C) opcode every freemkv vendor command hijacks.
const KNOCK_OPCODE: u8 = 0x3C;
/// Knock-mode byte (CDB byte 1) that distinguishes this ABI from an ordinary
/// READ BUFFER mode.
const KNOCK_MODE: u8 = 0x0E;
/// The `C0 DE` knock (CDB bytes 2-3) that marks a freemkv vendor command.
const KNOCK_MAGIC: [u8; 2] = [0xC0, 0xDE];

/// State byte that selects OEM behaviour (clears the feature's RAM flag). The
/// OFF pole of the Region toggle.
const STATE_OFF: u8 = 0x00;
/// State byte that enables the patched behaviour (sets the feature's RAM flag).
/// The ON pole of the Region toggle.
const STATE_ON: u8 = 0x01;

/// Speed sub-function (`0x02`) cap value selecting OEM read-speed behaviour.
#[allow(dead_code)]
const SPEED_CAP_OEM: u8 = 0x00;
/// Speed sub-function (`0x02`) cap value selecting the uncapped / maximum read
/// speed (full riplock lift). `0x01`..=`0xFE` select an intermediate ceiling.
const SPEED_CAP_MAX: u8 = 0xFF;

/// Raw Read (`0x04`) mode: OEM cert enforcement.
#[allow(dead_code)]
const RAW_READ_OFF: u8 = 0x00;
/// Raw Read (`0x04`) mode: "cert is valid" — the drive reports host auth as
/// already succeeded, so a bare `0xAD` fmt `0x80` yields the VID with NO cert
/// and NO AKE. This is the mode this unlocker sets.
const RAW_READ_CERT_VALID: u8 = 0x01;
/// Raw Read (`0x04`) mode: "accept any host cert, revoked or not" — the host
/// still runs the real AKE. Driven by the AACS cert unlocker, not here.
#[allow(dead_code)]
const RAW_READ_ACCEPT_ANY: u8 = 0x02;

/// Vendor sub-functions (CDB byte 4). These numeric values ARE the wire
/// protocol and match `freemkv-firmware`'s `abi.rs::SubFn`.
mod subfn {
    /// Identity — detection (read; ignores state).
    pub(super) const IDENTITY: u8 = 0x01;
    /// Speed / riplock (state byte IS the cap value: `00` = OEM, `01`..=`FF`
    /// ceiling, `FF` = max).
    pub(super) const SPEED: u8 = 0x02;
    /// Region-free (toggle; `01` = RPC region-free).
    pub(super) const REGION: u8 = 0x03;
    /// Raw Read (transport unlock; state selects the cert-gate mode).
    pub(super) const RAW_READ: u8 = 0x04;
    /// DumpAll diagnostic RAM read (address big-endian in `cdb[5..9]`).
    pub(super) const DUMP_ALL: u8 = 0x09;
}

/// The ASCII magic that leads the Identity (subfn 01) reply — the `RESP_MAGIC`
/// of the canonical `abi.rs`. This is the ENTIRE freemkv-detection mechanism
/// (no bundled profile database — the firmware self-identifies).
const IDENTITY_MARKER: &[u8] = b"freemkv";

/// Response buffer size for the Identity probe — comfortably larger than the
/// current `"freemkv 0.6.4"` payload.
const IDENTITY_RESPONSE_LEN: usize = 32;

// Fixed response length for EVERY freemkv knock command; the drive commits this
// many bytes on data-in regardless of subfn. A short/zero allocation desyncs the
// transfer (ABORTED COMMAND, then a wedged FIFO) — see docs/freemkv-abi.md.
const KNOCK_RESP_LEN: usize = 64;

/// Bytes returned by one DumpAll (subfn 0x09) diagnostic read — the firmware
/// always commits a fixed 64-byte window.
const MEMREAD_LEN: usize = 64;

/// Build the 10-byte knock CDB for a freemkv vendor sub-function:
/// `3C 0E C0 DE <subfn> <state> <len_hi> <len_mid> <len_lo> 00`.
fn build_cdb(subfn: u8, state: u8, alloc_len: u32) -> [u8; 10] {
    let len = alloc_len.to_be_bytes();
    [
        KNOCK_OPCODE,
        KNOCK_MODE,
        KNOCK_MAGIC[0],
        KNOCK_MAGIC[1],
        subfn,
        state,
        len[1],
        len[2],
        len[3],
        0x00,
    ]
}

// Build the DumpAll (subfn 0x09) CDB: addr packed big-endian into cdb[5..9] (the
// allocation-length field is reused to carry the address for the fixed 64-byte
// window, matching freemkv-firmware's abi.rs::build_memread_cdb) — bypasses build_cdb.
fn build_memread_cdb(addr: u32) -> [u8; 10] {
    let a = addr.to_be_bytes();
    [
        KNOCK_OPCODE,
        KNOCK_MODE,
        KNOCK_MAGIC[0],
        KNOCK_MAGIC[1],
        subfn::DUMP_ALL,
        a[0],
        a[1],
        a[2],
        a[3],
        0x00,
    ]
}

/// Whether a transport error is a genuine dead bus (a senseless
/// transport-failure status) rather than a drive rejection surfaced through a
/// non-conforming transport (`Err` carrying a sense).
fn is_dead_bus(e: &crate::scsi::ScsiError) -> bool {
    e.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none()
}

// The freemkv custom-firmware unlocker. Detection: subfn-01 Identity, checking
// the response starts "freemkv" — no bundled profile catalog needed, unlike
// crate::ld::LdUnlocker. Stateless: `unlock()` returns what it learned.
#[derive(Default)]
pub struct FreemkvUnlocker;

impl FreemkvUnlocker {
    pub fn new() -> Self {
        FreemkvUnlocker
    }

    // Issue the subfn-01 Identity command: Ok(true) if response starts "freemkv",
    // Ok(false) if rejected/mismatched (not this firmware). A dead bus is
    // Err(Transport) — this is the FIRST command, so a transport fault must abort.
    fn identify(&self, scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
        let cdb = build_cdb(subfn::IDENTITY, STATE_OFF, IDENTITY_RESPONSE_LEN as u32);
        let mut buf = vec![0u8; IDENTITY_RESPONSE_LEN];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) => {
                let matched = r.status == 0
                    && r.bytes_transferred >= IDENTITY_MARKER.len()
                    && buf[..IDENTITY_MARKER.len()] == *IDENTITY_MARKER;
                if !matched {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "freemkv_identity_no_match",
                        "Identity probe did not report freemkv firmware"
                    );
                }
                Ok(matched)
            }
            Err(e) => {
                if is_dead_bus(&e) {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "freemkv_identity_transport_fault",
                        "transport fault on the freemkv Identity probe; aborting"
                    );
                    return Err(UnlockError::Transport);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_identity_rejected",
                    status = e.status,
                    "freemkv Identity probe rejected by the drive; not this firmware"
                );
                Ok(false)
            }
        }
    }

    // Issue a payload-less sub-function carrying an explicit state byte (toggle
    // pole, Speed cap, or Raw Read mode). Ok(()) on GOOD status; NotApplicable
    // if rejected; Transport only on a dead bus.
    fn send_state(
        &self,
        scsi: &mut dyn ScsiTransport,
        subfn: u8,
        state: u8,
    ) -> std::result::Result<(), UnlockError> {
        // Every knock command returns a fixed KNOCK_RESP_LEN data-in payload; a
        // toggle reads and DISCARDS it (only the GOOD status matters), but it MUST
        // set up the data-in phase or the drive aborts + wedges (see KNOCK_RESP_LEN).
        let cdb = build_cdb(subfn, state, KNOCK_RESP_LEN as u32);
        let mut buf = [0u8; KNOCK_RESP_LEN];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) if r.status == 0 => Ok(()),
            Ok(r) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_subfn_rejected",
                    subfn,
                    state,
                    status = r.status,
                    "freemkv sub-function rejected by the drive"
                );
                Err(UnlockError::NotApplicable)
            }
            Err(e) => {
                if is_dead_bus(&e) {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "freemkv_subfn_transport_fault",
                        subfn,
                        "transport fault on a freemkv sub-function; aborting"
                    );
                    return Err(UnlockError::Transport);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_subfn_rejected_as_err",
                    subfn,
                    status = e.status,
                    "freemkv sub-function rejected (via Err)"
                );
                Err(UnlockError::NotApplicable)
            }
        }
    }

    /// Speed / riplock (subfn 0x02). The state byte IS the cap: `0x00` restores
    /// OEM behaviour, `0xFF` lifts riplock to full speed, `0x01`..=`0xFE` select
    /// an intermediate ceiling.
    fn set_speed(
        &self,
        scsi: &mut dyn ScsiTransport,
        cap: u8,
    ) -> std::result::Result<(), UnlockError> {
        self.send_state(scsi, subfn::SPEED, cap)
    }

    /// Region toggle (subfn 0x03). `on` = DVD RPC region-free.
    fn set_region_free(
        &self,
        scsi: &mut dyn ScsiTransport,
        on: bool,
    ) -> std::result::Result<(), UnlockError> {
        let state = if on { STATE_ON } else { STATE_OFF };
        self.send_state(scsi, subfn::REGION, state)
    }

    // Raw Read (subfn 0x04) in RAW_READ_CERT_VALID mode: tells the drive host auth
    // already succeeded so a bare 0xAD fmt 0x80 returns the VID with no cert/AKE.
    // Load-bearing: if rejected, this firmware can't do the one-command unlock.
    fn set_raw_read(&self, scsi: &mut dyn ScsiTransport) -> std::result::Result<(), UnlockError> {
        self.send_state(scsi, subfn::RAW_READ, RAW_READ_CERT_VALID)
    }

    /// DumpAll diagnostic RAM read (subfn 0x09): return the 64-byte window at
    /// `addr`. A host-side diagnostic path only — not used by the unlock flow.
    #[allow(dead_code)]
    fn dump_ram(
        &self,
        scsi: &mut dyn ScsiTransport,
        addr: u32,
    ) -> std::result::Result<[u8; MEMREAD_LEN], UnlockError> {
        let cdb = build_memread_cdb(addr);
        let mut buf = [0u8; MEMREAD_LEN];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) if r.status == 0 && r.bytes_transferred >= MEMREAD_LEN => Ok(buf),
            Ok(_) => Err(UnlockError::NotApplicable),
            Err(e) => {
                if is_dead_bus(&e) {
                    Err(UnlockError::Transport)
                } else {
                    Err(UnlockError::NotApplicable)
                }
            }
        }
    }

    // Full freemkv unlock sequence: 01 Identity (hard gate) → 03 Region → 02 Speed
    // (best-effort) → 04 01 Raw Read → bare 0xAD VID (both load-bearing, no
    // fallback). See docs/freemkv-abi.md for full failure-mode semantics.
    fn full_unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
    ) -> std::result::Result<Unlocked, UnlockError> {
        // 01 — Identity: must be a freemkv drive.
        if !self.identify(scsi)? {
            return Err(UnlockError::NotApplicable);
        }
        // Best-effort feature toggle: only a dead bus aborts.
        let best_effort = |r: std::result::Result<(), UnlockError>,
                           what: &'static str|
         -> std::result::Result<(), UnlockError> {
            match r {
                Ok(()) => Ok(()),
                Err(UnlockError::Transport) => Err(UnlockError::Transport),
                Err(_) => {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "freemkv_feature_unavailable",
                        feature = what,
                        "feature unavailable; continuing"
                    );
                    Ok(())
                }
            }
        };
        // 03 — Region-free (feature).
        best_effort(self.set_region_free(scsi, true), "region")?;
        // 02 — Speed / riplock lift to full (feature).
        best_effort(self.set_speed(scsi, SPEED_CAP_MAX), "speed")?;
        // 04 01 — Raw Read "cert valid" (LOAD-BEARING). No fallback: a firmware
        // that rejects it can't do the one-command unlock.
        match self.set_raw_read(scsi) {
            Ok(()) => {}
            Err(UnlockError::Transport) => return Err(UnlockError::Transport),
            Err(_) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_raw_read_rejected",
                    "Raw Read (04 01) rejected — cannot unlock this drive"
                );
                return Err(UnlockError::VidUnavailable);
            }
        }
        // Bare 0xAD VID read — the shared BEST-EFFORT reader (identical to the
        // LD/Renesas routes). Raw Read already unlocked the drive, so a VID miss
        // must not discard it: only a dead bus propagates (`?`), else `None`.
        let vid = crate::vid::read_aacs_vid(scsi)?;
        tracing::debug!(
            target: "freemkv::disc",
            phase = "freemkv_unlocked",
            has_vid = vid.is_some(),
            "freemkv drive unlocked (Raw Read on)"
        );
        Ok(Unlocked { vid, bus_key: None })
    }
}

impl Unlocker for FreemkvUnlocker {
    fn name(&self) -> &'static str {
        "freemkv"
    }

    /// Recognise the drive by its Identity knock, lift riplock/region
    /// (best-effort), turn on Raw Read (the actual unlock), and read the Volume
    /// ID with a bare `0xAD` (best-effort). `Some` when Raw Read succeeded — the
    /// drive is unlocked whether or not the VID read did; `None` if it isn't a
    /// freemkv drive; `Err(Transport)` on a dead bus. `ctx` is unused: this
    /// unlocker self-identifies rather than matching on drive identity.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        crate::fallthrough(self.full_unlock(scsi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscKind;
    use crate::scsi::mock::{MockTransport, Reply};
    use crate::scsi::{DataDirection, Result, ScsiResult, ScsiTransport};

    fn ctx(id: &crate::DriveId) -> UnlockCtx<'_> {
        UnlockCtx::new(id, DiscKind::Unknown)
    }

    /// Serves a fixed payload with a GOOD status (used for the Identity probe).
    struct FakeTransport {
        payload: Vec<u8>,
    }
    impl ScsiTransport for FakeTransport {
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

    fn freemkv_identity_payload() -> Vec<u8> {
        let mut p = vec![0u8; IDENTITY_RESPONSE_LEN];
        let s = b"freemkv 0.6.4";
        p[..s.len()].copy_from_slice(s);
        p
    }

    /// A well-formed format-0x80 VID structure: 4-byte header, 16-byte VID at
    /// offset 4, 16-byte MAC (zeroed on the bare path — it isn't checked). 36 =
    /// the fixed `0xAD` fmt-0x80 response length (see `crate::vid`).
    fn vid_ds_response(vid: [u8; 16]) -> Vec<u8> {
        let mut p = vec![0u8; 36];
        p[4..20].copy_from_slice(&vid);
        p
    }

    // ── CDB shape ────────────────────────────────────────────────────────

    /// The 10-byte knock CDB layout is a pinned wire-format contract.
    #[test]
    fn build_cdb_encodes_the_knock_shape() {
        let cdb = build_cdb(subfn::IDENTITY, STATE_OFF, IDENTITY_RESPONSE_LEN as u32);
        assert_eq!(cdb.len(), 10);
        assert_eq!(cdb[0], 0x3C);
        assert_eq!(cdb[1], 0x0E);
        assert_eq!(cdb[2], 0xC0);
        assert_eq!(cdb[3], 0xDE);
        assert_eq!(cdb[4], subfn::IDENTITY);
        assert_eq!(cdb[5], 0x00);
        assert_eq!([cdb[6], cdb[7], cdb[8]], [0x00, 0x00, 0x20]); // 32, 24-bit BE
        assert_eq!(cdb[9], 0x00);
    }

    /// The 24-bit allocation length is big-endian across bytes 6..8.
    #[test]
    fn build_cdb_encodes_alloc_len_24bit_big_endian() {
        let cdb = build_cdb(subfn::RAW_READ, RAW_READ_CERT_VALID, 0x01_2345);
        assert_eq!([cdb[6], cdb[7], cdb[8]], [0x01, 0x23, 0x45]);
        assert_eq!(cdb[4], subfn::RAW_READ);
        assert_eq!(cdb[5], 0x01);
    }

    /// The sub-function numbers ARE the wire protocol and match the firmware
    /// `abi.rs::SubFn`: 01 Identity, 02 Speed, 03 Region, 04 Raw Read, 09 DumpAll.
    #[test]
    fn subfn_values_match_firmware_abi() {
        assert_eq!(subfn::IDENTITY, 0x01);
        assert_eq!(subfn::SPEED, 0x02);
        assert_eq!(subfn::REGION, 0x03);
        assert_eq!(subfn::RAW_READ, 0x04);
        assert_eq!(subfn::DUMP_ALL, 0x09);
    }

    /// The Raw Read mode selectors match the firmware: 00 OEM, 01 cert-valid
    /// (this unlocker), 02 accept-any-cert (the AKE path).
    #[test]
    fn raw_read_modes_are_pinned() {
        assert_eq!(RAW_READ_OFF, 0x00);
        assert_eq!(RAW_READ_CERT_VALID, 0x01);
        assert_eq!(RAW_READ_ACCEPT_ANY, 0x02);
    }

    /// Exact CDB bytes for each vendor sub-function that build_cdb serves.
    #[test]
    fn build_cdb_exact_bytes_per_subfn() {
        assert_eq!(
            build_cdb(subfn::IDENTITY, STATE_OFF, IDENTITY_RESPONSE_LEN as u32),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00]
        );
        // Toggles carry the fixed KNOCK_RESP_LEN (64 = 0x40) data-in allocation in
        // bytes 6..8 — the host must read the response or the drive wedges.
        assert_eq!(
            build_cdb(subfn::SPEED, SPEED_CAP_MAX, KNOCK_RESP_LEN as u32),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0xFF, 0x00, 0x00, 0x40, 0x00]
        );
        assert_eq!(
            build_cdb(subfn::REGION, STATE_ON, KNOCK_RESP_LEN as u32),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x03, 0x01, 0x00, 0x00, 0x40, 0x00]
        );
        assert_eq!(
            build_cdb(subfn::RAW_READ, RAW_READ_CERT_VALID, KNOCK_RESP_LEN as u32),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x01, 0x00, 0x00, 0x40, 0x00]
        );
    }

    // ── Detection ────────────────────────────────────────────────────────

    #[test]
    fn identify_true_on_freemkv_marker_and_issues_identity_cdb() {
        let mut t = MockTransport::always(Reply::good(freemkv_identity_payload()));
        assert!(FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
        assert_eq!(
            t.cdbs[0],
            build_cdb(subfn::IDENTITY, STATE_OFF, IDENTITY_RESPONSE_LEN as u32)
        );
    }

    #[test]
    fn identify_false_on_non_matching_payload() {
        let mut t = FakeTransport {
            payload: vec![0u8; IDENTITY_RESPONSE_LEN],
        };
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_false_on_short_response() {
        let mut t = MockTransport::always(Reply::short(freemkv_identity_payload(), 3));
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_false_when_command_rejected() {
        let mut t = MockTransport::always(Reply::illegal_request());
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_false_when_command_rejected_as_err() {
        let mut t = MockTransport::always(Reply::illegal_request_as_err());
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    #[test]
    fn identify_transport_fault_aborts() {
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(
            FreemkvUnlocker::new().identify(&mut t).unwrap_err(),
            UnlockError::Transport
        );
    }

    // ── Feature toggles ──────────────────────────────────────────────────

    #[test]
    fn set_speed_max_issues_the_cap_ff_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set_speed(&mut t, SPEED_CAP_MAX)
            .expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0xFF, 0x00, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn set_speed_intermediate_cap_is_placed_in_state_byte() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new().set_speed(&mut t, 0x42).expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x42, 0x00, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn set_region_free_on_issues_the_state_01_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set_region_free(&mut t, true)
            .expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x03, 0x01, 0x00, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn set_raw_read_issues_the_04_01_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new().set_raw_read(&mut t).expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x01, 0x00, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn toggle_drive_rejection_is_not_applicable() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let err = FreemkvUnlocker::new().set_raw_read(&mut t).unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }

    #[test]
    fn toggle_transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let err = FreemkvUnlocker::new()
            .set_speed(&mut t, SPEED_CAP_MAX)
            .unwrap_err();
        assert_eq!(err, UnlockError::Transport);
    }

    // ── full_unlock / unlock ─────────────────────────────────────────────
    // The bare 0xAD VID read itself is tested in crate::vid; here we cover the
    // full unlock sequence end-to-end, including the best-effort VID handling.

    /// The full unlock runs `01→03→02→04→AD` in order: identity, region, speed,
    /// raw-read, bare VID read. This is the load-bearing sequence test.
    #[test]
    fn full_unlock_issues_identity_region_speed_rawread_then_bare_vid() {
        let vid = [0x7Cu8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // 01 Identity
                Reply::good(vec![]),                     // 03 Region
                Reply::good(vec![]),                     // 02 Speed
                Reply::good(vec![]),                     // 04 01 Raw Read
                Reply::good(vid_ds_response(vid)),       // 0xAD bare VID
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let out = FreemkvUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("no fault")
            .expect("Raw Read on ⇒ unlocked");
        assert_eq!(out.vid, Some(vid));
        // Four vendor knocks then the standard 0xAD read.
        assert_eq!(t.cdbs.len(), 5);
        let vendor_subfns: Vec<u8> = t.cdbs[..4].iter().map(|c| c[4]).collect();
        assert_eq!(vendor_subfns, vec![0x01, 0x03, 0x02, 0x04]);
        assert_eq!(t.cdbs[3][5], RAW_READ_CERT_VALID); // Raw Read state 01
        assert_eq!(t.cdbs[4][0], crate::scsi::SCSI_READ_DISC_STRUCTURE);
    }

    /// A missing region/speed feature does not fail the unlock (best-effort).
    #[test]
    fn full_unlock_tolerates_missing_region_and_speed() {
        let vid = [0x3Cu8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::illegal_request(),                // region unsupported
                Reply::illegal_request(),                // speed unsupported
                Reply::good(vec![]),                     // raw read
                Reply::good(vid_ds_response(vid)),       // bare VID
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let out = FreemkvUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("no fault")
            .expect("unlocked");
        assert_eq!(out.vid, Some(vid));
    }

    /// Raw Read is LOAD-BEARING: if the drive rejects it, this isn't an
    /// unlockable freemkv drive, so `unlock()` declines (`Ok(false)`) and falls
    /// through — never a hard error.
    #[test]
    fn declines_when_raw_read_rejected() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::good(vec![]),                     // region
                Reply::good(vec![]),                     // speed
                Reply::illegal_request(),                // raw read REJECTED
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        assert!(
            FreemkvUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .expect("no fault")
                .is_none()
        );
    }

    /// Best-effort VID: Raw Read succeeded (drive unlocked), but the bare VID
    /// read was rejected — `unlock()` still returns `true`, with `vid() == None`.
    /// This is the fix: the old load-bearing VID aborted the whole unlock here,
    /// dropping a genuinely-unlocked drive to the cert path.
    #[test]
    fn unlocks_without_vid_when_bare_read_fails() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::good(vec![]),                     // region
                Reply::good(vec![]),                     // speed
                Reply::good(vec![]),                     // raw read
                Reply::illegal_request(),                // bare VID: no medium
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let out = FreemkvUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("no fault")
            .expect("unlocked despite no VID");
        assert_eq!(out.vid, None);
    }

    #[test]
    fn declines_non_freemkv_drive() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let id = crate::DriveId::default();
        assert!(
            FreemkvUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .expect("no fault")
                .is_none()
        );
    }

    #[test]
    fn transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let id = crate::DriveId::default();
        assert_eq!(
            FreemkvUnlocker::new()
                .unlock(&mut t, &ctx(&id))
                .unwrap_err(),
            UnlockError::Transport
        );
    }

    // ── DumpAll (subfn 0x09) ─────────────────────────────────────────────

    #[test]
    fn dump_ram_builds_memread_cdb_and_returns_the_window() {
        let mut payload = vec![0xABu8; MEMREAD_LEN];
        payload[0] = 0xEE;
        let mut t = MockTransport::always(Reply::good(payload));
        let got = FreemkvUnlocker::new()
            .dump_ram(&mut t, 0x01F8_1234)
            .expect("dump ok");
        assert_eq!(got[0], 0xEE);
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x09, 0x01, 0xF8, 0x12, 0x34, 0x00]
        );
    }

    #[test]
    fn build_memread_cdb_packs_address_big_endian_at_5_to_9() {
        let cdb = build_memread_cdb(0xDEAD_BEEF);
        assert_eq!(cdb[4], subfn::DUMP_ALL);
        assert_eq!([cdb[5], cdb[6], cdb[7], cdb[8]], [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cdb[9], 0x00);
    }

    #[test]
    fn name_is_freemkv() {
        assert_eq!(FreemkvUnlocker::new().name(), "freemkv");
    }
}
