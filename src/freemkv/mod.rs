//! freemkv — the self-identifying custom-firmware unlocker.
//!
//! Unlike [`crate::ld`] (MediaTek MT1959, matched against a bundled drive
//! profile database), a freemkv-firmware drive needs no catalog: it answers a
//! single vendor Identity probe with an ASCII payload starting `"freemkv"`.
//! That self-identification IS the detection mechanism — there is no profile
//! lookup here and none is needed.
//!
//! # The freemkv vendor ABI (READ BUFFER hijack)
//!
//! Every freemkv command hijacks the standard SCSI `READ BUFFER` (`0x3C`) in
//! "knock mode". The 10-byte CDB is
//! `3C 0E C0 DE <subfn> <state> <len_hi> <len_mid> <len_lo> 00`
//! — opcode `0x3C`, mode byte `0x0E`, the `C0 DE` knock, a one-byte
//! sub-function, a one-byte state, and a 24-bit big-endian allocation length.
//! (This mirrors the canonical `freemkv-firmware` `abi.rs` frame exactly; the
//! host must never diverge from it.)
//!
//! Sub-functions (`cdb[4]`):
//! - `0x01` **Identity** — read; returns `b"freemkv"` + version, ignores state.
//! - `0x02` **Speed** — the state byte IS the speed cap value: `0x00` = OEM,
//!   `0x01`..=`0xFF` a read-speed ceiling, `0xFF` = uncapped / max. This is NOT
//!   a plain on/off toggle — see [`SPEED_CAP_OEM`] / [`SPEED_CAP_MAX`].
//! - `0x03` **Volume ID (VID)** — plaintext Volume ID read; `state 01` = on,
//!   `state 00` = OEM. The firmware handler produces the AACS Volume ID and
//!   returns the RAW 16-byte VID in the data-in response — NO `b"freemkv"`
//!   magic prefix (see the LEAN/RAW rule below). One command returns the VID —
//!   there is no separate standard `READ DISC STRUCTURE`. Needs a disc: with no
//!   medium loaded the firmware answers CHECK CONDITION (no-medium), which the
//!   host reads as "no VID", not a fault.
//!   A firmware DEBUG build may also treat the STATE byte as a retrieval
//!   VARIANT selector (`0x01`..=`0x05`); see [`read_vid_variant`] /
//!   [`probe_vid_variants`], gated behind [`VID_VARIANT_MIN`]..=[`VID_VARIANT_MAX`].
//! - `0x04` **Bus Encryption** — toggle; `state 01` removes the in-transit
//!   (bus) encryption layer so sectors come back in the clear (still AACS
//!   content-encrypted; the host applies title keys).
//! - `0x05` **Region-free** — toggle; `state 01` makes the drive RPC
//!   region-free.
//! - `0x06`..=`0x08` — reserved; not implemented here.
//! - `0x09` **DumpAll** — diagnostic RAM read; 32-bit address big-endian in
//!   `cdb[5..9]`, returns a fixed 64-byte window.
//!
//! # LEAN / RAW replies (FINAL)
//!
//! Only subfn `0x01` **Identity** returns a magic-led reply (`b"freemkv"` +
//! version). EVERY other sub-function is LEAN and RAW: the data-in response is
//! the raw payload with NO `b"freemkv"` prefix. Only the host can issue the
//! `3C 0E C0 DE` knock, so any GOOD-status reply is ours by definition — the
//! magic would be redundant. The Identity magic is therefore the ONE
//! freemkv-detection probe (see [`IDENTITY_MARKER`]); the VID read parses 16
//! raw bytes directly.
//!
//! # Toggle polarity (UNIFORM)
//!
//! Across EVERY toggle the state byte is `0x00` = OEM behaviour, `0x01` =
//! patched / enabled. There is no per-feature inversion — see [`STATE_OFF`] /
//! [`STATE_ON`]. The two exceptions are not toggles at all: Speed (`0x02`)
//! carries a cap value in the state byte, and DumpAll (`0x09`) carries a 32-bit
//! address across `cdb[5..9]`.

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
/// OFF pole of EVERY toggle — polarity is uniform across all sub-functions.
const STATE_OFF: u8 = 0x00;
/// State byte that enables the patched behaviour (sets the feature's RAM flag).
/// The ON pole of EVERY toggle.
const STATE_ON: u8 = 0x01;

/// Speed sub-function (`0x02`) cap value selecting OEM read-speed behaviour.
/// The state byte of subfn 0x02 IS the cap, so this coincides with
/// [`STATE_OFF`] numerically but is a distinct concept (a cap value, not a
/// toggle pole). The default rip flow uses [`SPEED_CAP_MAX`]; this OEM pole is
/// kept as the documented other end of the cap range.
#[allow(dead_code)]
const SPEED_CAP_OEM: u8 = 0x00;
/// Speed sub-function (`0x02`) cap value selecting the uncapped / maximum read
/// speed (full riplock lift). `0x01`..=`0xFE` select an intermediate ceiling.
const SPEED_CAP_MAX: u8 = 0xFF;

/// Vendor sub-functions (CDB byte 4). These numeric values ARE the wire
/// protocol and match `freemkv-firmware`'s `abi.rs`.
mod subfn {
    /// Identity — detection (read; ignores state).
    pub(super) const IDENTITY: u8 = 0x01;
    /// Speed / riplock (state byte IS the cap value: `00` = OEM, `01`..=`FF`
    /// ceiling, `FF` = max).
    pub(super) const SPEED: u8 = 0x02;
    /// Volume ID (self-contained read; `01` = produce+return the AACS VID).
    pub(super) const VID: u8 = 0x03;
    /// Bus Encryption (toggle; `01` = remove the in-transit bus-encryption layer).
    pub(super) const BUS_ENCRYPTION: u8 = 0x04;
    /// Region-free (toggle; `01` = RPC region-free).
    pub(super) const REGION: u8 = 0x05;
    /// Reserved sub-functions — not implemented here, kept for wire-format
    /// completeness so no other feature accidentally reuses these slots.
    #[allow(dead_code)]
    pub(super) const RESERVED_06: u8 = 0x06;
    #[allow(dead_code)]
    pub(super) const RESERVED_07: u8 = 0x07;
    #[allow(dead_code)]
    pub(super) const RESERVED_08: u8 = 0x08;
    /// DumpAll diagnostic RAM read (address big-endian in `cdb[5..9]`).
    pub(super) const DUMP_ALL: u8 = 0x09;
}

/// The ASCII magic that leads the Identity (subfn 01) reply ONLY — the
/// `RESP_MAGIC` of the canonical `abi.rs`. Under the LEAN/RAW rule no other
/// sub-function carries it (a GOOD-status reply to the host's knock is ours by
/// definition), so this doubles as the ENTIRE freemkv-detection mechanism (no
/// bundled profile database — the firmware self-identifies).
const IDENTITY_MARKER: &[u8] = b"freemkv";

/// Response buffer size for the Identity probe — comfortably larger than the
/// current `"freemkv 0.6.0"` payload.
const IDENTITY_RESPONSE_LEN: usize = 32;

/// Allocation length for a toggle command. A toggle only flips a RAM flag and
/// returns GOOD status — there is no response payload to read back — so the
/// data-in transfer is empty.
const TOGGLE_ALLOC_LEN: u32 = 0;

/// The 16-byte AACS Volume ID.
const VID_LEN: usize = 16;
/// Allocation length for the subfn-0x03 VID read. Under the LEAN/RAW rule the
/// reply is exactly the 16 raw VID bytes (no magic prefix), so this is
/// [`VID_LEN`] — the CDB requests exactly 16 bytes (`00 00 10` big-endian).
const VID_ALLOC_LEN: u32 = VID_LEN as u32;

/// First STATE value the subfn-0x03 VID-variant harness probes. A firmware
/// DEBUG build treats the STATE byte as a retrieval-variant selector; this is
/// the low end of that range (the production [`FreemkvUnlocker::read_vid`] uses
/// [`STATE_ON`], which coincides numerically with this first variant).
const VID_VARIANT_MIN: u8 = 1;
/// Last STATE value the subfn-0x03 VID-variant harness probes (inclusive).
const VID_VARIANT_MAX: u8 = 5;

/// Bytes returned by one DumpAll (subfn 0x09) diagnostic read — the firmware
/// always commits a fixed 64-byte window.
const MEMREAD_LEN: usize = 64;

/// One row of the [`FreemkvUnlocker::probe_vid_variants`] sweep: the STATE
/// `variant` that was probed and its per-variant outcome (a plausible VID, or a
/// non-fatal reason there wasn't one).
type VidVariantOutcome = (u8, std::result::Result<[u8; VID_LEN], UnlockError>);

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

/// Build the DumpAll (subfn 0x09) CDB: read [`MEMREAD_LEN`] bytes at the 32-bit
/// `addr`, packed big-endian into `cdb[5..9]`. The fixed 64-byte window means
/// the native allocation-length field is reused to carry the address (matching
/// `freemkv-firmware`'s `abi.rs::build_memread_cdb`), so this does NOT go
/// through [`build_cdb`].
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

/// Whether a 16-byte reply is a plausible Volume ID: exactly [`VID_LEN`] bytes
/// (guaranteed by the array type) and not all-zero. An all-zero buffer is what a
/// CHECK CONDITION or an unmapped debug variant leaves behind, so the
/// [`FreemkvUnlocker::probe_vid_variants`] harness treats it as "no VID" rather
/// than a bogus hit.
fn is_plausible_vid(vid: &[u8; VID_LEN]) -> bool {
    vid.iter().any(|&b| b != 0)
}

/// The freemkv custom-firmware unlocker. `pub(crate)` — clients reach it only
/// through [`crate::all_unlockers`], never by name (the locked-design
/// contract).
///
/// Detects a drive by issuing the subfn-01 Identity command and checking the
/// response begins with `"freemkv"` — there is no bundled profile catalog to
/// match against (unlike [`crate::ld::Mt1959Unlocker`]), because the firmware
/// answers for itself.
pub(crate) struct FreemkvUnlocker;

impl FreemkvUnlocker {
    pub(crate) fn new() -> Self {
        FreemkvUnlocker
    }

    /// Issue the subfn-01 Identity command. `Ok(true)` if the drive
    /// self-identifies as freemkv firmware (response starts `"freemkv"`);
    /// `Ok(false)` if the drive rejects the command or answers with anything
    /// else (not a freemkv drive — fall through). A dead bus is
    /// `Err(UnlockError::Transport)` — this is the FIRST command this
    /// unlocker issues, so a transport fault here must abort the consumer,
    /// not be read as "not a freemkv drive".
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
                // Only a senseless transport-failure status is a dead bus;
                // anything else (a conforming or non-conforming transport
                // reporting a drive rejection) means "not a freemkv drive".
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

    /// Issue a payload-less sub-function carrying an explicit `state` byte (a
    /// toggle pole or the Speed cap value). `Ok(())` on GOOD status;
    /// `Err(NotApplicable)` if the drive rejects it (firmware lacks the feature
    /// — fall through / best-effort); `Err(Transport)` only on a dead bus.
    fn send_state(
        &self,
        scsi: &mut dyn ScsiTransport,
        subfn: u8,
        state: u8,
    ) -> std::result::Result<(), UnlockError> {
        let cdb = build_cdb(subfn, state, TOGGLE_ALLOC_LEN);
        // A toggle carries no response payload — zero-length data-in.
        let mut buf: [u8; 0] = [];
        match scsi.execute(&cdb, DataDirection::None, &mut buf, 5_000) {
            Ok(r) if r.status == 0 => Ok(()),
            Ok(r) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_toggle_rejected",
                    subfn,
                    state,
                    status = r.status,
                    "freemkv toggle rejected by the drive"
                );
                Err(UnlockError::NotApplicable)
            }
            Err(e) => {
                if is_dead_bus(&e) {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "freemkv_toggle_transport_fault",
                        subfn,
                        "transport fault on a freemkv toggle; aborting"
                    );
                    return Err(UnlockError::Transport);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_toggle_rejected_as_err",
                    subfn,
                    status = e.status,
                    "freemkv toggle rejected (via Err)"
                );
                Err(UnlockError::NotApplicable)
            }
        }
    }

    /// Issue a uniform-polarity toggle sub-function (`on` → [`STATE_ON`],
    /// otherwise [`STATE_OFF`]). Thin wrapper over [`Self::send_state`] for the
    /// features whose state byte is a plain on/off pole (VID gate, Bus
    /// Encryption, Region) — NOT Speed, whose state byte is a cap value.
    fn set_toggle(
        &self,
        scsi: &mut dyn ScsiTransport,
        subfn: u8,
        on: bool,
    ) -> std::result::Result<(), UnlockError> {
        let state = if on { STATE_ON } else { STATE_OFF };
        self.send_state(scsi, subfn, state)
    }

    /// Speed / riplock (subfn 0x02). The state byte IS the cap: `cap` = `0x00`
    /// ([`SPEED_CAP_OEM`]) restores OEM behaviour, `0xFF` ([`SPEED_CAP_MAX`])
    /// lifts riplock to full speed, and `0x01`..=`0xFE` select an intermediate
    /// read-speed ceiling.
    fn set_speed(
        &self,
        scsi: &mut dyn ScsiTransport,
        cap: u8,
    ) -> std::result::Result<(), UnlockError> {
        self.send_state(scsi, subfn::SPEED, cap)
    }

    /// Bus Encryption toggle (subfn 0x04). `on` turns off the AACS bus-encryption
    /// layer so sectors come back in the clear (still AACS content-encrypted;
    /// the host applies title keys).
    fn set_bus_encryption(
        &self,
        scsi: &mut dyn ScsiTransport,
        on: bool,
    ) -> std::result::Result<(), UnlockError> {
        self.set_toggle(scsi, subfn::BUS_ENCRYPTION, on)
    }

    /// Region toggle (subfn 0x05). `on` = DVD region-free. Not part of the
    /// default rip flow (region behaviour is a deliberate opt-in), but exposed
    /// for completeness.
    #[allow(dead_code)]
    fn set_region_free(
        &self,
        scsi: &mut dyn ScsiTransport,
        on: bool,
    ) -> std::result::Result<(), UnlockError> {
        self.set_toggle(scsi, subfn::REGION, on)
    }

    /// Read the AACS Volume ID via the self-contained subfn-0x03 command.
    ///
    /// Issues ONE command — `3C 0E C0 DE 03 01 00 00 10 00` (`state 01`, alloc
    /// 16) — and reads the VID directly from that command's data-in reply. Under
    /// the LEAN/RAW rule the reply is the RAW 16-byte VID with NO `b"freemkv"`
    /// prefix (only Identity is magic-led): a GOOD-status reply to the host's
    /// own knock is ours by definition. There is NO separate READ DISC
    /// STRUCTURE.
    ///
    /// `Ok(Some(vid))` on a full 16-byte GOOD reply; `Ok(None)` when the read is
    /// short / drive-rejected (no VID, but not fatal — e.g. no disc / no medium
    /// CHECK CONDITION); `Err(Transport)` only on a dead bus.
    fn read_vid(
        &self,
        scsi: &mut dyn ScsiTransport,
    ) -> std::result::Result<Option<[u8; 16]>, UnlockError> {
        match self.read_vid_variant(scsi, STATE_ON) {
            Ok(vid) => Ok(Some(vid)),
            Err(UnlockError::Transport) => Err(UnlockError::Transport),
            // No medium / short / rejected — a clean "no VID", not a fault.
            Err(_) => Ok(None),
        }
    }

    /// Read the RAW 16-byte VID for one subfn-0x03 STATE `variant`.
    ///
    /// Issues `3C 0E C0 DE 03 <variant> 00 00 10 00` (alloc [`VID_LEN`]) and
    /// returns the 16 raw bytes on GOOD status. This is the primitive both the
    /// production [`Self::read_vid`] (`variant` = [`STATE_ON`]) and the debug
    /// [`Self::probe_vid_variants`] harness build on — a firmware DEBUG build
    /// selects a retrieval variant via this STATE byte.
    ///
    /// `Ok(vid)` on a full 16-byte GOOD reply; `Err(VidUnavailable)` on a
    /// CHECK CONDITION / short / rejected read (no VID / no medium — a clean
    /// non-fatal outcome); `Err(Transport)` only on a dead bus.
    fn read_vid_variant(
        &self,
        scsi: &mut dyn ScsiTransport,
        variant: u8,
    ) -> std::result::Result<[u8; VID_LEN], UnlockError> {
        let cdb = build_cdb(subfn::VID, variant, VID_ALLOC_LEN);
        let mut buf = [0u8; VID_LEN];
        let result = match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) => r,
            Err(e) => {
                if is_dead_bus(&e) {
                    return Err(UnlockError::Transport);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_vid_rejected_as_err",
                    variant,
                    status = e.status,
                    "VID read rejected (via Err); no Volume ID"
                );
                return Err(UnlockError::VidUnavailable);
            }
        };
        // A drive sense arrives as Ok with a non-zero status; without this check
        // a CHECK CONDITION's zero-filled buffer would parse as a VID.
        if result.status != 0 {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "freemkv_vid_check_condition",
                variant,
                status = result.status,
                "VID read returned a drive sense (no medium / no VID)"
            );
            return Err(UnlockError::VidUnavailable);
        }
        if result.bytes_transferred < VID_LEN {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "freemkv_vid_short_response",
                variant,
                bytes_transferred = result.bytes_transferred,
                "VID response too short"
            );
            return Err(UnlockError::VidUnavailable);
        }
        tracing::debug!(
            target: "freemkv::disc",
            phase = "freemkv_vid_ok",
            variant,
            "Volume ID retrieved"
        );
        Ok(buf)
    }

    /// DEBUG harness: probe every subfn-0x03 STATE variant in
    /// [`VID_VARIANT_MIN`]..=[`VID_VARIANT_MAX`] IN ORDER, returning one
    /// `(variant, result)` per attempt so an operator can see which variant a
    /// firmware DEBUG build maps to a plausible VID.
    ///
    /// A dead bus aborts the whole sweep (`Err(Transport)`); every other
    /// per-variant outcome is captured in the returned Vec. A "plausible" VID is
    /// 16 bytes and not all-zero — [`is_plausible_vid`] applies that rule, so a
    /// variant that returns an all-zero buffer surfaces as `Err(VidUnavailable)`
    /// rather than a bogus success.
    #[allow(dead_code)]
    fn probe_vid_variants(
        &self,
        scsi: &mut dyn ScsiTransport,
    ) -> std::result::Result<Vec<VidVariantOutcome>, UnlockError> {
        let mut out = Vec::with_capacity((VID_VARIANT_MAX - VID_VARIANT_MIN + 1) as usize);
        for variant in VID_VARIANT_MIN..=VID_VARIANT_MAX {
            let res = match self.read_vid_variant(scsi, variant) {
                // A dead bus is not a per-variant condition — abort the sweep.
                Err(UnlockError::Transport) => return Err(UnlockError::Transport),
                Ok(vid) if is_plausible_vid(&vid) => Ok(vid),
                Ok(_) => Err(UnlockError::VidUnavailable),
                Err(e) => Err(e),
            };
            out.push((variant, res));
        }
        Ok(out)
    }

    /// DumpAll diagnostic RAM read (subfn 0x09): return the 64-byte window at
    /// `addr`. A host-side diagnostic path only — not used by the unlock flow.
    /// `Err(Transport)` on a dead bus; `Err(NotApplicable)` on a drive
    /// rejection.
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

    /// The full freemkv unlock sequence, in fixed order:
    /// `01 Identity → 05 Region-free → 04 Bus-off → 03 VID → 02 Speed`.
    ///
    /// Identity is the only hard gate (a non-freemkv drive is `NotApplicable`).
    /// The toggles are best-effort: a firmware that lacks one is logged and
    /// skipped (`NotApplicable` from a toggle does not abort), but a dead bus
    /// (`Transport`) always aborts — every command here is a freemkv vendor CDB,
    /// so a transport fault means the drive stopped answering. `drive_unlocked`
    /// reflects whether the bus layer was actually removed (subfn 0x04 accepted).
    /// After this returns, disc data is read normally (`READ(10)`) OUTSIDE the
    /// unlocker — this only flips the switches and returns the VID.
    fn full_unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
    ) -> std::result::Result<Unlocked, UnlockError> {
        // 01 — Identity: must be a freemkv drive.
        if !self.identify(scsi)? {
            return Err(UnlockError::NotApplicable);
        }
        // Run a best-effort toggle, propagating only a dead bus.
        let best_effort = |r: std::result::Result<(), UnlockError>,
                           what: &'static str|
         -> std::result::Result<bool, UnlockError> {
            match r {
                Ok(()) => Ok(true),
                Err(UnlockError::Transport) => Err(UnlockError::Transport),
                Err(_) => {
                    tracing::debug!(
                        target: "freemkv::disc",
                        phase = "freemkv_toggle_unavailable",
                        toggle = what,
                        "toggle unavailable; continuing"
                    );
                    Ok(false)
                }
            }
        };
        // 05 — Region-free.
        best_effort(self.set_region_free(scsi, true), "region")?;
        // 04 — Bus encryption OFF (clear sectors in transit). Tracked so the
        // result honestly reports whether the bus layer came off.
        let bus_off = best_effort(self.set_bus_encryption(scsi, true), "bus")?;
        // 03 — Volume ID (the one value only the drive can give us).
        let vid = self.read_vid(scsi)?;
        // 02 — Speed / riplock lift to full.
        best_effort(self.set_speed(scsi, SPEED_CAP_MAX), "speed")?;
        tracing::debug!(
            target: "freemkv::disc",
            phase = "freemkv_unlocked",
            bus_off,
            "freemkv drive unlocked"
        );
        Ok(Unlocked {
            vid,
            bus_key: None,
            drive_unlocked: bus_off,
        })
    }
}

impl Unlocker for FreemkvUnlocker {
    fn name(&self) -> &'static str {
        "freemkv"
    }

    /// Unlock DRIVE FEATURES on a freemkv drive: recognise it, lift riplock
    /// (subfn 0x02) as a best-effort feature, and read the AACS Volume ID via
    /// the self-contained subfn-0x03 command (one command returns the VID; no
    /// separate READ DISC STRUCTURE). Bus removal is a separate capability
    /// ([`Unlocker::unlock_bus`] → bus encryption), so this does NOT report
    /// `drive_unlocked`.
    fn unlock_features(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        self.full_unlock(scsi)
    }

    /// Same full sequence as [`Unlocker::unlock_features`]: a freemkv drive is
    /// unlocked in one pass (`01→05→04→03→02`), turning every capability on and
    /// returning the Volume ID. Both trait entry points delegate to
    /// [`FreemkvUnlocker::full_unlock`]; `drive_unlocked` reflects whether the
    /// bus layer (subfn 0x04) actually came off.
    fn unlock_bus(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        self.full_unlock(scsi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscKind;
    use crate::scsi::mock::{MockTransport, Reply};
    use crate::scsi::{DataDirection, Result, ScsiResult, ScsiTransport};

    fn ctx(id: &crate::DriveId) -> UnlockCtx<'_> {
        UnlockCtx::new(id, DiscKind::Unknown, &[])
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
        let s = b"freemkv 0.6.0";
        p[..s.len()].copy_from_slice(s);
        p
    }

    /// A well-formed subfn-0x03 VID response under the LEAN/RAW rule: the raw
    /// 16-byte VID with NO `b"freemkv"` prefix.
    fn vid_response(vid: [u8; 16]) -> Vec<u8> {
        vid.to_vec()
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
        let cdb = build_cdb(subfn::VID, STATE_ON, 0x01_2345);
        assert_eq!([cdb[6], cdb[7], cdb[8]], [0x01, 0x23, 0x45]);
        assert_eq!(cdb[4], subfn::VID);
        assert_eq!(cdb[5], 0x01);
    }

    /// Toggle polarity is UNIFORM: 0x00 = OEM, 0x01 = patched, for every plain
    /// on/off subfn (VID gate, Bus Encryption, Region). Speed (a cap value) and
    /// DumpAll (an address) are excluded — they are not toggles.
    #[test]
    fn toggle_polarity_is_uniform_off_00_on_01() {
        assert_eq!(STATE_OFF, 0x00);
        assert_eq!(STATE_ON, 0x01);
        for &sf in &[subfn::VID, subfn::BUS_ENCRYPTION, subfn::REGION] {
            assert_eq!(build_cdb(sf, STATE_OFF, TOGGLE_ALLOC_LEN)[5], 0x00);
            assert_eq!(build_cdb(sf, STATE_ON, TOGGLE_ALLOC_LEN)[5], 0x01);
        }
    }

    /// The sub-function numbers ARE the wire protocol — pin every one, including
    /// the reserved 0x06..=0x08 slots and DumpAll's move to 0x09.
    #[test]
    fn subfn_values_are_pinned() {
        assert_eq!(subfn::IDENTITY, 0x01);
        assert_eq!(subfn::SPEED, 0x02);
        assert_eq!(subfn::VID, 0x03);
        assert_eq!(subfn::BUS_ENCRYPTION, 0x04);
        assert_eq!(subfn::REGION, 0x05);
        assert_eq!(subfn::RESERVED_06, 0x06);
        assert_eq!(subfn::RESERVED_07, 0x07);
        assert_eq!(subfn::RESERVED_08, 0x08);
        assert_eq!(subfn::DUMP_ALL, 0x09);
    }

    /// Exact CDB bytes for each sub-function that build_cdb serves — the pinned
    /// wire format, one assertion per subfn.
    #[test]
    fn build_cdb_exact_bytes_per_subfn() {
        assert_eq!(
            build_cdb(subfn::IDENTITY, STATE_OFF, IDENTITY_RESPONSE_LEN as u32),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00]
        );
        assert_eq!(
            build_cdb(subfn::SPEED, SPEED_CAP_MAX, TOGGLE_ALLOC_LEN),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0xFF, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            build_cdb(subfn::VID, STATE_ON, VID_ALLOC_LEN),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x03, 0x01, 0x00, 0x00, 0x10, 0x00]
        );
        assert_eq!(
            build_cdb(subfn::BUS_ENCRYPTION, STATE_ON, TOGGLE_ALLOC_LEN),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            build_cdb(subfn::REGION, STATE_ON, TOGGLE_ALLOC_LEN),
            [0x3C, 0x0E, 0xC0, 0xDE, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        // DumpAll does NOT go through build_cdb (it packs an address), covered
        // by dump_ram_builds_memread_cdb_and_returns_the_window.
    }

    // ── Detection ────────────────────────────────────────────────────────

    /// A response beginning `"freemkv"` is a hit, and the Identity CDB is
    /// exactly `3C 0E C0 DE 01 00 00 00 20 00`.
    #[test]
    fn identify_true_on_freemkv_marker_and_issues_identity_cdb() {
        let mut t = MockTransport::always(Reply::good(freemkv_identity_payload()));
        assert!(FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
        assert_eq!(
            t.cdbs[0],
            build_cdb(subfn::IDENTITY, STATE_OFF, IDENTITY_RESPONSE_LEN as u32)
        );
    }

    /// Any other payload (e.g. an MT1959 or unrelated drive) is a miss.
    #[test]
    fn identify_false_on_non_matching_payload() {
        let mut t = FakeTransport {
            payload: vec![0u8; IDENTITY_RESPONSE_LEN],
        };
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    /// A short response that can't even carry the marker is a miss, not a panic.
    #[test]
    fn identify_false_on_short_response() {
        let mut t = MockTransport::always(Reply::short(freemkv_identity_payload(), 3));
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    /// A drive rejection (CHECK CONDITION) is "not a freemkv drive", not a fault.
    #[test]
    fn identify_false_when_command_rejected() {
        let mut t = MockTransport::always(Reply::illegal_request());
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    /// The same rejection via a non-conforming transport (`Err` with a sense)
    /// reaches the same answer, not a dead bus.
    #[test]
    fn identify_false_when_command_rejected_as_err() {
        let mut t = MockTransport::always(Reply::illegal_request_as_err());
        assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    }

    /// A genuine transport fault on the FIRST command must abort the consumer.
    #[test]
    fn identify_transport_fault_aborts() {
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(
            FreemkvUnlocker::new().identify(&mut t).unwrap_err(),
            UnlockError::Transport
        );
    }

    // ── Toggles: exact CDB bytes for each sub-function / state ────────────

    /// Speed carries the cap value in the state byte: `SPEED_CAP_MAX` (0xFF)
    /// lifts riplock to full speed.
    #[test]
    fn set_speed_max_issues_the_cap_ff_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set_speed(&mut t, SPEED_CAP_MAX)
            .expect("ok");
        assert_eq!(t.cdbs.len(), 1);
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0xFF, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// `SPEED_CAP_OEM` (0x00) restores OEM read-speed behaviour.
    #[test]
    fn set_speed_oem_issues_the_cap_00_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set_speed(&mut t, SPEED_CAP_OEM)
            .expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// An intermediate cap value is placed verbatim in the state byte.
    #[test]
    fn set_speed_intermediate_cap_is_placed_in_state_byte() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new().set_speed(&mut t, 0x42).expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x42, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn set_bus_encryption_on_issues_the_state_01_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set_bus_encryption(&mut t, true)
            .expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn set_bus_encryption_off_issues_the_state_00_cdb() {
        let mut t = MockTransport::always(Reply::good(vec![]));
        FreemkvUnlocker::new()
            .set_bus_encryption(&mut t, false)
            .expect("ok");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
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
            [0x3C, 0x0E, 0xC0, 0xDE, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// A toggle rejected by the drive is `NotApplicable`, not a fault.
    #[test]
    fn toggle_drive_rejection_is_not_applicable() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let err = FreemkvUnlocker::new()
            .set_bus_encryption(&mut t, true)
            .unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }

    /// A dead bus on a toggle propagates as `Transport`.
    #[test]
    fn toggle_transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let err = FreemkvUnlocker::new()
            .set_speed(&mut t, SPEED_CAP_MAX)
            .unwrap_err();
        assert_eq!(err, UnlockError::Transport);
    }

    // ── read_vid (self-contained subfn 0x03) ─────────────────────────────

    /// read_vid issues ONE command — RAW, alloc 16: `3C 0E C0 DE 03 01 00 00 10
    /// 00` — and reads the 16 raw VID bytes from that reply (NO `b"freemkv"`
    /// prefix). No separate READ DISC STRUCTURE.
    #[test]
    fn read_vid_issues_one_raw_alloc16_subfn_03_command_and_parses_the_vid() {
        let vid = [0x5Au8; 16];
        let mut t = MockTransport::always(Reply::good(vid_response(vid)));
        let got = FreemkvUnlocker::new().read_vid(&mut t).expect("parse ok");
        assert_eq!(got, Some(vid));
        assert_eq!(t.cdbs.len(), 1, "exactly one command");
        assert_eq!(
            t.cdbs[0],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x03, 0x01, 0x00, 0x00, 0x10, 0x00]
        );
    }

    /// The reply is the RAW 16 bytes with NO magic prefix — the whole buffer IS
    /// the VID, byte-for-byte.
    #[test]
    fn read_vid_parses_raw_16_bytes_no_magic() {
        let vid: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let resp = vid_response(vid);
        assert_eq!(resp.len(), VID_LEN, "raw 16 bytes, no prefix");
        assert_eq!(&resp[..], &vid);
        let mut t = MockTransport::always(Reply::good(resp));
        assert_eq!(
            FreemkvUnlocker::new().read_vid(&mut t).expect("ok"),
            Some(vid)
        );
    }

    /// A response too short to carry the 16-byte VID → `Ok(None)` (no VID, not fatal).
    #[test]
    fn read_vid_short_response_is_none() {
        let mut t = MockTransport::always(Reply::short(vid_response([0x11; 16]), 15));
        assert_eq!(FreemkvUnlocker::new().read_vid(&mut t).expect("ok"), None);
    }

    /// A CHECK CONDITION (no medium / no disc) → clean `Ok(None)`, never a VID
    /// parsed from the zero fill.
    #[test]
    fn read_vid_check_condition_is_none() {
        let mut t = MockTransport::always(Reply::illegal_request());
        assert_eq!(FreemkvUnlocker::new().read_vid(&mut t).expect("ok"), None);
    }

    /// A dead bus on the VID read propagates as `Transport`.
    #[test]
    fn read_vid_transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(
            FreemkvUnlocker::new().read_vid(&mut t).unwrap_err(),
            UnlockError::Transport
        );
    }

    // ── VID-variant debug harness (subfn 0x03 STATE selects a variant) ────

    /// The variant range is pinned: 1..=5, the STATE values a firmware DEBUG
    /// build maps to retrieval variants.
    #[test]
    fn vid_variant_range_is_pinned_1_to_5() {
        assert_eq!(VID_VARIANT_MIN, 1);
        assert_eq!(VID_VARIANT_MAX, 5);
    }

    /// Each variant places its number verbatim in the STATE byte (cdb[5]) and
    /// keeps the RAW alloc-16 shape (`00 00 10` at bytes 6..8).
    #[test]
    fn read_vid_variant_places_variant_in_state_byte() {
        for variant in VID_VARIANT_MIN..=VID_VARIANT_MAX {
            let vid = [variant; 16];
            let mut t = MockTransport::always(Reply::good(vid_response(vid)));
            let got = FreemkvUnlocker::new()
                .read_vid_variant(&mut t, variant)
                .expect("variant ok");
            assert_eq!(got, vid);
            assert_eq!(
                t.cdbs[0],
                [
                    0x3C, 0x0E, 0xC0, 0xDE, 0x03, variant, 0x00, 0x00, 0x10, 0x00
                ],
                "variant {variant} CDB",
            );
        }
    }

    /// A no-medium CHECK CONDITION on a variant is the clean "no VID"
    /// `VidUnavailable`, not a fault.
    #[test]
    fn read_vid_variant_check_condition_is_vid_unavailable() {
        let mut t = MockTransport::always(Reply::illegal_request());
        assert_eq!(
            FreemkvUnlocker::new()
                .read_vid_variant(&mut t, VID_VARIANT_MIN)
                .unwrap_err(),
            UnlockError::VidUnavailable
        );
    }

    /// A dead bus on a variant propagates as `Transport`.
    #[test]
    fn read_vid_variant_transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(
            FreemkvUnlocker::new()
                .read_vid_variant(&mut t, VID_VARIANT_MIN)
                .unwrap_err(),
            UnlockError::Transport
        );
    }

    /// probe_vid_variants issues variants 1..=5 IN ORDER — one command per
    /// variant, each carrying its number in the STATE byte.
    #[test]
    fn probe_vid_variants_issues_variants_1_to_5_in_order() {
        let mut t = MockTransport::always(Reply::good(vid_response([0xA5; 16])));
        let results = FreemkvUnlocker::new()
            .probe_vid_variants(&mut t)
            .expect("no dead bus");
        // One result per variant, in order.
        let variants: Vec<u8> = results.iter().map(|(v, _)| *v).collect();
        assert_eq!(variants, vec![1, 2, 3, 4, 5]);
        // One CDB per variant, each with its number in cdb[5], in order.
        assert_eq!(t.cdbs.len(), 5);
        for (i, variant) in (VID_VARIANT_MIN..=VID_VARIANT_MAX).enumerate() {
            assert_eq!(
                t.cdbs[i],
                [
                    0x3C, 0x0E, 0xC0, 0xDE, 0x03, variant, 0x00, 0x00, 0x10, 0x00
                ],
            );
        }
    }

    /// A variant returning a plausible (non-zero) 16-byte VID is `Ok(vid)`; an
    /// all-zero reply is rejected as `VidUnavailable`, not a bogus hit.
    #[test]
    fn probe_vid_variants_flags_plausible_vs_all_zero() {
        // Variant 1 rejected (no VID), variants 2..5 return a plausible VID.
        let plausible = [0x3Cu8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::illegal_request(),
                Reply::good(vid_response(plausible)),
                Reply::good(vid_response([0u8; 16])), // all-zero → not plausible
                Reply::good(vid_response(plausible)),
                Reply::good(vid_response(plausible)),
            ],
            Reply::TransportFault,
        );
        let results = FreemkvUnlocker::new()
            .probe_vid_variants(&mut t)
            .expect("no dead bus");
        assert_eq!(results[0], (1, Err(UnlockError::VidUnavailable)));
        assert_eq!(results[1], (2, Ok(plausible)));
        assert_eq!(results[2], (3, Err(UnlockError::VidUnavailable)));
        assert_eq!(results[3], (4, Ok(plausible)));
        assert_eq!(results[4], (5, Ok(plausible)));
    }

    /// A dead bus aborts the whole sweep with `Transport`, not a per-variant result.
    #[test]
    fn probe_vid_variants_transport_fault_aborts_sweep() {
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(
            FreemkvUnlocker::new()
                .probe_vid_variants(&mut t)
                .unwrap_err(),
            UnlockError::Transport
        );
    }

    /// `is_plausible_vid`: 16 non-zero bytes pass, an all-zero buffer fails.
    #[test]
    fn is_plausible_vid_rejects_all_zero() {
        assert!(is_plausible_vid(&[0x01; 16]));
        assert!(is_plausible_vid(&{
            let mut v = [0u8; 16];
            v[15] = 1;
            v
        }));
        assert!(!is_plausible_vid(&[0u8; 16]));
    }

    // ── unlock_features / unlock_bus ─────────────────────────────────────

    /// The full unlock runs `01→05→04→03→02` in order: identity, region-free,
    /// bus-off, VID, speed. This is the load-bearing sequence test.
    #[test]
    fn full_unlock_issues_01_05_04_03_02_in_order() {
        let vid = [0x7Cu8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // 01 Identity
                Reply::good(vec![]),                     // 05 Region-free
                Reply::good(vec![]),                     // 04 Bus-off
                Reply::good(vid_response(vid)),          // 03 VID
                Reply::good(vec![]),                     // 02 Speed
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let u = FreemkvUnlocker::new()
            .unlock_features(&mut t, &ctx(&id))
            .expect("recognized");
        assert!(u.drive_unlocked, "bus toggle accepted → drive unlocked");
        assert_eq!(u.vid, Some(vid));
        // subfn bytes in issue order: 01 Identity, 05 Region, 04 Bus, 03 VID, 02 Speed.
        let subfns: Vec<u8> = t.cdbs.iter().map(|c| c[4]).collect();
        assert_eq!(subfns, vec![0x01, 0x05, 0x04, 0x03, 0x02]);
        // Speed carries the max cap in its state byte.
        assert_eq!(t.cdbs[4][5], SPEED_CAP_MAX);
    }

    /// `unlock_features` recognises the drive, runs the full sequence, and
    /// reports the VID plus `drive_unlocked` (the bus toggle came off).
    #[test]
    fn unlock_features_recognizes_and_reads_vid() {
        let vid = [0x7Cu8; 16];
        // identity, region, bus, vid, speed.
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()),
                Reply::good(vec![]),
                Reply::good(vec![]),
                Reply::good(vid_response(vid)),
                Reply::good(vec![]),
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let u = FreemkvUnlocker::new()
            .unlock_features(&mut t, &ctx(&id))
            .expect("recognized");
        assert!(u.drive_unlocked, "bus toggle accepted");
        assert_eq!(u.vid, Some(vid));
    }

    /// A missing speed feature does not fail the unlock — VID is read before
    /// speed (best-effort riplock), so a rejected speed toggle is tolerated.
    #[test]
    fn unlock_features_tolerates_missing_speed() {
        let vid = [0x3Cu8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::good(vec![]),                     // region
                Reply::good(vec![]),                     // bus
                Reply::good(vid_response(vid)),          // vid
                Reply::illegal_request(),                // speed toggle unsupported
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let u = FreemkvUnlocker::new()
            .unlock_features(&mut t, &ctx(&id))
            .expect("recognized");
        assert_eq!(u.vid, Some(vid));
    }

    #[test]
    fn unlock_features_not_applicable_on_non_freemkv_drive() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let id = crate::DriveId::default();
        let err = FreemkvUnlocker::new()
            .unlock_features(&mut t, &ctx(&id))
            .unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }

    #[test]
    fn unlock_features_transport_fault_propagates() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let id = crate::DriveId::default();
        let err = FreemkvUnlocker::new()
            .unlock_features(&mut t, &ctx(&id))
            .unwrap_err();
        assert_eq!(err, UnlockError::Transport);
    }

    /// `unlock_bus` runs the same full sequence; the bus toggle (subfn 0x04) is
    /// the third CDB (after identity + region), and `drive_unlocked` is set.
    #[test]
    fn unlock_bus_enables_bus_encryption_and_reports_unlocked() {
        let vid = [0x9Au8; 16];
        // identity, region, bus, vid, speed.
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()),
                Reply::good(vec![]),
                Reply::good(vec![]),
                Reply::good(vid_response(vid)),
                Reply::good(vec![]),
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let u = FreemkvUnlocker::new()
            .unlock_bus(&mut t, &ctx(&id))
            .expect("bus removed");
        assert!(u.drive_unlocked);
        assert_eq!(u.vid, Some(vid));
        // The bus encryption toggle is the third CDB (identity, region, THEN bus).
        assert_eq!(
            t.cdbs[2],
            [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// A drive that rejects the bus toggle does NOT abort the unlock (best-effort):
    /// the sequence continues, the VID is still read, and `drive_unlocked` is
    /// reported false because the bus layer did not come off.
    #[test]
    fn unlock_bus_bus_encryption_rejected_is_best_effort() {
        let vid = [0x55u8; 16];
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()), // identity
                Reply::good(vec![]),                     // region
                Reply::illegal_request(),                // bus toggle unsupported
                Reply::good(vid_response(vid)),          // vid still read
                Reply::good(vec![]),                     // speed
            ],
            Reply::TransportFault,
        );
        let id = crate::DriveId::default();
        let u = FreemkvUnlocker::new()
            .unlock_bus(&mut t, &ctx(&id))
            .expect("continues despite bus rejection");
        assert!(!u.drive_unlocked, "bus toggle rejected → not unlocked");
        assert_eq!(u.vid, Some(vid));
    }

    #[test]
    fn unlock_bus_not_applicable_on_non_freemkv_drive() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let id = crate::DriveId::default();
        let err = FreemkvUnlocker::new()
            .unlock_bus(&mut t, &ctx(&id))
            .unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable);
    }

    // ── DumpAll (subfn 0x09) ─────────────────────────────────────────────

    /// DumpAll packs the 32-bit address big-endian into `cdb[5..9]` (subfn now
    /// at 0x09) and returns the 64-byte window.
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

    /// The DumpAll CDB carries the subfn at cdb[4] and the full 32-bit address
    /// big-endian across cdb[5..9], leaving the trailing control byte zero.
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
