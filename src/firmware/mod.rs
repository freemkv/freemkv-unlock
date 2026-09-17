//! firmware — an ergonomic, typed Rust API for the freemkv-firmware
//! vendor-command grammar.
//!
//! # This file is a MIRROR of the wire contract
//!
//! The single source of truth for the freemkv vendor-command ABI is
//! `freemkv-firmware/crates/freemkv-fw/src/abi.rs`. The firmware tool and this
//! host crate share **no code** — this module is a hand-kept mirror, so the
//! numeric values below (verbs, features, state bytes, CDB field offsets) ARE
//! the contract and MUST NOT drift. [`tests`] pins every pinned value so a drift
//! against `abi.rs` is caught at `cargo test` time.
//!
//! # Grammar: `verb [feature] [state]`
//!
//! A freemkv command hijacks the standard SCSI `READ BUFFER` (`0x3C`) opcode via
//! an OEM-unused mode plus a two-byte knock, then carries a small verb grammar:
//!
//! ```text
//!   cdb[0]    = 0x3C  (READ BUFFER)          ← standard opcode; bridge-safe
//!   cdb[1]    = 0x0E  (KNOCK_MODE)           ← OEM's jump table rejects modes >= 0x0E
//!   cdb[2..4] = 0xC0 0xDE (KNOCK)            ← defence-in-depth signature
//!   cdb[4]    = Verb                         ← IDENTITY / SET / GET / RESET / DUMPALL
//!   cdb[5]    = Feature id                   ← SET/GET only (else 0)
//!   cdb[6]    = State byte                   ← SET only (else 0)
//!   cdb[7..9] = allocation length (16-bit big-endian)  ← data-returning verbs
//!   cdb[9]    = control (0)
//! ```
//!
//! [`Verb::DumpAll`] is the exception: it packs a 32-bit RAM address big-endian
//! into `cdb[5..9]` and always returns a fixed [`MEMREAD_LEN`]-byte window.
//!
//! Every feature defaults to [`STATE_PASSTHROUGH`] (firmware does not touch the
//! subsystem → byte-identical to OEM); [`Verb::Reset`] with [`RESET_TO_OEM`]
//! returns every feature to passthrough, while [`RESET_TO_FLASH`] reloads the last
//! [`Verb::Save`]d config block.

use crate::scsi::{DataDirection, ScsiTransport};

// ── Wire constants (mirror of abi.rs) ────────────────────────────────────────

/// Standard SCSI `READ BUFFER` opcode — the command freemkv hijacks (`cdb[0]`).
pub const READ_BUFFER_OPCODE: u8 = 0x3C;
/// The freemkv sub-command mode at `cdb[1]`; OEM rejects modes `>= 0x0E`.
pub const KNOCK_MODE: u8 = 0x0E;
/// Two-byte knock at `cdb[2..4]` ("C0DE").
pub const KNOCK: [u8; 2] = [0xC0, 0xDE];
/// Response-framing magic leading the [`Verb::Identity`] reply (`b"freemkv"`).
pub const RESP_MAGIC: &[u8] = b"freemkv";

/// Length of a freemkv (READ BUFFER) CDB.
pub const CDB_LEN: usize = 10;
/// Offset of the opcode byte (`cdb[0]`).
pub const CDB_OPCODE: usize = 0;
/// Offset of the mode/knock byte (`cdb[1]`).
pub const CDB_MODE: usize = 1;
/// Offset of the first knock byte (`cdb[2]`, `cdb[3]`).
pub const CDB_KNOCK: usize = 2;
/// Offset of the verb byte (`cdb[4]`).
pub const CDB_VERB: usize = 4;
/// Offset of the feature-id byte (`cdb[5]`) — SET/GET only.
pub const CDB_FEATURE: usize = 5;
/// Offset of the state byte (`cdb[6]`) — SET only.
pub const CDB_STATE: usize = 6;
/// Offset of the 16-bit big-endian allocation length (`cdb[7..9]`).
pub const CDB_ALLOC_LEN: usize = 7;

/// Bytes returned by one [`Verb::DumpAll`] read (fixed 64-byte window).
pub const MEMREAD_LEN: usize = 64;

/// Minimum data-in allocation length any freemkv vendor command may request.
///
/// **Hardware-confirmed (LG BU40N on freemkv firmware):** the drive's `READ
/// BUFFER` hijack ABORTS (Check Condition, sense key Aborted Command) any vendor
/// command whose data-in allocation length is under ~16 bytes (0/1/2 all abort;
/// 16 and 64 both succeed). Every builder floors its allocation at `64` — it
/// matches [`MEMREAD_LEN`] and is safely above the minimum. The verb/feature/
/// state ride in the CDB, so a larger data-in is harmless; a [`Verb::Get`] still
/// reads its state byte from data offset 0. Mirrors firmware ABI `MIN_ALLOC_LEN`.
pub const MIN_ALLOC_LEN: u16 = 64;

/// Feature state: **passthrough** — firmware does not touch this subsystem
/// (OEM behaviour). The boot default of every feature and what [`Verb::Reset`]
/// restores. `0xFF`.
pub const STATE_PASSTHROUGH: u8 = 0xFF;
/// Feature state: explicit **off / disabled** (`0x00`).
pub const STATE_OFF: u8 = 0x00;
/// Feature state: explicit **on / enabled** (`0x01`).
pub const STATE_ON: u8 = 0x01;

/// [`Feature::Speed`] state: speed control OFF — the read-speed cap is lifted and
/// the drive runs uncapped at maximum throughput. This is the [`STATE_OFF`]
/// (`0x00`) leg of Speed: "off" is the *limiter* being off, i.e. maximum speed.
/// `0x01..=0xFE` are explicit caps and `0xFF` is the OEM ramp.
pub const SPEED_MAX: u8 = 0x00;

/// [`Feature::Region`] state: force BD region A (`0x0A`). See [`BdRegion`]. BD
/// regions A/B/C share the low-nibble block with the DVD `0x0N` scheme
/// ([`REGION_DVD_BASE`]) and [`REGION_FREE`] (`0x0F`).
pub const REGION_BD_A: u8 = 0x0A;
/// [`Feature::Region`] state: force BD region B (`0x0B`).
pub const REGION_BD_B: u8 = 0x0B;
/// [`Feature::Region`] state: force BD region C (`0x0C`).
pub const REGION_BD_C: u8 = 0x0C;

/// [`Feature::Region`] state base for "force DVD region N": `REGION_DVD_BASE + N`,
/// so regions 1..=8 are `0x01..=0x08`. `0x00` itself is region-locked (nothing
/// plays).
pub const REGION_DVD_BASE: u8 = 0x00;

/// [`Feature::Region`] state: region-free — any disc plays regardless of its
/// region code. Sits in the region low-nibble block above the DVD (`0x01..=0x08`)
/// and BD (`0x0A..=0x0C`) values.
pub const REGION_FREE: u8 = 0x0F;

/// [`Verb::Reset`] mode (rides in the state slot `cdb[6]`): reload the saved flash
/// config block into the RAM feature-state table, discarding un-saved RAM changes
/// — the non-destructive "revert to last SAVE".
pub const RESET_TO_FLASH: u8 = 0x00;

/// [`Verb::Reset`] mode (rides in the state slot `cdb[6]`): force every feature to
/// [`STATE_PASSTHROUGH`] (OEM behaviour everywhere), regardless of the saved config.
pub const RESET_TO_OEM: u8 = 0xFF;

/// The verb selector in `cdb[4]`. These numeric values ARE the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verb {
    /// Status/ping — returns [`RESP_MAGIC`] + version + the feature-state table.
    Identity = 0x01,
    /// Set one feature (`cdb[5]`) to a state (`cdb[6]`).
    Set = 0x02,
    /// Read one feature's (`cdb[5]`) current state back in the data-in payload.
    Get = 0x03,
    /// Restore the RAM feature-state table. The mode rides in `cdb[6]` (the state
    /// slot): [`RESET_TO_FLASH`] (`0x00`) reloads the saved flash config block back
    /// into RAM (discarding un-saved changes), [`RESET_TO_OEM`] (`0xFF`) forces every
    /// feature to [`STATE_PASSTHROUGH`] (out-of-the-box behaviour). Ignores feature.
    Reset = 0x04,
    /// Diagnostic RAM peek: [`MEMREAD_LEN`] bytes at the 32-bit address in
    /// `cdb[5..9]` (big-endian).
    DumpAll = 0x09,
    /// Persist the whole RAM feature-state table to the flash config block. This is
    /// the ONLY verb that writes the config to flash: [`Verb::Set`] and
    /// [`Verb::Reset`] touch RAM only, so a host's changes stay volatile until a
    /// `Save` commits them (and survive a power cycle only once saved). Ignores
    /// feature/state.
    Save = 0x0B,
}

/// The feature selector in `cdb[5]` for [`Verb::Set`] / [`Verb::Get`]. These
/// numeric values ARE the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Feature {
    /// Read-speed / riplock ceiling. [`STATE_PASSTHROUGH`] (`0xFF`) = OEM ramp;
    /// [`STATE_OFF`] (`0x00`) = speed control off, i.e. the cap is lifted and the
    /// drive runs uncapped at maximum throughput (see [`SPEED_MAX`]); `0x01..=0xFE`
    /// = an explicit speed cap (the byte IS the cap, lower is slower). Note the OFF
    /// direction: "off" means the *limiter* is off, so OFF is the fastest state.
    Speed = 0x01,
    /// Region (RPC) control. [`STATE_PASSTHROUGH`] (`0xFF`) = drive's own region
    /// logic; [`STATE_OFF`] (`0x00`) = region-locked (nothing plays);
    /// [`REGION_DVD_BASE`]` + N` (`0x01..=0x08`) = force DVD region 1..8;
    /// [`REGION_BD_A`]/`_B`/`_C` (`0x0A`/`0x0B`/`0x0C`) = force BD region A/B/C;
    /// [`REGION_FREE`] (`0x0F`) = region-free (any disc plays).
    Region = 0x02,
    /// UHD (AACS 2.0) capability gate. [`STATE_PASSTHROUGH`] (`0xFF`) = OEM (as
    /// shipped); [`STATE_OFF`] (`0x00`) = No (refuse UHD discs); [`STATE_ON`]
    /// (`0x01`) = Yes (accept UHD — the mode gate is neutralized so the drive
    /// engages UHD discs). On the byte-extraction classifier (e.g. BU40N) the No
    /// (OFF) leg currently reads back but behaves == OEM (boot-safe no-op, pending
    /// deeper RE) — do NOT treat OFF as a proven UHD disable there.
    Uhd = 0x03,
    /// Blu-ray (AACS 1.0) capability gate. [`STATE_PASSTHROUGH`] (`0xFF`) = OEM (BD
    /// engaged as shipped); [`STATE_OFF`] (`0x00`) = No (force-refuse BD discs — the
    /// drive raises its own `6F` refusal sense); [`STATE_ON`] (`0x01`) = Yes (accept
    /// BD — an enable direction, not a no-op).
    Bd = 0x04,
    /// Host Revocation List handling on the cert path. [`STATE_PASSTHROUGH`]
    /// (`0xFF`) = OEM enforce; [`STATE_OFF`] (`0x00`) = off (skip the HRL lookup —
    /// revoked certs accepted, non-destructive, the unlock direction); [`STATE_ON`]
    /// (`0x01`) = on (enforce the HRL).
    Hrl = 0x05,
    /// Drive-host AKE. [`STATE_PASSTHROUGH`] (`0xFF`) = OEM real handshake;
    /// [`STATE_OFF`] (`0x00`) = off (null/bypass — the drive acts pre-authenticated,
    /// the unlock direction); [`STATE_ON`] (`0x01`) = on (require the real handshake).
    Ake = 0x06,
    /// In-transit AACS bus encryption. [`STATE_PASSTHROUGH`] (`0xFF`) = OEM (bus
    /// encryption on); [`STATE_OFF`] (`0x00`) = off (de-bussed — content returned
    /// with no bus encryption, the unlock direction); [`STATE_ON`] (`0x01`) = on
    /// (bus encryption).
    Bus = 0x07,
}

/// The set of all features, in the canonical order the IDENTITY feature-state
/// table serialises them (and the order [`FirmwareControl::states`] probes).
pub const ALL_FEATURES: [Feature; 7] = [
    Feature::Speed,
    Feature::Region,
    Feature::Uhd,
    Feature::Bd,
    Feature::Hrl,
    Feature::Ake,
    Feature::Bus,
];

/// A Blu-ray region for [`FirmwareControl::force_region_bd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BdRegion {
    /// Region A (`0x0A`).
    A,
    /// Region B (`0x0B`).
    B,
    /// Region C (`0x0C`).
    C,
}

impl BdRegion {
    /// The `Feature::Region` state byte that forces this BD region.
    pub fn state(self) -> u8 {
        match self {
            BdRegion::A => REGION_BD_A,
            BdRegion::B => REGION_BD_B,
            BdRegion::C => REGION_BD_C,
        }
    }
}

// ── CDB builders (mirror of abi.rs) ──────────────────────────────────────────

/// Build a 10-byte host CDB for a verb over the `3C 0E C0 DE …` frame.
///
/// `feature`/`state` land at `cdb[5]`/`cdb[6]` (0 when the verb ignores them);
/// `alloc_len` is the data-in buffer size, 16-bit big-endian at `cdb[7..9]`.
/// Use [`build_memread_cdb`] for [`Verb::DumpAll`] (different field layout).
pub fn build_cdb(
    verb: Verb,
    feature: Option<Feature>,
    state: Option<u8>,
    alloc_len: u16,
) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&KNOCK);
    cdb[CDB_VERB] = verb as u8;
    cdb[CDB_FEATURE] = feature.map(|f| f as u8).unwrap_or(0);
    cdb[CDB_STATE] = state.unwrap_or(0);
    cdb[CDB_ALLOC_LEN] = (alloc_len >> 8) as u8;
    cdb[CDB_ALLOC_LEN + 1] = alloc_len as u8;
    cdb
}

/// Build a `SET feature = state` CDB. Requests a [`MIN_ALLOC_LEN`]-byte data-in
/// (the drive aborts sub-16-byte transfers — HW-confirmed, see [`MIN_ALLOC_LEN`]);
/// the feature/state ride in the CDB, so the returned payload is ignored.
pub fn build_set_cdb(feature: Feature, state: u8) -> [u8; CDB_LEN] {
    build_cdb(Verb::Set, Some(feature), Some(state), MIN_ALLOC_LEN)
}

/// Build a `GET feature` CDB. Requests a [`MIN_ALLOC_LEN`]-byte data-in (the
/// drive aborts a 1-byte transfer — HW-confirmed, see [`MIN_ALLOC_LEN`]); the
/// current state byte is read back from data offset 0.
pub fn build_get_cdb(feature: Feature) -> [u8; CDB_LEN] {
    build_cdb(Verb::Get, Some(feature), None, MIN_ALLOC_LEN)
}

/// Build a `RESET` CDB. `mode` rides in the state slot (`cdb[6]`):
/// [`RESET_TO_FLASH`] (`0x00`) reloads the saved flash config into RAM,
/// [`RESET_TO_OEM`] (`0xFF`) forces every feature to passthrough. Floors its
/// data-in at [`MIN_ALLOC_LEN`] for the same HW min-transfer reason as
/// [`build_set_cdb`].
pub fn build_reset_cdb(mode: u8) -> [u8; CDB_LEN] {
    build_cdb(Verb::Reset, None, Some(mode), MIN_ALLOC_LEN)
}

/// Build a `SAVE` CDB (persist the RAM feature-state table to the flash config
/// block — the only verb that writes config to flash). Floors its data-in at
/// [`MIN_ALLOC_LEN`] for the same HW min-transfer reason as [`build_reset_cdb`].
pub fn build_save_cdb() -> [u8; CDB_LEN] {
    build_cdb(Verb::Save, None, None, MIN_ALLOC_LEN)
}

/// Build an `IDENTITY` CDB. `alloc_len` sizes the magic+version+state reply.
pub fn build_identity_cdb(alloc_len: u16) -> [u8; CDB_LEN] {
    build_cdb(Verb::Identity, None, None, alloc_len)
}

/// Build a [`Verb::DumpAll`] CDB: read [`MEMREAD_LEN`] bytes at the 32-bit
/// `addr`, packed big-endian into `cdb[5..9]`.
pub fn build_memread_cdb(addr: u32) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&KNOCK);
    cdb[CDB_VERB] = Verb::DumpAll as u8;
    cdb[5] = (addr >> 24) as u8;
    cdb[6] = (addr >> 16) as u8;
    cdb[7] = (addr >> 8) as u8;
    cdb[8] = addr as u8;
    cdb
}

/// Whether a device data response leads with [`RESP_MAGIC`].
pub fn verify_response(bytes: &[u8]) -> bool {
    bytes.starts_with(RESP_MAGIC)
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why a firmware command did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareError {
    /// The drive rejected the command (CHECK CONDITION / vendor refusal). Not a
    /// freemkv drive, or the feature/state is unsupported.
    Rejected,
    /// A verify-after-set (`SET` then `GET`) read back a state that did not
    /// match what was written. Carries `(feature, wanted, got)`.
    VerifyFailed {
        feature: Feature,
        wanted: u8,
        got: u8,
    },
    /// A genuine SCSI transport fault (bus dead). Callers must abort.
    Transport,
}

/// Result of a firmware command.
pub type Result<T> = std::result::Result<T, FirmwareError>;

/// Whether a transport error is a genuine dead bus (a senseless
/// transport-failure status) rather than a drive rejection surfaced through a
/// non-conforming transport (`Err` carrying a sense).
fn is_dead_bus(e: &crate::scsi::ScsiError) -> bool {
    e.status == crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE && e.sense.is_none()
}

// ── Parsed replies ───────────────────────────────────────────────────────────

/// The current state of every feature, indexed by [`Feature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureStates {
    /// [`Feature::Speed`] state.
    pub speed: u8,
    /// [`Feature::Region`] state.
    pub region: u8,
    /// [`Feature::Uhd`] state.
    pub uhd: u8,
    /// [`Feature::Bd`] state.
    pub bd: u8,
    /// [`Feature::Hrl`] state.
    pub hrl: u8,
    /// [`Feature::Ake`] state.
    pub ake: u8,
    /// [`Feature::Bus`] state.
    pub bus: u8,
}

impl FeatureStates {
    /// All features at [`STATE_PASSTHROUGH`] (the OEM / freshly-reset drive).
    pub fn all_passthrough() -> Self {
        FeatureStates {
            speed: STATE_PASSTHROUGH,
            region: STATE_PASSTHROUGH,
            uhd: STATE_PASSTHROUGH,
            bd: STATE_PASSTHROUGH,
            hrl: STATE_PASSTHROUGH,
            ake: STATE_PASSTHROUGH,
            bus: STATE_PASSTHROUGH,
        }
    }

    /// The state byte for one feature.
    pub fn get(&self, feature: Feature) -> u8 {
        match feature {
            Feature::Speed => self.speed,
            Feature::Region => self.region,
            Feature::Uhd => self.uhd,
            Feature::Bd => self.bd,
            Feature::Hrl => self.hrl,
            Feature::Ake => self.ake,
            Feature::Bus => self.bus,
        }
    }

    fn set(&mut self, feature: Feature, state: u8) {
        match feature {
            Feature::Speed => self.speed = state,
            Feature::Region => self.region = state,
            Feature::Uhd => self.uhd = state,
            Feature::Bd => self.bd = state,
            Feature::Hrl => self.hrl = state,
            Feature::Ake => self.ake = state,
            Feature::Bus => self.bus = state,
        }
    }
}

/// A parsed [`Verb::Identity`] reply. Only present when the reply led with
/// [`RESP_MAGIC`]. The firmware answers IDENTITY with a human banner
/// `freemkv <version>` (NUL-padded) — there is NO binary state table in the
/// reply, so this carries only the version string; read the live feature states
/// via [`FirmwareControl::states`]/[`get`](FirmwareControl::get).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareIdentity {
    /// Firmware version string, the banner text after [`RESP_MAGIC`] up to the
    /// first NUL, trimmed (e.g. `"0.7.1"`).
    pub version: String,
}

impl FirmwareIdentity {
    /// Parse an IDENTITY data-in payload. `None` unless it leads with
    /// [`RESP_MAGIC`] (i.e. not freemkv firmware). Layout: `RESP_MAGIC` (7) +
    /// ASCII version banner, NUL-terminated/padded.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if !verify_response(bytes) {
            return None;
        }
        let tail = &bytes[RESP_MAGIC.len()..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        let version = String::from_utf8_lossy(&tail[..end]).trim().to_string();
        Some(FirmwareIdentity { version })
    }
}

/// A named arming recipe (see [`FirmwareControl`] `arm_*` helpers). Lets a
/// caller pick a mode by value (e.g. from a CLI flag or a config field) and
/// apply it uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmRecipe {
    /// [`FirmwareControl::arm_oem_bd`].
    OemBd,
    /// [`FirmwareControl::arm_oem_uhd`].
    OemUhd,
    /// [`FirmwareControl::arm_bypass_bd`].
    BypassBd,
    /// [`FirmwareControl::arm_bypass_uhd`].
    BypassUhd,
    /// [`FirmwareControl::arm_stealth_oem`].
    StealthOem,
}

// ── FirmwareControl ──────────────────────────────────────────────────────────

/// A timeout every firmware command uses (ms). Matches the wider unlocker.
const CMD_TIMEOUT_MS: u32 = 5_000;

/// An ergonomic, typed driver for the freemkv vendor-command grammar over any
/// [`ScsiTransport`]. Borrows the transport for the lifetime of the control.
///
/// ```no_run
/// # use freemkv_unlock::firmware::{FirmwareControl, Feature};
/// # fn demo(scsi: &mut dyn freemkv_unlock::scsi::ScsiTransport) {
/// let mut fw = FirmwareControl::new(scsi);
/// if fw.is_freemkv().unwrap_or(false) {
///     // Real AKE on a UHD disc, revocation ignored, bus de-encrypted:
///     let _ = fw.arm_oem_uhd();
/// }
/// # }
/// ```
pub struct FirmwareControl<'a> {
    scsi: &'a mut dyn ScsiTransport,
}

impl<'a> FirmwareControl<'a> {
    /// Wrap a transport.
    pub fn new(scsi: &'a mut dyn ScsiTransport) -> Self {
        FirmwareControl { scsi }
    }

    /// Issue a CDB with a data-in phase, returning the bytes transferred into a
    /// fixed [`MEMREAD_LEN`]-byte buffer.
    fn exec_in(&mut self, cdb: &[u8; CDB_LEN]) -> Result<([u8; MEMREAD_LEN], usize)> {
        let mut buf = [0u8; MEMREAD_LEN];
        match self
            .scsi
            .execute(cdb, DataDirection::FromDevice, &mut buf, CMD_TIMEOUT_MS)
        {
            Ok(r) if r.status == 0 => Ok((buf, r.bytes_transferred)),
            Ok(_) => Err(FirmwareError::Rejected),
            Err(e) => Err(if is_dead_bus(&e) {
                FirmwareError::Transport
            } else {
                FirmwareError::Rejected
            }),
        }
    }

    /// Send IDENTITY and parse the magic + version banner.
    /// `Ok(None)` if the drive answered but the reply lacked [`RESP_MAGIC`] (not
    /// freemkv firmware); `Err(Transport)` only on a dead bus, `Err(Rejected)`
    /// if the drive refused the command outright (also "not freemkv").
    pub fn identity(&mut self) -> Result<Option<FirmwareIdentity>> {
        let cdb = build_identity_cdb(MEMREAD_LEN as u16);
        match self.exec_in(&cdb) {
            Ok((buf, n)) => Ok(FirmwareIdentity::parse(&buf[..n.min(buf.len())])),
            // A drive that rejects the knock is simply not freemkv firmware.
            Err(FirmwareError::Rejected) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Convenience: is this a freemkv-firmware drive? `false` on a rejection or a
    /// no-magic reply; `Err(Transport)` on a dead bus.
    pub fn is_freemkv(&mut self) -> Result<bool> {
        Ok(self.identity()?.is_some())
    }

    /// Read one feature's current state byte (GET).
    pub fn get(&mut self, feature: Feature) -> Result<u8> {
        let cdb = build_get_cdb(feature);
        let (buf, n) = self.exec_in(&cdb)?;
        if n == 0 {
            return Err(FirmwareError::Rejected);
        }
        Ok(buf[0])
    }

    /// Set one feature to an explicit state byte (SET).
    ///
    /// Issued with a data-in phase (`exec_in`), not `exec_none`: the drive's
    /// READ BUFFER hijack aborts ANY vendor verb that carries no data-in
    /// transfer — the `MIN_ALLOC_LEN` floor in the CDB is only honored when the
    /// host actually reads that many bytes back. The returned bytes are the
    /// echoed state frame; we discard them (GET is the read path).
    pub fn set(&mut self, feature: Feature, state: u8) -> Result<()> {
        let cdb = build_set_cdb(feature, state);
        self.exec_in(&cdb).map(|_| ())
    }

    /// Restore every feature to [`STATE_PASSTHROUGH`] (RESET with
    /// [`RESET_TO_OEM`]). Data-in phase for the same reason as [`set`](Self::set) —
    /// a no-data RESET is aborted.
    pub fn reset(&mut self) -> Result<()> {
        let cdb = build_reset_cdb(RESET_TO_OEM);
        self.exec_in(&cdb).map(|_| ())
    }

    /// Reload the saved flash config block back into the RAM feature-state table
    /// (RESET with [`RESET_TO_FLASH`]), discarding any un-saved RAM changes — the
    /// non-destructive "revert to last SAVE". Data-in phase for the same reason as
    /// [`reset`](Self::reset).
    pub fn reset_to_flash(&mut self) -> Result<()> {
        let cdb = build_reset_cdb(RESET_TO_FLASH);
        self.exec_in(&cdb).map(|_| ())
    }

    /// Persist the whole RAM feature-state table to the flash config block (SAVE)
    /// — the only verb that writes config to flash, so a host's SET changes survive
    /// a power cycle only once saved. Data-in phase for the same reason as
    /// [`reset`](Self::reset).
    pub fn save(&mut self) -> Result<()> {
        let cdb = build_save_cdb();
        self.exec_in(&cdb).map(|_| ())
    }

    /// SET a feature, then GET it back and confirm the state stuck.
    fn set_verify(&mut self, feature: Feature, state: u8) -> Result<()> {
        self.set(feature, state)?;
        let got = self.get(feature)?;
        if got == state {
            Ok(())
        } else {
            Err(FirmwareError::VerifyFailed {
                feature,
                wanted: state,
                got,
            })
        }
    }

    /// Read the current state of every feature via repeated GET.
    pub fn states(&mut self) -> Result<FeatureStates> {
        let mut s = FeatureStates::all_passthrough();
        for feature in ALL_FEATURES {
            s.set(feature, self.get(feature)?);
        }
        Ok(s)
    }

    /// Diagnostic RAM peek: [`MEMREAD_LEN`] bytes at `addr` (DUMPALL).
    pub fn dump(&mut self, addr: u32) -> Result<[u8; MEMREAD_LEN]> {
        let cdb = build_memread_cdb(addr);
        let (buf, n) = self.exec_in(&cdb)?;
        if n < MEMREAD_LEN {
            return Err(FirmwareError::Rejected);
        }
        Ok(buf)
    }

    // ── Typed setters ────────────────────────────────────────────────────────

    /// Force the UHD (AACS 2.0) capability gate on (drive engages UHD discs).
    pub fn enable_uhd(&mut self) -> Result<()> {
        self.set(Feature::Uhd, STATE_ON)
    }
    /// Force the UHD capability gate off.
    pub fn disable_uhd(&mut self) -> Result<()> {
        self.set(Feature::Uhd, STATE_OFF)
    }
    /// Force the Blu-ray (AACS 1.0) capability gate on.
    pub fn enable_bd(&mut self) -> Result<()> {
        self.set(Feature::Bd, STATE_ON)
    }
    /// Force the Blu-ray capability gate off (drive refuses BD discs). Sends the
    /// uniform [`STATE_OFF`] (`0x00`) — an unarmed image boots to [`STATE_PASSTHROUGH`]
    /// (`0xFF`, OEM) via the firmware power-on hook, so `0x00` no longer collides
    /// with the boot value (the retired `0x02` sentinel is gone).
    pub fn disable_bd(&mut self) -> Result<()> {
        self.set(Feature::Bd, STATE_OFF)
    }
    /// Skip the HRL lookup (revoked certs accepted; non-destructive). The unlock
    /// direction is now [`STATE_OFF`] (`0x00` = HRL enforcement off).
    pub fn skip_hrl(&mut self) -> Result<()> {
        self.set(Feature::Hrl, STATE_OFF)
    }
    /// Null the drive-host AKE (drive acts pre-authenticated). The unlock direction
    /// is now [`STATE_OFF`] (`0x00` = handshake off/bypassed).
    pub fn null_ake(&mut self) -> Result<()> {
        self.set(Feature::Ake, STATE_OFF)
    }
    /// Turn AACS in-transit bus encryption off (content returned de-bussed). The
    /// unlock direction is now [`STATE_OFF`] (`0x00` = bus encryption off).
    pub fn bus_off(&mut self) -> Result<()> {
        self.set(Feature::Bus, STATE_OFF)
    }
    /// Region-free (RPC-1). Sends [`REGION_FREE`] (`0x0F`) — under the migrated
    /// region scheme `0x01` now means "force DVD region 1", not region-free.
    pub fn region_free(&mut self) -> Result<()> {
        self.set(Feature::Region, REGION_FREE)
    }
    /// Force a specific Blu-ray region.
    pub fn force_region_bd(&mut self, region: BdRegion) -> Result<()> {
        self.set(Feature::Region, region.state())
    }
    /// Force a specific DVD region (1..=8). Returns [`FirmwareError::Rejected`]
    /// for an out-of-range region rather than sending a malformed state.
    pub fn force_region_dvd(&mut self, region: u8) -> Result<()> {
        if !(1..=8).contains(&region) {
            return Err(FirmwareError::Rejected);
        }
        self.set(Feature::Region, REGION_DVD_BASE + region)
    }
    /// Lift the read-speed / riplock ceiling to maximum.
    pub fn unlock_speed(&mut self) -> Result<()> {
        self.set(Feature::Speed, SPEED_MAX)
    }

    // ── Named recipes (the "modes" table) ─────────────────────────────────────

    /// **arm_oem_bd** — OEM-style Blu-ray (AACS 1.0) rip with a REAL AKE, only
    /// revocation disabled.
    ///
    /// Sets: `Hrl = skip` (revoked host certs accepted; non-destructive).
    /// Leaves everything else at passthrough — the drive still runs the real
    /// host-cert handshake and returns bus-encrypted content, so the host
    /// performs the AKE and de-busses. Rips: BD with an otherwise-revoked cert.
    pub fn arm_oem_bd(&mut self) -> Result<()> {
        self.set_verify(Feature::Hrl, STATE_OFF)
    }

    /// **arm_oem_uhd** — OEM-style UHD (AACS 2.0) rip with a REAL AKE.
    ///
    /// Sets: `Uhd = on` (mode-gate neutralized so the drive engages the UHD
    /// disc), `Hrl = skip` (revocation off), `Bus = off` (content de-bussed).
    /// The host still runs the real AKE. Rips: UHD via the OEM cert path.
    pub fn arm_oem_uhd(&mut self) -> Result<()> {
        self.set_verify(Feature::Uhd, STATE_ON)?;
        self.set_verify(Feature::Hrl, STATE_OFF)?;
        self.set_verify(Feature::Bus, STATE_OFF)
    }

    /// **arm_bypass_bd** — full-bypass Blu-ray rip (NO host cert needed).
    ///
    /// Sets: `Ake = null` (drive acts pre-authenticated, so a bare VID read
    /// returns the volume ID with no cert and no AKE). Rips: BD with no cert.
    pub fn arm_bypass_bd(&mut self) -> Result<()> {
        self.set_verify(Feature::Ake, STATE_OFF)
    }

    /// **arm_bypass_uhd** — full-bypass UHD rip (NO host cert needed).
    ///
    /// Sets: `Uhd = on` (engage the UHD disc), `Ake = null` (skip the
    /// handshake), `Bus = off` (content de-bussed). Rips: UHD with no cert.
    pub fn arm_bypass_uhd(&mut self) -> Result<()> {
        self.set_verify(Feature::Uhd, STATE_ON)?;
        self.set_verify(Feature::Ake, STATE_OFF)?;
        self.set_verify(Feature::Bus, STATE_OFF)
    }

    /// **arm_stealth_oem** — return the drive to byte-for-byte OEM behaviour.
    ///
    /// Issues RESET (every feature → passthrough) and verifies each feature read
    /// back as [`STATE_PASSTHROUGH`]. Rips: nothing — this DISARMS the drive.
    pub fn arm_stealth_oem(&mut self) -> Result<()> {
        self.reset()?;
        for feature in ALL_FEATURES {
            let got = self.get(feature)?;
            if got != STATE_PASSTHROUGH {
                return Err(FirmwareError::VerifyFailed {
                    feature,
                    wanted: STATE_PASSTHROUGH,
                    got,
                });
            }
        }
        Ok(())
    }

    /// Apply a named [`ArmRecipe`].
    pub fn arm(&mut self, recipe: ArmRecipe) -> Result<()> {
        match recipe {
            ArmRecipe::OemBd => self.arm_oem_bd(),
            ArmRecipe::OemUhd => self.arm_oem_uhd(),
            ArmRecipe::BypassBd => self.arm_bypass_bd(),
            ArmRecipe::BypassUhd => self.arm_bypass_uhd(),
            ArmRecipe::StealthOem => self.arm_stealth_oem(),
        }
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
