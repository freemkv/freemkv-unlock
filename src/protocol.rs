//! Shared freemkv CDB wire definitions for flashed and runtime implementations.

// ── Wire constants (mirror of abi.rs) ────────────────────────────────────────

/// Standard SCSI `READ BUFFER` opcode — the command freemkv hijacks (`cdb[0]`).
pub const READ_BUFFER_OPCODE: u8 = 0x3C;
/// The freemkv sub-command mode at `cdb[1]`; OEM rejects modes `>= 0x0E`.
pub const KNOCK_MODE: u8 = 0x0E;
/// Two-byte knock at `cdb[2..4]` ("C0DE") — the *safe* knock carried by every
/// durable verb (Identity/Set/Get/Reset/DumpAll/Save/FlashWrite).
pub const KNOCK: [u8; 2] = [0xC0, 0xDE];
/// Two-byte knock at `cdb[2..4]` — the *debug* knock, distinct from [`KNOCK`]
/// by construction. The only frame the fw honours for the debug-only verbs
/// ([`Verb::Call`], [`Verb::Poke`], [`Verb::Reboot`]).
pub const DEBUG_KNOCK: [u8; 2] = [0xDE, 0xB9];
/// Response-framing magic leading the [`Verb::Identity`] reply (`b"freemkv"`).
pub const RESP_MAGIC: &[u8] = b"freemkv";

/// Oldest firmware `(major, minor)` this mirror arms: 0.9 made wire id `0x06`
/// the consolidated `Encryption` lever. Released 0.8.x (`0x06` = `Ake`, separate
/// `0x07 Bus`) de-busses via `0x06` alone only as a hardware-dependent side
/// effect (not validated), and 0.7.x uses a sub-function grammar: both refused.
pub const MIN_FW_VERSION: (u32, u32) = (0, 9);

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
/// — the non-destructive "revert to last SAVE". Marker-gated in firmware ≥0.8.3: a
/// never-saved drive loads the baked create-time defaults instead.
pub const RESET_TO_FLASH: u8 = 0x00;

/// [`Verb::Reset`] mode (rides in the state slot `cdb[6]`): restore the baked
/// per-create **defaults** (the create-time flags, e.g. UHD/BD on) into the RAM
/// feature-state table. RAM-only — does not touch flash. This is what a never-saved
/// drive boots to. Firmware ≥0.8.3.
pub const RESET_TO_DEFAULTS: u8 = 0x01;

/// [`Verb::Reset`] mode (rides in the state slot `cdb[6]`): TRUE OEM. Forces every
/// feature to [`STATE_PASSTHROUGH`] in RAM **and** (firmware ≥0.8.3) writes the NV
/// config block all-`0xFF` — marker included — so the drive is byte-for-byte like a
/// never-saved/never-configured drive (no trace it was ever set). Because the marker
/// is then `0xFF`, the NEXT boot loads the baked defaults, exactly like a fresh drive.
pub const RESET_TO_OEM: u8 = 0xFF;

/// The verb selector in `cdb[4]`. These numeric values ARE the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verb {
    /// Status/ping — returns `freemkv <version>` (no NUL), then the raw
    /// feature-flag bytes `flag[0x01..=0x06]`, zero-padded to the window.
    Identity = 0x01,
    /// Set one feature (`cdb[5]`) to a state (`cdb[6]`).
    Set = 0x02,
    /// Read one feature's (`cdb[5]`) current state back in the data-in payload.
    Get = 0x03,
    /// Restore the RAM feature-state table. The mode rides in `cdb[6]` (the state
    /// slot): [`RESET_TO_FLASH`] (`0x00`) reloads the saved flash config block back
    /// into RAM (discarding un-saved changes; marker-gated in fw ≥0.8.3),
    /// [`RESET_TO_DEFAULTS`] (`0x01`) restores the baked create-time defaults, and
    /// [`RESET_TO_OEM`] (`0xFF`) forces every feature to [`STATE_PASSTHROUGH`] AND
    /// blanks the NV block (traceless, fw ≥0.8.3). Ignores feature.
    Reset = 0x04,
    /// Diagnostic RAM peek: [`MEMREAD_LEN`] bytes at the 32-bit address in
    /// `cdb[5..9]` (big-endian).
    DumpAll = 0x09,
    /// **TEMPORARY** diagnostic probe: program a single byte to an allowlisted
    /// flash offset via the OEM PROGRAM routine. `CDB[5..9]` = 32-bit flash offset
    /// (big-endian); `CDB[9]` = value byte. The firmware refuses any offset outside
    /// the compile-time allowlist window (`0x1EA000..0x1EB000` — the corpus-proven-
    /// unlocked NV/SAVE block) with a distinct `"REFU"` status word (PROGRAM not
    /// called). Reply: 4-byte offset echo (BE) + 4-byte PROGRAM/REFU status (BE).
    /// Not part of the durable feature grammar; subsumed by [`Verb::Save`].
    FlashWrite = 0x0A,
    /// Persist the whole RAM feature-state table to the flash config block. This is
    /// the ONLY verb that writes the config to flash: [`Verb::Set`] and
    /// [`Verb::Reset`] touch RAM only, so a host's changes stay volatile until a
    /// `Save` commits them (and survive a power cycle only once saved). Ignores
    /// feature/state.
    Save = 0x0B,
    /// **Debug-knock only.** Interactive fw-exploration `blx target` primitive.
    /// `CDB[5..9]` = 32-bit target VA (big-endian); `CDB[9]` = single u8 that
    /// is loaded into r0 as the sole register argument. Refused under the safe
    /// [`KNOCK`]; only executed under [`DEBUG_KNOCK`]. See [`build_call_cdb`].
    Call = 0x0C,
    /// **Debug-knock only.** Poke a single byte to an arbitrary address.
    /// `CDB[5..9]` = 32-bit target address (big-endian, RAM or MMIO);
    /// `CDB[9]` = byte value to store. Refused under the safe [`KNOCK`]; only
    /// executed under [`DEBUG_KNOCK`]. See [`build_poke_cdb`].
    Poke = 0x0D,
    /// **Debug-knock only.** Invokes the firmware's boot function entry with
    /// r0=4 to force the cold path (BSS clear + C-runtime data init + full
    /// post-init), recovering a wedged drive without a power cycle. The target
    /// briefly returns Aborted Command mid-reboot, then comes back ~5s later
    /// with the safe-knock verb chain re-armed to its power-on defaults. The
    /// target VA is baked into the handler at build time, so no CDB arguments
    /// are carried beyond the verb byte. Refused under the safe [`KNOCK`];
    /// only executed under [`DEBUG_KNOCK`]. See [`build_reboot_cdb`].
    Reboot = 0x0F,
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
    /// Unrestricted (BD/UHD) capability widen gate. [`STATE_PASSTHROUGH`]
    /// (`0xFF`) = OEM; [`STATE_OFF`] (`0x00`) = No (currently no-op on
    /// byte-extraction classifiers like BU40N, pending RE); [`STATE_ON`] (`0x01`)
    /// = Yes. fw 0.9.2 folds BD into this gate by name only: its BD-refuse detour
    /// still reads wire id `0x04` (`Bd`, deprecated), which this mirror does not
    /// expose, so on 0.9.2 this lever governs UHD acceptance.
    Unrestricted = 0x03,
    /// Host Revocation List handling on the cert path. [`STATE_PASSTHROUGH`]
    /// (`0xFF`) = OEM enforce; [`STATE_OFF`] (`0x00`) = off (skip the HRL lookup —
    /// revoked certs accepted, non-destructive, the unlock direction); [`STATE_ON`]
    /// (`0x01`) = on (enforce the HRL).
    Hrl = 0x05,
    /// The one master encryption/cert bypass. [`STATE_OFF`] (`0x00`) = every
    /// drive-side encryption/cert requirement gone (cert-AKE relaxed, bus-wrap
    /// off — what used to need a cert now doesn't). [`STATE_PASSTHROUGH`] (`0xFF`)
    /// = OEM behavior (real handshake, bus-encrypted content). [`STATE_ON`]
    /// (`0x01`) = on (require the real handshake). Wire id `0x07` is retired
    /// (was `Bus`, empirically proved inert as a separate datapath lever on
    /// BU40N/MT1959 — the single Encryption lever de-busses on its own).
    Encryption = 0x06,
}

/// Every exposed feature, in wire-id order (the order [`crate::firmware::FirmwareControl::states`]
/// probes). The IDENTITY flag table also carries the unexposed `0x04` slot.
pub const ALL_FEATURES: [Feature; 5] = [
    Feature::Speed,
    Feature::Region,
    Feature::Unrestricted,
    Feature::Hrl,
    Feature::Encryption,
];

/// A Blu-ray region for [`crate::firmware::FirmwareControl::force_region_bd`].
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
/// [`RESET_TO_DEFAULTS`] (`0x01`) restores the baked create-time defaults, and
/// [`RESET_TO_OEM`] (`0xFF`) forces every feature to passthrough (and blanks NV).
/// Floors its data-in at [`MIN_ALLOC_LEN`] for the same HW min-transfer reason as
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

/// Build a 10-byte CDB for [`Verb::Call`]: `blx target(r0)` where `target` is
/// packed big-endian in `cdb[5..9]` and the u8 `r0` register argument rides in
/// `cdb[9]`. Carries the [`DEBUG_KNOCK`] at `cdb[2..4]` — the ONLY frame the
/// fw honours for Call. The handler ORs the thumb bit into the address at
/// runtime. r1..r3 are undefined at callee entry.
pub fn build_call_cdb(target: u32, r0: u8) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&DEBUG_KNOCK);
    cdb[CDB_VERB] = Verb::Call as u8;
    cdb[5] = (target >> 24) as u8;
    cdb[6] = (target >> 16) as u8;
    cdb[7] = (target >> 8) as u8;
    cdb[8] = target as u8;
    cdb[9] = r0;
    cdb
}

/// Build a 10-byte CDB for [`Verb::Poke`]: write a single byte `val` to the
/// arbitrary 32-bit address `target` (RAM or MMIO). Target is packed
/// big-endian in `cdb[5..9]` and `val` rides in `cdb[9]`. Carries the
/// [`DEBUG_KNOCK`] at `cdb[2..4]`. NO bounds check on the address — this is a
/// diagnostic primitive for on-drive state discovery, not a durable verb.
pub fn build_poke_cdb(target: u32, val: u8) -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&DEBUG_KNOCK);
    cdb[CDB_VERB] = Verb::Poke as u8;
    cdb[5] = (target >> 24) as u8;
    cdb[6] = (target >> 16) as u8;
    cdb[7] = (target >> 8) as u8;
    cdb[8] = target as u8;
    cdb[9] = val;
    cdb
}

/// Build a 10-byte CDB for [`Verb::Reboot`]: force the firmware boot function's
/// cold path (soft-reboot the controller). Carries the [`DEBUG_KNOCK`] at
/// `cdb[2..4]`. NO arguments are transmitted on the wire — the target VA is
/// baked into the emitted handler at build time (per-image, resolved from the
/// boot-init signature). Requests a [`MIN_ALLOC_LEN`]-byte data-in like every
/// other durable-shape verb: the drive returns Aborted Command mid-reboot
/// anyway, so callers should tolerate a rejection on this send and re-probe
/// identity after a short delay.
pub fn build_reboot_cdb() -> [u8; CDB_LEN] {
    let mut cdb = [0u8; CDB_LEN];
    cdb[CDB_OPCODE] = READ_BUFFER_OPCODE;
    cdb[CDB_MODE] = KNOCK_MODE;
    cdb[CDB_KNOCK..CDB_KNOCK + 2].copy_from_slice(&DEBUG_KNOCK);
    cdb[CDB_VERB] = Verb::Reboot as u8;
    cdb[CDB_ALLOC_LEN] = (MIN_ALLOC_LEN >> 8) as u8;
    cdb[CDB_ALLOC_LEN + 1] = MIN_ALLOC_LEN as u8;
    cdb
}

/// Whether a device data response leads with [`RESP_MAGIC`].
pub fn verify_response(bytes: &[u8]) -> bool {
    bytes.starts_with(RESP_MAGIC)
}

/// A parsed [`Verb::Identity`] reply. Only present when the reply led with
/// [`RESP_MAGIC`]. The reply is `freemkv <version>` with no terminator, then the
/// raw feature-flag bytes; only the version is parsed — read the live states
/// via [`crate::firmware::FirmwareControl::states`]/[`get`](crate::firmware::FirmwareControl::get).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareIdentity {
    /// The version token after `freemkv ` (printable non-space ASCII), e.g.
    /// `"0.9.2"`; empty if no `freemkv ` token follows the magic. A Speed cap in the
    /// printable range can append one character after the patch number.
    pub version: String,
}

impl FirmwareIdentity {
    /// Parse an IDENTITY data-in payload. `None` unless it leads with
    /// [`RESP_MAGIC`] (i.e. not freemkv firmware).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if !verify_response(bytes) {
            return None;
        }
        let version = match bytes[RESP_MAGIC.len()..].split_first() {
            Some((b' ', rest)) => rest
                .iter()
                .take_while(|b| b.is_ascii_graphic())
                .map(|&b| char::from(b))
                .collect(),
            _ => String::new(),
        };
        Some(FirmwareIdentity { version })
    }

    /// Whether this firmware speaks the grammar this mirror sends (version at
    /// or above [`MIN_FW_VERSION`]). `false` for an unparseable version.
    pub fn is_supported(&self) -> bool {
        self.major_minor().is_some_and(|v| v >= MIN_FW_VERSION)
    }

    fn major_minor(&self) -> Option<(u32, u32)> {
        let mut parts = self.version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?;
        let digits = minor
            .find(|c: char| !c.is_ascii_digit())
            .map_or(minor, |end| &minor[..end]);
        Some((major, digits.parse().ok()?))
    }
}

/// Where the freemkv command implementation lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implementation {
    /// Existing flashed firmware, without the optional capability extension.
    Firmware,
    /// Pioneer runtime implementation.
    PioneerRuntime,
}

/// Supported requests, independent of their current on/off state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    implementation: Implementation,
}
impl Capabilities {
    /// Implementation selected by the validated identity descriptor.
    pub fn implementation(self) -> Implementation {
        self.implementation
    }
    /// Whether this implementation can perform a particular SET request.
    pub fn supports_set(self, feature: Feature, state: u8) -> bool {
        match self.implementation {
            Implementation::Firmware => true,
            Implementation::PioneerRuntime => {
                feature != Feature::Encryption
                    || matches!(state, STATE_OFF | STATE_ON | STATE_PASSTHROUGH)
            }
        }
    }
}

/// Identity plus the implementation's supported requests. Legacy identity parsing
/// remains available through `FirmwareIdentity`; this descriptor must be used
/// before choosing a hardware backend or issuing a recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolIdentity {
    pub identity: FirmwareIdentity,
    pub capabilities: Capabilities,
}

// Extension: magic, version, implementation, SET and GET bitmaps. Version four
// includes standard VID reads and optional SET no-ops; encryption changes policy.
// Unknown nonzero extensions fail closed, independently of legacy state bytes.
const EXTENSION_OFFSET: usize = 32;
const PIONEER_EXTENSION: &[u8; 8] = b"FMCP\x04\x01\x6e\x00";
impl ProtocolIdentity {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != MEMREAD_LEN {
            return None;
        }
        let identity = FirmwareIdentity::parse(bytes)?;
        if !identity.is_supported() {
            return None;
        }
        let tail = bytes.get(EXTENSION_OFFSET..).unwrap_or_default();
        let implementation = if tail.iter().all(|b| *b == 0) {
            Implementation::Firmware
        } else if tail.starts_with(PIONEER_EXTENSION)
            && tail[PIONEER_EXTENSION.len()..].iter().all(|b| *b == 0)
        {
            Implementation::PioneerRuntime
        } else {
            return None;
        };
        Some(Self {
            identity,
            capabilities: Capabilities { implementation },
        })
    }
}

/// Initial runtime identity. Legacy feature state bytes remain passthrough;
/// optional SETs acknowledge without changing their passthrough state.
pub(crate) fn pioneer_identity() -> [u8; MEMREAD_LEN] {
    let mut bytes = [0; MEMREAD_LEN];
    let banner = b"freemkv 0.9.2";
    bytes[..banner.len()].copy_from_slice(banner);
    bytes[banner.len()..banner.len() + 6].fill(STATE_PASSTHROUGH);
    bytes[EXTENSION_OFFSET..EXTENSION_OFFSET + PIONEER_EXTENSION.len()]
        .copy_from_slice(PIONEER_EXTENSION);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_support_is_distinct_from_state() {
        let id = ProtocolIdentity::parse(&pioneer_identity()).unwrap();
        assert_eq!(
            id.capabilities.implementation(),
            Implementation::PioneerRuntime
        );
        for f in ALL_FEATURES {
            for s in [STATE_OFF, STATE_ON, STATE_PASSTHROUGH, 2, 254] {
                assert_eq!(
                    id.capabilities.supports_set(f, s),
                    f != Feature::Encryption
                        || matches!(s, STATE_OFF | STATE_ON | STATE_PASSTHROUGH)
                );
            }
        }
    }
    #[test]
    fn unknown_and_truncated_extensions_never_become_legacy() {
        let bytes = pioneer_identity();
        for n in 0..64 {
            assert!(ProtocolIdentity::parse(&bytes[..n]).is_none());
        }
        for offset in 32..40 {
            let mut bad = bytes;
            bad[offset] ^= 0x80;
            assert!(ProtocolIdentity::parse(&bad).is_none());
        }
        let mut old_runtime = bytes;
        old_runtime[36] = 1;
        assert!(ProtocolIdentity::parse(&old_runtime).is_none());
        let mut legacy = bytes;
        legacy[32..].fill(0);
        assert_eq!(
            ProtocolIdentity::parse(&legacy)
                .unwrap()
                .capabilities
                .implementation(),
            Implementation::Firmware
        );
    }
}
