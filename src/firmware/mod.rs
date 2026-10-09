//! Typed mirror of the freemkv firmware vendor-command ABI.
//!
//! Numeric values must match `freemkv-firmware/crates/freemkv-fw/src/abi.rs`.
//! Tests pin the verbs, features, state bytes and CDB offsets.
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
//! DumpAll instead encodes a 32-bit address in `cdb[5..9]` and returns MEMREAD_LEN bytes.
//! Features default to passthrough. Reset selects OEM, built-in defaults or saved flash state.

use crate::scsi::{DataDirection, ScsiTransport, is_dead_bus};

pub use crate::protocol::*;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why a firmware command did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareError {
    /// The drive rejected the command (CHECK CONDITION / vendor refusal). Not a
    /// freemkv drive, or the feature/state is unsupported.
    Rejected,
    /// IDENTITY did not report freemkv firmware at or above [`MIN_FW_VERSION`];
    /// a recipe was refused before any SET/RESET was sent.
    UnsupportedFirmware,
    /// A caller argument was out of range; nothing was sent to the drive.
    InvalidArgument,
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

// ── Parsed replies ───────────────────────────────────────────────────────────

/// The current state of every feature, indexed by [`Feature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureStates {
    /// [`Feature::Speed`] state.
    pub speed: u8,
    /// [`Feature::Region`] state.
    pub region: u8,
    /// [`Feature::Unrestricted`] state.
    pub unrestricted: u8,
    /// [`Feature::Hrl`] state.
    pub hrl: u8,
    /// [`Feature::Encryption`] state (the consolidated cert/bus bypass).
    pub encryption: u8,
}

impl FeatureStates {
    /// All features at [`STATE_PASSTHROUGH`] (the OEM / freshly-reset drive).
    pub fn all_passthrough() -> Self {
        FeatureStates {
            speed: STATE_PASSTHROUGH,
            region: STATE_PASSTHROUGH,
            unrestricted: STATE_PASSTHROUGH,
            hrl: STATE_PASSTHROUGH,
            encryption: STATE_PASSTHROUGH,
        }
    }

    /// The state byte for one feature.
    pub fn get(&self, feature: Feature) -> u8 {
        match feature {
            Feature::Speed => self.speed,
            Feature::Region => self.region,
            Feature::Unrestricted => self.unrestricted,
            Feature::Hrl => self.hrl,
            Feature::Encryption => self.encryption,
        }
    }

    fn set(&mut self, feature: Feature, state: u8) {
        match feature {
            Feature::Speed => self.speed = state,
            Feature::Region => self.region = state,
            Feature::Unrestricted => self.unrestricted = state,
            Feature::Hrl => self.hrl = state,
            Feature::Encryption => self.encryption = state,
        }
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
    // NOTE: Feature::Unrestricted unifies former BD+UHD gates (fw 0.9.2); recipe
    // names above name the disc TYPE being ripped, not the retired per-format
    // feature — see `arm_oem_uhd`/`arm_bypass_uhd`.
    /// [`FirmwareControl::arm_stealth_oem`].
    StealthOem,
}

impl ArmRecipe {
    /// Whether the recipe sets `Encryption = off`: the drive then acts
    /// pre-authenticated and serves de-bussed content (no cert AKE needed).
    pub(crate) fn disables_encryption(self) -> bool {
        matches!(
            self,
            ArmRecipe::OemUhd | ArmRecipe::BypassBd | ArmRecipe::BypassUhd
        )
    }
}

// ── FirmwareControl ──────────────────────────────────────────────────────────

/// A timeout every firmware command uses (ms). Matches the wider unlocker.
const CMD_TIMEOUT_MS: u32 = 5_000;

/// An ergonomic, typed driver for the freemkv vendor-command grammar over any
/// [`ScsiTransport`]. Borrows the transport for the lifetime of the control.
///
/// ```no_run
/// # use freemkv_unlock::firmware::{FirmwareControl, FirmwareError};
/// # fn demo(scsi: &mut dyn freemkv_unlock::scsi::ScsiTransport) -> Result<(), FirmwareError> {
/// let mut fw = FirmwareControl::new(scsi);
/// // Encryption off on a UHD disc, revocation ignored. Refused with
/// // `UnsupportedFirmware` unless IDENTITY reports a supported freemkv drive;
/// // `Transport` (dead bus) must abort the caller.
/// fw.arm_oem_uhd()?;
/// # Ok(())
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
    /// `Ok(None)` if the reply lacked [`RESP_MAGIC`] or the drive refused the
    /// command (not freemkv firmware); `Err(Transport)` only on a dead bus.
    pub fn identity(&mut self) -> Result<Option<FirmwareIdentity>> {
        let cdb = build_identity_cdb(MEMREAD_LEN as u16);
        match self.exec_in(&cdb) {
            Ok((buf, n)) => Ok(FirmwareIdentity::parse(&buf[..n.min(buf.len())])),
            // A drive that rejects the knock is simply not freemkv firmware.
            Err(FirmwareError::Rejected) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Read the implementation descriptor and supported requests. Unsupported or
    /// malformed extensions are rejected rather than treated as legacy firmware.
    pub fn descriptor(&mut self) -> Result<Option<ProtocolIdentity>> {
        let cdb = build_identity_cdb(MEMREAD_LEN as u16);
        match self.exec_in(&cdb) {
            Ok((buf, n)) if n <= buf.len() => Ok(ProtocolIdentity::parse(&buf[..n])),
            Ok(_) => Err(FirmwareError::Rejected),
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

    /// Restore every feature to [`STATE_PASSTHROUGH`] (RESET with [`RESET_TO_OEM`])
    /// — TRUE OEM: firmware ≥0.8.3 also blanks the NV block so the drive is
    /// traceless. Data-in phase for the same reason as [`set`](Self::set) — a no-data
    /// RESET is aborted.
    pub fn reset(&mut self) -> Result<()> {
        let cdb = build_reset_cdb(RESET_TO_OEM);
        self.exec_in(&cdb).map(|_| ())
    }

    /// Restore the baked create-time defaults into the RAM feature-state table
    /// (RESET with [`RESET_TO_DEFAULTS`]) — what a never-saved drive boots to; does
    /// not touch flash. Firmware ≥0.8.3. Data-in phase for the same reason as
    /// [`reset`](Self::reset).
    pub fn reset_to_defaults(&mut self) -> Result<()> {
        let cdb = build_reset_cdb(RESET_TO_DEFAULTS);
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

    /// SET a feature, then GET it back and confirm the state stuck. Blind spot:
    /// fw answers a refused/out-of-range GET with GOOD + zeros, which reads as
    /// [`STATE_OFF`]; the recipes gate on [`Self::require_supported`] first.
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

    /// Refuse (`UnsupportedFirmware`) unless IDENTITY reports a supported
    /// freemkv firmware; every recipe calls this before its first SET/RESET.
    fn require_supported(&mut self) -> Result<()> {
        match self.identity()? {
            Some(id) if id.is_supported() => Ok(()),
            _ => Err(FirmwareError::UnsupportedFirmware),
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

    /// Force the Unrestricted (BD/UHD) capability gate on (drive engages both
    /// BD and UHD discs). fw 0.9.2 unified the former separate UHD/BD gates
    /// into this single lever.
    pub fn enable_unrestricted(&mut self) -> Result<()> {
        self.set(Feature::Unrestricted, STATE_ON)
    }
    /// Force the Unrestricted (BD/UHD) capability gate off.
    pub fn disable_unrestricted(&mut self) -> Result<()> {
        self.set(Feature::Unrestricted, STATE_OFF)
    }
    /// Skip the HRL lookup (revoked certs accepted; non-destructive). The unlock
    /// direction is now [`STATE_OFF`] (`0x00` = HRL enforcement off).
    pub fn skip_hrl(&mut self) -> Result<()> {
        self.set(Feature::Hrl, STATE_OFF)
    }
    /// Disable every drive-side encryption/cert requirement in one shot: the
    /// drive acts pre-authenticated (no handshake) AND content returns de-bussed
    /// (no in-transit bus encryption). The consolidated `Encryption` lever
    /// replaces the old separate `Ake`/`Bus` levers — wire id `0x07` (`Bus`) is
    /// retired. The unlock direction is [`STATE_OFF`] (`0x00`).
    pub fn disable_encryption(&mut self) -> Result<()> {
        self.set(Feature::Encryption, STATE_OFF)
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
    /// Force a specific DVD region (1..=8). Returns
    /// [`FirmwareError::InvalidArgument`] for an out-of-range region without
    /// touching the drive.
    pub fn force_region_dvd(&mut self, region: u8) -> Result<()> {
        if !(1..=8).contains(&region) {
            return Err(FirmwareError::InvalidArgument);
        }
        self.set(Feature::Region, REGION_DVD_BASE + region)
    }
    /// Lift the read-speed / riplock ceiling to maximum.
    pub fn unlock_speed(&mut self) -> Result<()> {
        self.set(Feature::Speed, SPEED_MAX)
    }

    // ── Named recipes (the "modes" table) ─────────────────────────────────────
    // Each recipe first issues IDENTITY and refuses unsupported firmware. A
    // recipe that fails midway leaves its earlier SETs applied (no rollback).

    /// **arm_oem_bd** — OEM-style Blu-ray (AACS 1.0) rip with a REAL AKE, only
    /// revocation disabled.
    ///
    /// Sets: `Hrl = skip` (revoked host certs accepted; non-destructive).
    /// Leaves everything else at passthrough — the drive still runs the real
    /// host-cert handshake and returns bus-encrypted content, so the host
    /// performs the AKE and de-busses. Rips: BD with an otherwise-revoked cert.
    pub fn arm_oem_bd(&mut self) -> Result<()> {
        self.require_supported()?;
        self.set_verify(Feature::Hrl, STATE_OFF)
    }

    /// **arm_oem_uhd** — OEM-style UHD (AACS 2.0) rip.
    ///
    /// Sets: `Unrestricted = on` (mode-gate neutralized so the drive engages
    /// the UHD disc), `Hrl = skip` (revocation off), `Encryption = off`
    /// (content de-bussed — the consolidated cert/bus bypass). Rips: UHD via
    /// the OEM path.
    pub fn arm_oem_uhd(&mut self) -> Result<()> {
        self.require_supported()?;
        self.set_verify(Feature::Unrestricted, STATE_ON)?;
        self.set_verify(Feature::Hrl, STATE_OFF)?;
        self.set_verify(Feature::Encryption, STATE_OFF)
    }

    /// **arm_bypass_bd** — full-bypass Blu-ray rip (NO host cert needed).
    ///
    /// Sets: `Encryption = off` (the consolidated cert/bus bypass — drive acts
    /// pre-authenticated, no handshake, content de-bussed) and `Hrl = skip`
    /// (revocation off). Rips: BD with no cert.
    pub fn arm_bypass_bd(&mut self) -> Result<()> {
        self.require_supported()?;
        self.set_verify(Feature::Hrl, STATE_OFF)?;
        self.set_verify(Feature::Encryption, STATE_OFF)
    }

    /// **arm_bypass_uhd** — full-bypass UHD rip (NO host cert needed).
    ///
    /// Sets: `Unrestricted = on` (engage the UHD disc), `Encryption = off`
    /// (the consolidated cert/bus bypass), and `Hrl = skip` (revocation off).
    /// Rips: UHD with no cert.
    pub fn arm_bypass_uhd(&mut self) -> Result<()> {
        self.require_supported()?;
        self.set_verify(Feature::Unrestricted, STATE_ON)?;
        self.set_verify(Feature::Hrl, STATE_OFF)?;
        self.set_verify(Feature::Encryption, STATE_OFF)
    }

    /// **arm_stealth_oem** — return the drive to byte-for-byte OEM behaviour.
    ///
    /// Issues RESET (every feature → passthrough) and verifies each feature read
    /// back as [`STATE_PASSTHROUGH`]. Rips: nothing — this DISARMS the drive.
    /// Needs fw >= [`MIN_FW_VERSION`]; raw [`reset`](Self::reset) has no gate.
    pub fn arm_stealth_oem(&mut self) -> Result<()> {
        self.require_supported()?;
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

/// Test fixture: the fw 0.9.x IDENTITY wire shape (core.rs `identity_blob` +
/// handler): `freemkv <ver>` with NO NUL, then the 6 raw flag bytes
/// `flag[0x01..=0x06]`, then zero padding to the 64-byte window.
#[cfg(test)]
pub(crate) fn identity_reply(version: &str, flags: [u8; 6]) -> Vec<u8> {
    let mut p = RESP_MAGIC.to_vec();
    p.push(b' ');
    p.extend_from_slice(version.as_bytes());
    p.extend_from_slice(&flags);
    p.resize(MEMREAD_LEN, 0);
    p
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
