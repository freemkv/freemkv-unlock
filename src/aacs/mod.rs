//! aacs — the AACS host-certificate unlocker (Blu-ray / UHD).
//!
//! Self-contained module: it owns the cert-handshake EC crypto (the AKE, bus-key
//! derivation, P-160 / P-256 curve math) that REMOVES AACS bus encryption. It
//! implements [`crate::Unlocker`], learning the Volume ID + AACS 2.x bus key.
//! Content-key decryption (unit keys, MKB, VUK) is the consumer's job, not here.

mod error;
mod handshake;

/// Keypair-validity check for a stored AACS 1.0 host cert (`priv·G ==
/// cert_pub_key`). Exposed for the key service, which must refuse to serve a
/// cert whose stored private key doesn't match its certificate.
pub use handshake::aacs1_keypair_matches;

use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, KeyInit};

use crate::firmware::{ArmRecipe, FirmwareControl, FirmwareError};
use crate::scsi::ScsiTransport;
use crate::{DiscKind, HostCert, UnlockCtx, UnlockError, Unlocked, Unlocker};

/// AES-128-ECB decrypt a single 16-byte block — used to decrypt the bus key /
/// read_data_key the drive returns after the handshake.
pub(crate) fn aes_ecb_decrypt(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&(*key).into());
    let mut block: Array<u8, _> = (*data).into();
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

/// The AACS host-certificate unlocker — the fallback for a drive with NO vendor
/// unlock (can't be raw-read-enabled), so the bus is removed by a real host-cert
/// AKE + bus key rather than a CDB. The host certs are injected at CONSTRUCTION
/// (the one place certs enter the system). Owns its AKE crypto — no reach into
/// libfreemkv.
pub struct AacsUnlocker {
    host_certs: Vec<HostCert>,
    /// Opt-in: a freemkv firmware recipe to ARM the drive with before the cert
    /// AKE. `None` (the default) keeps behaviour byte-identical to a stock host
    /// — the drive is never touched with a vendor command. See
    /// [`AacsUnlocker::arm_before_unlock`].
    arm: Option<ArmRecipe>,
    /// TEST-ONLY seam: a self-generated AACS 1.0 LA anchor to run the cert AKE
    /// under. Production verifies against the real compiled-in anchor, which no
    /// synthetic drive emulator can sign for, so the end-to-end unlock tests
    /// drive the handshake under a test anchor instead. `None` in every real
    /// build (the field does not exist off `cfg(test)`).
    #[cfg(test)]
    test_v1_anchor: Option<([u8; 20], [u8; 20])>,
}

impl AacsUnlocker {
    pub fn new(host_certs: Vec<HostCert>) -> Self {
        AacsUnlocker {
            host_certs,
            arm: None,
            #[cfg(test)]
            test_v1_anchor: None,
        }
    }

    /// TEST-ONLY: run the cert AKE under a self-generated AACS 1.0 LA anchor
    /// (see [`AacsUnlocker::test_v1_anchor`]).
    #[cfg(test)]
    pub(crate) fn with_test_v1_anchor(mut self, la_x: [u8; 20], la_y: [u8; 20]) -> Self {
        self.test_v1_anchor = Some((la_x, la_y));
        self
    }

    /// Run the cert handshake against the drive. Production threads the real LA
    /// anchors via [`handshake::run_cert_handshake`]; a test may override the
    /// AACS 1.0 anchor so a synthetic drive can complete the AKE.
    fn run_handshake(
        &self,
        scsi: &mut dyn ScsiTransport,
    ) -> std::result::Result<handshake::CertHandshake, UnlockError> {
        #[cfg(test)]
        if let Some((ax, ay)) = self.test_v1_anchor {
            // v2 anchor is unused here: allow_p256 = false keeps the native 2.0
            // path off, so a zeroed placeholder is never read.
            let dummy_v2 = [0u8; 32];
            return handshake::run_cert_handshake_with_anchors(
                scsi,
                &self.host_certs,
                (&ax, &ay),
                (&dummy_v2, &dummy_v2),
                false,
            );
        }
        handshake::run_cert_handshake(scsi, &self.host_certs)
    }

    /// Opt IN (off by default) to arming a freemkv drive with `recipe` via
    /// [`FirmwareControl::arm`] before the cert AKE; non-freemkv or unsupported
    /// firmware gets only IDENTITY. An `Encryption=off` recipe (`BypassBd`,
    /// `BypassUhd`, `OemUhd`) pre-authenticates and de-busses the drive, so no
    /// cert is needed and `unlock()` returns the bare-read VID with no bus key.
    /// [`ArmRecipe::OemBd`] (`Hrl=off`) lets a revoked cert through the AKE. A
    /// recipe refused midway is not rolled back: its earlier SETs stay in RAM.
    pub fn arm_before_unlock(mut self, recipe: ArmRecipe) -> Self {
        self.arm = Some(recipe);
        self
    }

    /// If arming is opted-in, apply the recipe. `Ok(true)` only when an
    /// `Encryption=off` recipe armed (drive pre-authenticated + de-bussed).
    /// Unsupported firmware or a refused recipe is `Ok(false)` (a refusal may
    /// leave earlier SETs applied, so it logs at warn); a dead bus aborts.
    fn maybe_arm(&self, scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
        let Some(recipe) = self.arm else {
            return Ok(false);
        };
        match FirmwareControl::new(scsi).arm(recipe) {
            Ok(()) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "aacs_arm_applied",
                    recipe = ?recipe,
                    "freemkv firmware armed before the cert AKE"
                );
                Ok(recipe.disables_encryption())
            }
            Err(FirmwareError::Transport) => Err(UnlockError::Transport),
            Err(FirmwareError::UnsupportedFirmware) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "aacs_arm_unsupported",
                    recipe = ?recipe,
                    "not supported freemkv firmware; plain cert AKE"
                );
                Ok(false)
            }
            Err(e) => {
                tracing::warn!(
                    target: "freemkv::disc",
                    phase = "aacs_arm_recipe_refused",
                    recipe = ?recipe,
                    error = ?e,
                    "arm recipe refused (earlier SETs stay applied); plain cert AKE"
                );
                Ok(false)
            }
        }
    }
}

impl Unlocker for AacsUnlocker {
    fn name(&self) -> &'static str {
        "AACS"
    }

    /// Remove AACS bus encryption via the host-cert handshake. Like every other
    /// unlocker this DOES unlock the drive — just with a cert + AKE instead of a
    /// vendor CDB. `Some` on a successful handshake (VID + bus key learned), or
    /// after an opted-in `Encryption=off` arm (bare VID, no bus key);
    /// `None` on a non-AACS disc, no usable cert, or a rejected handshake (fall
    /// through); `Err(Transport)` on a dead bus.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        if ctx.kind != DiscKind::Aacs {
            return Ok(None);
        }
        // Opt-in arm (no-op by default). Encryption=off leaves the drive
        // pre-authenticated and de-bussed: no cert AKE, and no bus key to apply.
        if self.maybe_arm(scsi)? {
            let vid = crate::vid::read_aacs_vid(scsi)?;
            return Ok(Some(Unlocked { vid, bus_key: None }));
        }
        if self.host_certs.is_empty() {
            // No host cert to authenticate with — fall through.
            return Ok(None);
        }
        crate::fallthrough(self.run_handshake(scsi).map(|h| {
            // A UHD disc whose bus-key fetch the drive refused (non-transport)
            // returns Ok with read_data_key: None + read_data_key_err: Some —
            // otherwise indistinguishable from an AACS-1.0 disc. Surface it.
            if h.read_data_key.is_none()
                && let Some(code) = h.read_data_key_err
            {
                tracing::info!(
                    target: "freemkv::disc",
                    phase = "read_data_key_dropped",
                    error_code = code,
                    "AACS auth + VID succeeded but the drive served no read_data_key (bus key); \
                     unlock reports bus_key: None"
                );
            }
            Unlocked {
                vid: Some(h.volume_id),
                bus_key: h.read_data_key,
            }
        }))
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
