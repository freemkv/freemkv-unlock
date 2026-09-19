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

    /// Opt IN to arming a freemkv-firmware drive with a named recipe *before*
    /// the cert AKE (builder style). OFF by default, so the cert route's default
    /// behaviour is unchanged and a non-freemkv / stock drive is never sent a
    /// vendor command. When set, `unlock()` probes via
    /// [`FirmwareControl::identity`] and applies `recipe` only on a match — e.g.
    /// [`ArmRecipe::BypassBd`] (`Ake=null`) pre-authenticates the drive so cert
    /// selection is moot; [`ArmRecipe::OemBd`] (`Hrl=skip`) accepts a revoked
    /// cert. A non-freemkv drive or a refused recipe is left untouched.
    pub fn arm_before_unlock(mut self, recipe: ArmRecipe) -> Self {
        self.arm = Some(recipe);
        self
    }

    /// If arming is opted-in, detect freemkv firmware and apply the recipe.
    /// Best-effort: a non-freemkv drive or a refused recipe is a no-op; only a
    /// dead bus (`FirmwareError::Transport`) aborts the whole unlock.
    fn maybe_arm(&self, scsi: &mut dyn ScsiTransport) -> std::result::Result<(), UnlockError> {
        let Some(recipe) = self.arm else {
            return Ok(());
        };
        let mut fw = FirmwareControl::new(scsi);
        match fw.identity() {
            Ok(Some(id)) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "aacs_arm_freemkv_detected",
                    version = %id.version,
                    recipe = ?recipe,
                    "freemkv firmware detected; arming before the cert AKE"
                );
                match fw.arm(recipe) {
                    Ok(()) => Ok(()),
                    Err(FirmwareError::Transport) => Err(UnlockError::Transport),
                    Err(e) => {
                        tracing::debug!(
                            target: "freemkv::disc",
                            phase = "aacs_arm_recipe_refused",
                            recipe = ?recipe,
                            error = ?e,
                            "firmware refused the arm recipe; proceeding with the plain cert AKE"
                        );
                        Ok(())
                    }
                }
            }
            Ok(None) => Ok(()), // not freemkv — leave the drive untouched
            Err(FirmwareError::Transport) => Err(UnlockError::Transport),
            Err(_) => Ok(()),
        }
    }
}

impl Unlocker for AacsUnlocker {
    fn name(&self) -> &'static str {
        "AACS"
    }

    /// Remove AACS bus encryption via the host-cert handshake. Like every other
    /// unlocker this DOES unlock the drive — just with a cert + AKE instead of a
    /// vendor CDB. `Some` on a successful handshake (VID + bus key learned);
    /// `None` on a non-AACS disc, no usable cert, or a rejected handshake (fall
    /// through); `Err(Transport)` on a dead bus.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        if ctx.kind != DiscKind::Aacs || self.host_certs.is_empty() {
            // Wrong disc kind, or no host cert to authenticate with — the loop
            // falls through to a VID-less / keysource path.
            return Ok(None);
        }
        // Opt-in: arm a freemkv-firmware drive before the AKE (no-op by default,
        // and on non-freemkv drives). Only a dead bus aborts here.
        self.maybe_arm(scsi)?;
        crate::fallthrough(self.run_handshake(scsi).map(|h| {
            // A UHD disc whose bus-key fetch the drive refused (non-transport)
            // returns Ok with read_data_key: None + read_data_key_err: Some —
            // otherwise indistinguishable from an AACS-1.0 disc. Surface it.
            if h.read_data_key.is_none()
                && let Some(code) = h.read_data_key_err
            {
                tracing::warn!(
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
mod tests {
    use super::*;

    /// AES-128-ECB decrypt against the FIPS-197 Appendix B / NIST known-answer
    /// test vector: decrypting the published ciphertext with the published key
    /// must recover the published plaintext.
    #[test]
    fn aes_ecb_decrypt_matches_fips197_test_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let ciphertext: [u8; 16] = [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4,
            0xC5, 0x5A,
        ];
        let expected_plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let out = aes_ecb_decrypt(&key, &ciphertext);
        assert_eq!(out, expected_plaintext);
    }

    /// Decrypting a different ciphertext under the same key must not produce
    /// the same plaintext — pins that the function actually decrypts the
    /// given block rather than returning a constant.
    #[test]
    fn aes_ecb_decrypt_varies_with_input() {
        let key = [0u8; 16];
        let a = aes_ecb_decrypt(&key, &[0u8; 16]);
        let b = aes_ecb_decrypt(&key, &[1u8; 16]);
        assert_ne!(a, b);
    }

    fn id() -> crate::DriveId {
        crate::DriveId::default()
    }

    /// Self-guards on the disc kind: on a non-AACS disc `unlock()` declines
    /// (`Ok(false)`) WITHOUT touching the transport, even WITH a cert present —
    /// so the reason is the kind, not a missing cert.
    #[test]
    fn declines_non_aacs_kinds() {
        struct DeadTransport;
        impl ScsiTransport for DeadTransport {
            fn execute(
                &mut self,
                _cdb: &[u8],
                _dir: crate::scsi::DataDirection,
                _data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
                panic!("transport must not be touched on a non-AACS disc");
            }
        }
        let id = id();
        let mut t = DeadTransport;
        for k in [DiscKind::Unknown, DiscKind::Unencrypted, DiscKind::Css] {
            assert!(
                AacsUnlocker::new(vec![host_cert()])
                    .unlock(&mut t, &UnlockCtx::new(&id, k))
                    .expect("declines")
                    .is_none(),
                "declines {k:?}"
            );
        }
    }

    // Full success path through `Unlocker::unlock`: a self-consistent AACS 1.0
    // emulator proves the entry point learns `vid`/`bus_key` — and that the cert
    // route reports `unlock() == true` (it DOES unlock the drive, via the cert).
    #[test]
    fn unlock_succeeds_end_to_end() {
        let mut t = handshake::tests::DriveEmu::new();
        t.serve_data_keys = true;
        let (lax, lay) = (t.la_x, t.la_y);
        let id = id();
        let ctx = UnlockCtx::new(&id, DiscKind::Aacs);
        let out = AacsUnlocker::new(vec![host_cert()])
            .with_test_v1_anchor(lax, lay)
            .unlock(&mut t, &ctx)
            .expect("auth + VID + data-key reads all succeed")
            .expect("the cert route unlocks the drive");
        assert_eq!(out.vid, Some([0x5Au8; 16]));
        assert!(out.bus_key.is_some());
    }

    // The `read_data_key_dropped` path: auth + VID succeed but the drive serves
    // no bus key (non-transport). `unlock` still reports Unlocked (unlocked via
    // the cert) with `vid: Some` but `bus_key: None` — surfaced, not hidden.
    #[test]
    fn unlock_without_a_served_read_data_key_yields_vid_but_no_bus_key() {
        let mut t = handshake::tests::DriveEmu::new();
        t.serve_zero_data_keys = true; // GOOD status, all-zero key block
        let (lax, lay) = (t.la_x, t.la_y);
        let id = id();
        let ctx = UnlockCtx::new(&id, DiscKind::Aacs);
        let out = AacsUnlocker::new(vec![host_cert()])
            .with_test_v1_anchor(lax, lay)
            .unlock(&mut t, &ctx)
            .expect("auth + VID succeed even when the bus key is refused")
            .expect("the cert route still unlocks the drive");
        assert_eq!(out.vid, Some([0x5Au8; 16]), "the VID was learned");
        assert!(
            out.bus_key.is_none(),
            "no read_data_key served ⇒ bus_key: None (reported, not faked)"
        );
    }

    fn host_cert() -> crate::HostCert {
        handshake::tests::dummy_cert()
    }

    // ── Opt-in arm-before-unlock ──────────────────────────────────────────────

    /// The default (no arm opted-in) NEVER touches the transport for arming.
    #[test]
    fn no_arm_by_default_does_not_probe_firmware() {
        struct PanicTransport;
        impl ScsiTransport for PanicTransport {
            fn execute(
                &mut self,
                _cdb: &[u8],
                _dir: crate::scsi::DataDirection,
                _data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
                panic!("default AacsUnlocker must not issue a firmware knock");
            }
        }
        let u = AacsUnlocker::new(vec![host_cert()]);
        assert!(u.arm.is_none());
        u.maybe_arm(&mut PanicTransport).expect("no-op");
    }

    /// Opting in on a NON-freemkv drive probes once (IDENTITY) and then leaves
    /// the drive untouched — no recipe SETs are sent.
    #[test]
    fn arm_on_non_freemkv_drive_is_a_noop_after_the_probe() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::illegal_request());
        let u = AacsUnlocker::new(vec![host_cert()]).arm_before_unlock(ArmRecipe::BypassBd);
        u.maybe_arm(&mut t).expect("no-op on non-freemkv");
        // Exactly one CDB: the IDENTITY probe. No recipe SETs followed.
        assert_eq!(t.cdbs.len(), 1);
        assert_eq!(t.cdbs[0][4], crate::firmware::Verb::Identity as u8);
    }

    /// A dead bus on the arm probe aborts the whole unlock.
    #[test]
    fn arm_probe_transport_fault_aborts() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::TransportFault);
        let u = AacsUnlocker::new(vec![host_cert()]).arm_before_unlock(ArmRecipe::BypassBd);
        assert_eq!(u.maybe_arm(&mut t).unwrap_err(), UnlockError::Transport);
    }

    /// Opting in on a freemkv drive applies the recipe: BypassBd sends
    /// Set(Ake, on) and verifies it, BEFORE the handshake would run.
    #[test]
    fn arm_on_freemkv_drive_applies_the_recipe() {
        use crate::firmware::{
            ALL_FEATURES, CDB_FEATURE, CDB_STATE, CDB_VERB, Feature, RESP_MAGIC, STATE_OFF,
            STATE_PASSTHROUGH, Verb, build_set_cdb,
        };
        // A minimal freemkv drive: IDENTITY→magic, SET updates state, GET reads it.
        struct FwDrive {
            ake: u8,
            hrl: u8,
            cdbs: Vec<Vec<u8>>,
        }
        impl ScsiTransport for FwDrive {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: crate::scsi::DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
                self.cdbs.push(cdb.to_vec());
                let mut n = 0;
                if cdb[CDB_VERB] == Verb::Identity as u8 {
                    let mut resp = RESP_MAGIC.to_vec();
                    resp.push(0x01);
                    resp.extend(std::iter::repeat_n(STATE_PASSTHROUGH, ALL_FEATURES.len()));
                    n = resp.len().min(data.len());
                    data[..n].copy_from_slice(&resp[..n]);
                } else if cdb[CDB_VERB] == Verb::Set as u8 && cdb[CDB_FEATURE] == Feature::Ake as u8
                {
                    self.ake = cdb[CDB_STATE];
                } else if cdb[CDB_VERB] == Verb::Set as u8 && cdb[CDB_FEATURE] == Feature::Hrl as u8
                {
                    self.hrl = cdb[CDB_STATE];
                } else if cdb[CDB_VERB] == Verb::Get as u8
                    && cdb[CDB_FEATURE] == Feature::Ake as u8
                    && !data.is_empty()
                {
                    data[0] = self.ake;
                    n = 1;
                } else if cdb[CDB_VERB] == Verb::Get as u8
                    && cdb[CDB_FEATURE] == Feature::Hrl as u8
                    && !data.is_empty()
                {
                    data[0] = self.hrl;
                    n = 1;
                }
                Ok(crate::scsi::ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0u8; 32],
                })
            }
        }
        let mut t = FwDrive {
            ake: STATE_PASSTHROUGH,
            hrl: STATE_PASSTHROUGH,
            cdbs: Vec::new(),
        };
        let u = AacsUnlocker::new(vec![host_cert()]).arm_before_unlock(ArmRecipe::BypassBd);
        u.maybe_arm(&mut t).expect("armed");
        assert_eq!(t.hrl, STATE_OFF, "the recipe skipped revocation (Hrl=off)");
        assert_eq!(t.ake, STATE_OFF, "the recipe nulled the AKE (Ake=off)");
        // IDENTITY, then Set(Hrl,off)+verify, then Set(Ake,off)+verify.
        assert_eq!(t.cdbs[0][CDB_VERB], Verb::Identity as u8);
        assert_eq!(t.cdbs[1], build_set_cdb(Feature::Hrl, STATE_OFF));
        assert_eq!(t.cdbs[2][CDB_VERB], Verb::Get as u8);
        assert_eq!(t.cdbs[3], build_set_cdb(Feature::Ake, STATE_OFF));
        assert_eq!(t.cdbs[4][CDB_VERB], Verb::Get as u8);
    }

    /// With no host certs there is nothing to authenticate with → `Ok(false)`,
    /// and the transport is never touched.
    #[test]
    fn no_host_certs_declines() {
        struct DeadTransport;
        impl ScsiTransport for DeadTransport {
            fn execute(
                &mut self,
                _cdb: &[u8],
                _dir: crate::scsi::DataDirection,
                _data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
                panic!("transport must not be touched with no host certs");
            }
        }
        let id = id();
        let mut t = DeadTransport;
        assert!(
            AacsUnlocker::new(vec![])
                .unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Aacs))
                .expect("no certs declines")
                .is_none()
        );
    }
}
