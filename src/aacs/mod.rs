//! aacs — the AACS host-certificate unlocker (Blu-ray / UHD).
//!
//! Self-contained module: it owns the cert-handshake EC crypto (the AKE, bus-key
//! derivation, P-160 / P-256 curve math) that REMOVES AACS bus encryption. It
//! implements [`crate::Unlocker`], learning the Volume ID + AACS 2.x bus key.
//! Content-key decryption (unit keys, MKB, VUK) is the consumer's job, not here.

mod error;
mod handshake;

use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, KeyInit};

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
}

impl AacsUnlocker {
    pub fn new(host_certs: Vec<HostCert>) -> Self {
        AacsUnlocker { host_certs }
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
        crate::fallthrough(
            handshake::run_cert_handshake(scsi, &self.host_certs).map(|h| Unlocked {
                vid: Some(h.volume_id),
                bus_key: h.read_data_key,
            }),
        )
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
        let id = id();
        let ctx = UnlockCtx::new(&id, DiscKind::Aacs);
        let out = AacsUnlocker::new(vec![host_cert()])
            .unlock(&mut t, &ctx)
            .expect("auth + VID + data-key reads all succeed")
            .expect("the cert route unlocks the drive");
        assert_eq!(out.vid, Some([0x5Au8; 16]));
        assert!(out.bus_key.is_some());
    }

    fn host_cert() -> crate::HostCert {
        handshake::tests::dummy_cert()
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
