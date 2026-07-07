//! aacs — the AACS host-certificate unlocker (Blu-ray / UHD).
//!
//! Self-contained module: it owns the cert-handshake EC crypto (the AKE, bus-key
//! derivation, P-160 / P-256 curve math) that REMOVES AACS bus encryption. It
//! implements [`crate::Unlocker`], learning the Volume ID + AACS 2.x bus key.
//! Content-key decryption (unit keys, MKB, VUK) is the consumer's job, not here.

mod error;
mod handshake;

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};

use crate::scsi::ScsiTransport;
use crate::{DiscKind, UnlockCtx, UnlockError, Unlocked, Unlocker};

/// AES-128-ECB decrypt a single 16-byte block — used to decrypt the bus key /
/// read_data_key the drive returns after the handshake.
pub(crate) fn aes_ecb_decrypt(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(data);
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

/// The AACS host-certificate unlocker. Matches a Blu-ray/UHD disc
/// (`DiscKind::Aacs`) and runs the cert handshake against the host certs the
/// consumer collected (via [`UnlockCtx::host_certs`]), learning the Volume ID
/// and — on AACS 2.0 — the bus key.
pub struct AacsCert;

impl AacsCert {
    pub fn new() -> Self {
        AacsCert
    }
}

impl Default for AacsCert {
    fn default() -> Self {
        Self::new()
    }
}

impl Unlocker for AacsCert {
    fn name(&self) -> &'static str {
        "AACS"
    }

    /// AACS removes BUS encryption via the host-cert handshake; it provides no
    /// drive features. Self-guards on the disc kind (the consumer iterates every
    /// unlocker's `unlock_bus`, so a non-AACS disc must decline here).
    fn unlock_bus(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        if ctx.kind != DiscKind::Aacs {
            return Err(UnlockError::NotApplicable);
        }
        if ctx.host_certs.is_empty() {
            // No host cert to authenticate with — the consumer falls back to a
            // VID-less / keysource path.
            return Err(UnlockError::NoUsableHostCert);
        }
        let h = handshake::run_cert_handshake(scsi, ctx.host_certs)?;
        Ok(Unlocked {
            vid: Some(h.volume_id),
            // Host-cert AKE path: bus removal depends on the bus key, not a
            // firmware unlock.
            bus_key: h.read_data_key,
            drive_unlocked: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> crate::DriveId {
        crate::DriveId::default()
    }

    /// `unlock_bus` self-guards on the disc kind: on a non-AACS disc it declines
    /// (`NotApplicable`) WITHOUT touching the transport, so iterating it on a
    /// CSS/unknown disc is safe.
    #[test]
    fn unlock_bus_declines_non_aacs_kinds() {
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
            let r = AacsCert::new().unlock_bus(&mut t, &UnlockCtx::new(&id, k, &[]));
            assert_eq!(r.unwrap_err(), UnlockError::NotApplicable, "declines {k:?}");
        }
    }

    /// With no host certs there is nothing to authenticate with → NoUsableHostCert,
    /// and the transport is never touched.
    #[test]
    fn no_host_certs_is_no_usable_host_cert() {
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
        let r = AacsCert::new().unlock_bus(&mut t, &UnlockCtx::new(&id, DiscKind::Aacs, &[]));
        assert_eq!(r.unwrap_err(), UnlockError::NoUsableHostCert);
    }
}
