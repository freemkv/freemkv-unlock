//! freemkv-unlock-aacs — the AACS host-certificate unlocker plugin for libfreemkv.
//!
//! A Blu-ray / UHD disc with AACS bus encryption only serves clear content
//! after a host-certificate AKE (the cert handshake) yields the bus key. This
//! crate owns the [`libfreemkv::Unlocker`] impl that performs that unlock;
//! libfreemkv owns the cert-handshake primitive
//! ([`libfreemkv::aacs::handshake::run_cert_handshake`]) and the AACS content
//! decryption.
//!
//! Plug it in once at process start:
//!
//! ```no_run
//! libfreemkv::register_unlocker(Box::new(freemkv_unlock_aacs::AacsUnlocker::new()));
//! ```
//!
//! Remove the unlocker by deleting that one line and the dependency.

use libfreemkv::aacs::Vid;
use libfreemkv::aacs::handshake::{collect_host_certs, run_cert_handshake};
use libfreemkv::scsi::{DataDirection, SCSI_GET_CONFIGURATION, ScsiTransport};
use libfreemkv::{DiscKind, UnlockCtx, UnlockError, Unlocked, Unlocker};

/// The AACS host-certificate unlocker. Matches a Blu-ray/UHD disc
/// (`DiscKind::Aacs`), self-verifies the drive reports a BD profile, gathers
/// host certs from the scan options, and runs the cert handshake to learn the
/// Volume ID + AACS bus key (`read_data_key`).
pub struct AacsUnlocker;

impl AacsUnlocker {
    pub fn new() -> Self {
        AacsUnlocker
    }
}

impl Default for AacsUnlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl Unlocker for AacsUnlocker {
    fn name(&self) -> &str {
        "aacs-cert"
    }

    fn matches(&self, ctx: &UnlockCtx) -> bool {
        ctx.kind == DiscKind::Aacs
    }

    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        // Self-guard against the hardware — do NOT trust the caller-declared
        // DiscKind alone. If the drive does not report a Blu-ray profile, refuse
        // (NotApplicable) WITHOUT issuing any handshake CDB.
        if !mounted_disc_is_bd(scsi) {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "aacs_unlocker_not_bd",
                "AacsUnlocker invoked on a non-Blu-ray profile; refusing (NotApplicable)"
            );
            return Err(UnlockError::NotApplicable);
        }

        // The cert route needs a host-cert source. Without scan options there is
        // nothing to authenticate with — fall through (NotApplicable).
        let Some(opts) = ctx.opts else {
            return Err(UnlockError::NotApplicable);
        };

        // MKB generation (best-effort): lets a key source pick a
        // generation-appropriate host cert.
        let mkb = libfreemkv::aacs::read_mkb_from_drive(scsi)
            .ok()
            .and_then(|m| libfreemkv::aacs::mkb_version(&m));

        let host_certs = collect_host_certs(opts, mkb);
        if host_certs.is_empty() {
            tracing::warn!(
                target: "freemkv::disc",
                phase = "handshake_no_host_cert",
                "No AACS host certificate available from any key source, so the host-certificate handshake can't run."
            );
            return Err(UnlockError::NoUsableHostCert { mkb });
        }

        let h = run_cert_handshake(scsi, &host_certs)?;
        Ok(Unlocked {
            vid: Some(Vid(h.volume_id)),
            read_data_key: h.read_data_key,
            // Host-cert AKE path: bus removal depends on read_data_key, NOT a
            // firmware unlock.
            drive_unlocked: false,
            read_data_key_err: h.read_data_key_err,
        })
    }
}

/// Transport-level "is the mounted disc a Blu-ray?" probe (GET CONFIGURATION
/// current-profile, BD family `0x0040..=0x0043`). Keeps the AACS self-guard
/// inside the unlocker that needs it.
fn mounted_disc_is_bd(scsi: &mut dyn ScsiTransport) -> bool {
    // RT=0: the 8-byte feature header carries the Current Profile in bytes 6-7.
    let cdb = [
        SCSI_GET_CONFIGURATION,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x08,
        0x00,
    ];
    let mut buf = [0u8; 8];
    match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
        Ok(r) if r.bytes_transferred >= 8 => {
            let profile = ((buf[6] as u16) << 8) | buf[7] as u16;
            (0x0040..=0x0043).contains(&profile)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libfreemkv::scsi::ScsiResult;

    fn fake_id() -> libfreemkv::DriveId {
        let mut inquiry = vec![0u8; 96];
        inquiry[8..16].copy_from_slice(b"FAKEVNDR");
        libfreemkv::DriveId::from_inquiry(&inquiry, "")
    }

    /// A transport reporting a fixed current profile; counts any non-GET
    /// CONFIGURATION CDB (handshake activity).
    struct ProfileTransport {
        profile: u16,
        other_cdbs: usize,
    }
    impl ScsiTransport for ProfileTransport {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> libfreemkv::error::Result<ScsiResult> {
            if cdb[0] == SCSI_GET_CONFIGURATION {
                if data.len() >= 8 {
                    data[6] = (self.profile >> 8) as u8;
                    data[7] = self.profile as u8;
                }
                return Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: 8,
                    sense: [0u8; 32],
                });
            }
            self.other_cdbs += 1;
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: 0,
                sense: [0u8; 32],
            })
        }
    }

    /// AacsUnlocker matches only `DiscKind::Aacs` and carries the stable name.
    #[test]
    fn matches_only_aacs_kind() {
        let id = fake_id();
        let u = AacsUnlocker::new();
        assert_eq!(u.name(), "aacs-cert");
        assert!(u.matches(&UnlockCtx::new(&id, DiscKind::Aacs)));
        for k in [DiscKind::Unknown, DiscKind::Unencrypted, DiscKind::Css] {
            assert!(!u.matches(&UnlockCtx::new(&id, k)), "must not match {k:?}");
        }
    }

    /// Self-guard: a DVD-profile drive yields NotApplicable and NO handshake CDB
    /// is issued (no AACS auth fired at a DVD).
    #[test]
    fn self_guards_against_non_bd() {
        let id = fake_id();
        let mut t = ProfileTransport {
            profile: 0x0010, // DVD-ROM
            other_cdbs: 0,
        };
        let r = AacsUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Aacs));
        assert_eq!(r.unwrap_err(), UnlockError::NotApplicable);
        assert_eq!(t.other_cdbs, 0, "no handshake CDB at a non-BD drive");
    }

    /// A BD-profile drive with no scan options (no host-cert source) → it passes
    /// the hardware self-guard but cannot authenticate → NotApplicable.
    #[test]
    fn bd_without_opts_is_not_applicable() {
        let id = fake_id();
        let mut t = ProfileTransport {
            profile: 0x0040, // BD-ROM
            other_cdbs: 0,
        };
        // UnlockCtx::new carries opts = None.
        let r = AacsUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Aacs));
        assert_eq!(r.unwrap_err(), UnlockError::NotApplicable);
    }
}
