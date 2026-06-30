//! freemkv-unlock-css — the CSS (DVD-Video) unlocker plugin for libfreemkv.
//!
//! A CSS-enforcing DVD drive refuses to return scrambled sectors until a CSS
//! bus-authentication handshake has set its Authentication Success Flag
//! (ASF=1). This crate owns the [`libfreemkv::Unlocker`] impl that performs
//! that unlock; libfreemkv owns the bus-auth primitive
//! ([`libfreemkv::css::auth::unlock_css_reads`]) and the keyless descramble.
//!
//! Plug it in once at process start:
//!
//! ```no_run
//! libfreemkv::register_unlocker(Box::new(freemkv_unlock_css::CssUnlocker::new()));
//! ```
//!
//! Remove the unlocker by deleting that one line and the dependency.

use libfreemkv::scsi::{DataDirection, SCSI_GET_CONFIGURATION, ScsiTransport};
use libfreemkv::{DiscKind, UnlockCtx, UnlockError, Unlocked, Unlocker};

/// The CSS unlocker. Matches a DVD (`DiscKind::Css`), self-verifies the drive
/// reports a DVD profile, then runs the CSS bus-auth handshake to unlock
/// scrambled-sector reads. It learns neither a Volume ID nor a bus key — the
/// descramble key is recovered keylessly (the Stevenson attack in libfreemkv).
pub struct CssUnlocker;

impl CssUnlocker {
    pub fn new() -> Self {
        CssUnlocker
    }
}

impl Default for CssUnlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl Unlocker for CssUnlocker {
    fn name(&self) -> &str {
        "css"
    }

    fn matches(&self, ctx: &UnlockCtx) -> bool {
        ctx.kind == DiscKind::Css
    }

    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError> {
        // Self-guard against the hardware — do NOT trust the caller-declared
        // DiscKind alone. If the drive does not report a DVD profile, refuse
        // (NotApplicable) WITHOUT issuing any CSS CDB, so a mis-routed
        // Blu-ray/UHD is never sent CSS bus-auth.
        if !mounted_disc_is_dvd(scsi) {
            tracing::debug!(
                target: "freemkv::css",
                phase = "css_unlocker_not_dvd",
                "CssUnlocker invoked on a non-DVD profile; refusing (NotApplicable)"
            );
            return Err(UnlockError::NotApplicable);
        }
        // The bus-auth handshake (libfreemkv primitive) sets ASF=1; the lba is
        // not consumed by the unlock. CSS yields no VID and no bus key.
        libfreemkv::css::auth::unlock_css_reads(scsi, 0).map_err(UnlockError::from)?;
        Ok(Unlocked::default())
    }
}

/// Transport-level "is the mounted disc a DVD?" probe (GET CONFIGURATION
/// current-profile, DVD family `0x0010..=0x001F`). Keeps the CSS self-guard
/// inside the unlocker that needs it.
fn mounted_disc_is_dvd(scsi: &mut dyn ScsiTransport) -> bool {
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
            (0x0010..=0x001F).contains(&profile)
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

    /// CssUnlocker matches only `DiscKind::Css` and carries the stable name.
    #[test]
    fn matches_only_css_kind() {
        let id = fake_id();
        let u = CssUnlocker::new();
        assert_eq!(u.name(), "css");
        assert!(u.matches(&UnlockCtx::new(&id, DiscKind::Css)));
        for k in [DiscKind::Unknown, DiscKind::Unencrypted, DiscKind::Aacs] {
            assert!(!u.matches(&UnlockCtx::new(&id, k)), "must not match {k:?}");
        }
    }

    /// Self-guard: a drive reporting a Blu-ray profile yields NotApplicable and
    /// no CSS CDB is issued.
    #[test]
    fn self_guards_against_non_dvd() {
        struct BdTransport {
            non_config_cdbs: usize,
        }
        impl ScsiTransport for BdTransport {
            fn execute(
                &mut self,
                cdb: &[u8],
                _dir: DataDirection,
                data: &mut [u8],
                _timeout_ms: u32,
            ) -> libfreemkv::error::Result<ScsiResult> {
                if cdb[0] == SCSI_GET_CONFIGURATION {
                    if data.len() >= 8 {
                        data[6] = 0x00;
                        data[7] = 0x40; // BD-ROM current profile
                    }
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: 8,
                        sense: [0u8; 32],
                    });
                }
                self.non_config_cdbs += 1;
                Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: 0,
                    sense: [0u8; 32],
                })
            }
        }
        let id = fake_id();
        let mut t = BdTransport { non_config_cdbs: 0 };
        let r = CssUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Css));
        assert_eq!(r.unwrap_err(), UnlockError::NotApplicable);
        assert_eq!(t.non_config_cdbs, 0, "no CSS CDB at a non-DVD drive");
    }
}
