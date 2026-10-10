use super::*;
use crate::scsi::{ScsiError, ScsiResult};

struct Loader {
    fail: bool,
}

impl mediatek::LiveLoader for Loader {
    fn is_mediatek(&self, drive: &crate::DriveId) -> bool {
        drive.vendor_id == "TEST MEDIATEK"
    }

    fn load(&self, scsi: &mut dyn ScsiTransport) -> BackendResult<()> {
        for opcode in [0xe0, if self.fail { 0xe2 } else { 0xe1 }] {
            scsi.execute(&[opcode], DataDirection::ToDevice, &mut [1], 100)
                .map_err(|_| UnlockError::Transport)?;
        }
        if self.fail {
            Err(UnlockError::NotApplicable)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct Drive {
    installed: bool,
    critical: bool,
    begins: usize,
    ends: usize,
    pauses: usize,
    cancelled: bool,
    cancel_before_load: bool,
    cancel_during_load: bool,
    post_probe: u8,
    fail_activation: bool,
    events: Vec<(u8, bool)>,
}

fn transport_error() -> ScsiError {
    ScsiError {
        status: 0xff,
        sense: None,
    }
}

impl ScsiTransport for Drive {
    fn execute(
        &mut self,
        cdb: &[u8],
        _: DataDirection,
        data: &mut [u8],
        _: u32,
    ) -> crate::scsi::Result<ScsiResult> {
        if self.cancelled && !self.critical {
            return Err(transport_error());
        }
        self.events.push((cdb[0], self.critical));
        let response = match cdb[0] {
            0xe0 => {
                self.cancelled |= self.cancel_during_load;
                vec![]
            }
            0xe1 => {
                self.installed = true;
                vec![]
            }
            0xe2 => {
                self.installed = false;
                vec![]
            }
            0x3c if cdb[4] == 1 => {
                if !self.installed || self.post_probe == 1 {
                    vec![0; 64]
                } else if self.post_probe == 2 {
                    return Err(transport_error());
                } else if self.post_probe == 3 {
                    crate::protocol::pioneer_identity().to_vec()
                } else {
                    let mut identity = b"freemkv 0.9.2".to_vec();
                    identity.extend_from_slice(&[0xff, 0xff, 1, 1, 0xff, 0xff]);
                    identity.resize(64, 0);
                    if self.post_probe == 4 {
                        identity[32] = 0x80;
                    }
                    identity
                }
            }
            0x3c if cdb[4] == 2 => {
                if self.fail_activation {
                    return Err(transport_error());
                }
                vec![0; data.len()]
            }
            0xad => {
                let mut vid = vec![0; 36];
                vid[4..20].fill(0x7c);
                vid
            }
            _ => panic!("unexpected fake-drive command: {cdb:?}"),
        };
        data[..response.len()].copy_from_slice(&response);
        Ok(ScsiResult {
            status: 0,
            bytes_transferred: response.len(),
            sense: [0; 32],
        })
    }

    fn begin_critical(&mut self) -> crate::scsi::Result<()> {
        self.begins += 1;
        assert!(!self.critical, "critical spans must not nest");
        self.cancelled |= self.cancel_before_load;
        if self.cancelled {
            return Err(transport_error());
        }
        self.critical = true;
        Ok(())
    }

    fn end_critical(&mut self) {
        assert!(self.critical);
        self.ends += 1;
        self.critical = false;
    }

    fn pause(&mut self, _: std::time::Duration) -> crate::scsi::Result<()> {
        assert!(!self.critical);
        self.pauses += 1;
        if self.cancelled {
            Err(transport_error())
        } else {
            Ok(())
        }
    }
}

fn unlock(drive: &mut Drive, fail: bool) -> BackendResult<Option<Unlocked>> {
    let id = crate::DriveId {
        vendor_id: "TEST MEDIATEK".into(),
        ..crate::DriveId::default()
    };
    let ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
    FreemkvUnlocker::new()
        .with_mediatek_loader(Box::new(Loader { fail }))
        .unlock(drive, &ctx)
}

#[test]
fn regression_mediatek_load_unlocks_on_the_same_call() {
    let mut drive = Drive::default();
    let result = unlock(&mut drive, false)
        .unwrap()
        .expect("same-call unlock");
    assert_eq!(result.vid, Some([0x7c; 16]));
    assert_eq!(drive.events.iter().filter(|(op, _)| *op == 0xe0).count(), 1);
    assert_eq!((drive.begins, drive.ends, drive.pauses), (1, 1, 1));
    assert!(!drive.events[0].1);
    assert!(drive.events[1..].iter().all(|(_, guarded)| *guarded));
}

#[test]
fn regression_mediatek_cancel_before_critical_never_calls_loader() {
    let mut drive = Drive {
        cancel_before_load: true,
        ..Drive::default()
    };
    assert_eq!(
        unlock(&mut drive, false).unwrap_err(),
        UnlockError::Transport
    );
    assert_eq!(drive.events, vec![(0x3c, false)]);
    assert_eq!((drive.begins, drive.ends), (1, 0));
}

#[test]
fn regression_mediatek_cancel_during_load_completes_critical_work_then_reports_stop() {
    let mut drive = Drive {
        cancel_during_load: true,
        ..Drive::default()
    };
    assert_eq!(
        unlock(&mut drive, false).unwrap_err(),
        UnlockError::Transport
    );
    assert!(drive.installed);
    assert_eq!(drive.events.last(), Some(&(0xad, true)));
    assert!(drive.events[1..].iter().all(|(_, guarded)| *guarded));
    assert_eq!((drive.begins, drive.ends, drive.pauses), (1, 1, 1));
}

#[test]
fn regression_mediatek_loader_failure_cleanup_stays_guarded() {
    let mut drive = Drive::default();
    assert!(unlock(&mut drive, true).unwrap().is_none());
    assert!(!drive.installed);
    assert_eq!(
        drive.events,
        vec![(0x3c, false), (0xe0, true), (0xe2, true)]
    );
    assert_eq!((drive.begins, drive.ends), (1, 1));
}

#[test]
fn regression_mediatek_cancelled_failed_load_finishes_cleanup() {
    let mut drive = Drive {
        cancel_during_load: true,
        ..Drive::default()
    };
    assert_eq!(
        unlock(&mut drive, true).unwrap_err(),
        UnlockError::Transport
    );
    assert_eq!(drive.events.last(), Some(&(0xe2, true)));
    assert!(!drive.installed);
    assert_eq!((drive.begins, drive.ends, drive.pauses), (1, 1, 1));
}

#[test]
fn regression_mediatek_refuses_missing_wrong_or_malformed_post_load_identity() {
    for post_probe in [1, 2, 3, 4] {
        let mut drive = Drive {
            post_probe,
            ..Drive::default()
        };
        let result = unlock(&mut drive, false);
        if post_probe == 2 {
            assert_eq!(result.unwrap_err(), UnlockError::Transport);
        } else {
            assert!(result.unwrap().is_none());
        }
        assert_eq!(
            drive.events.len(),
            4,
            "no SET or VID after refused identity"
        );
        assert_eq!((drive.begins, drive.ends), (1, 1));
    }
}

#[test]
fn regression_mediatek_activation_failure_releases_critical_span() {
    let mut drive = Drive {
        fail_activation: true,
        ..Drive::default()
    };
    assert_eq!(
        unlock(&mut drive, false).unwrap_err(),
        UnlockError::Transport
    );
    assert_eq!((drive.begins, drive.ends), (1, 1));
    assert!(!drive.critical);
    assert!(!drive.events.iter().any(|(op, _)| *op == 0xad));
}

#[test]
fn regression_mediatek_preinstalled_firmware_skips_loader() {
    let mut drive = Drive {
        installed: true,
        ..Drive::default()
    };
    assert!(unlock(&mut drive, true).unwrap().is_some());
    assert!(!drive.events.iter().any(|(op, _)| matches!(op, 0xe0..=0xe2)));
    assert_eq!((drive.begins, drive.ends), (1, 1));
}
