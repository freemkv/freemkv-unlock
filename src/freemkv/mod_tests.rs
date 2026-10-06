use super::*;
use crate::DiscKind;
use crate::firmware::{REGION_FREE, STATE_OFF, build_identity_cdb, build_memread_cdb};
use crate::scsi::mock::{MockTransport, Reply};
use crate::scsi::{DataDirection, Result, ScsiResult, ScsiTransport};

fn ctx(id: &crate::DriveId) -> UnlockCtx<'_> {
    UnlockCtx::new(id, DiscKind::Unknown)
}

/// The fw IDENTITY wire shape: `freemkv <ver>` (no NUL), the raw flag
/// table, then zero padding to the 64-byte window.
fn identity_payload(version: &str, flags: &[u8]) -> Vec<u8> {
    let mut p = b"freemkv ".to_vec();
    p.extend_from_slice(version.as_bytes());
    p.extend_from_slice(flags);
    p.resize(RESP_LEN, 0);
    p
}

/// A fresh-boot fw 0.9.2 drive (DEFAULT_FLAGS: Unrestricted + Bd on).
fn freemkv_identity_payload() -> Vec<u8> {
    identity_payload("0.9.2", &[0xFF, 0xFF, 0x01, 0x01, 0xFF, 0xFF])
}

/// A well-formed format-0x80 VID structure: 4-byte header, 16-byte VID at
/// offset 4, 16-byte MAC (zeroed on the bare path — it isn't checked). 36 =
/// the fixed `0xAD` fmt-0x80 response length (see `crate::vid`).
fn vid_ds_response(vid: [u8; 16]) -> Vec<u8> {
    let mut p = vec![0u8; 36];
    p[4..20].copy_from_slice(&vid);
    p
}

fn unlock(t: &mut MockTransport) -> std::result::Result<Option<Unlocked>, UnlockError> {
    let id = crate::DriveId::default();
    FreemkvUnlocker::new().unlock(t, &ctx(&id))
}

/// Regression (BU40N fw 0.8.1): a SET issued WITHOUT the data-in phase its
/// CDB advertises is aborted by the drive (CHECK CONDITION / Aborted Command),
/// so the unlocker's `set()` MUST read the MIN_ALLOC_LEN table back like
/// `FirmwareControl::set` — not send `DataDirection::None`. Before the fix
/// the whole freemkv unlock failed at the first SET and fell back to AACS.
#[test]
fn set_issues_the_required_data_in_phase() {
    struct DataInContract;
    impl ScsiTransport for DataInContract {
        fn execute(
            &mut self,
            cdb: &[u8],
            dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            assert_eq!(cdb[4], 0x02, "test exercises only the SET verb");
            // Model the drive: a SET with no from-device phase is aborted.
            if !matches!(dir, DataDirection::FromDevice) || data.is_empty() {
                return Ok(ScsiResult {
                    status: 2,
                    bytes_transferred: 0,
                    sense: [0u8; 32],
                });
            }
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: data.len(),
                sense: [0u8; 32],
            })
        }
    }
    FreemkvUnlocker::new()
        .set(&mut DataInContract, Feature::Region, REGION_FREE)
        .expect("SET must succeed by issuing the data-in phase the firmware requires");
}

// ── Detection ────────────────────────────────────────────────────────

#[test]
fn identify_true_on_supported_firmware_and_issues_identity_cdb() {
    let mut t = MockTransport::always(Reply::good(freemkv_identity_payload()));
    assert!(FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
    assert_eq!(t.cdbs[0], build_identity_cdb(RESP_LEN as u16));
}

#[test]
fn identify_false_on_non_matching_payload() {
    let mut t = MockTransport::always(Reply::good(vec![0u8; RESP_LEN]));
    assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
}

#[test]
fn identify_false_on_short_response() {
    let mut t = MockTransport::always(Reply::short(freemkv_identity_payload(), 3));
    assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
}

/// The status guard decides: a CHECK CONDITION that nonetheless reports a
/// full magic-bearing transfer (residual/echoed buffer) is not freemkv.
#[test]
fn identify_false_on_check_condition_with_a_magic_buffer() {
    struct CheckConditionWithData;
    impl ScsiTransport for CheckConditionWithData {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            let p = freemkv_identity_payload();
            data.copy_from_slice(&p[..data.len()]);
            Ok(ScsiResult {
                status: 2,
                bytes_transferred: data.len(),
                sense: [0u8; 32],
            })
        }
    }
    assert!(
        !FreemkvUnlocker::new()
            .identify(&mut CheckConditionWithData)
            .expect("no fault")
    );
}

#[test]
fn identify_false_when_command_rejected() {
    let mut t = MockTransport::always(Reply::illegal_request());
    assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
}

#[test]
fn identify_false_when_command_rejected_as_err() {
    let mut t = MockTransport::always(Reply::illegal_request_as_err());
    assert!(!FreemkvUnlocker::new().identify(&mut t).expect("no fault"));
}

#[test]
fn identify_transport_fault_aborts() {
    let mut t = MockTransport::always(Reply::TransportFault);
    assert_eq!(
        FreemkvUnlocker::new().identify(&mut t).unwrap_err(),
        UnlockError::Transport
    );
}

/// Regression: released fw 0.7.x (`freemkv 0.7.1` reply, old sub-function
/// grammar where 0x02 = Speed) answers GOOD to every SET. The unlocker must
/// decline it, not claim a drive it never unlocked.
#[test]
fn declines_legacy_07_firmware_without_sending_a_set() {
    let mut t = MockTransport::always(Reply::good(identity_payload("0.7.1", &[])));
    assert!(unlock(&mut t).expect("no fault").is_none());
    assert_eq!(t.calls(), 1, "only the IDENTITY probe");
}

/// Regression: fw 0.8.x (0x06 = `Ake`, separate `Bus`): de-bus via 0x06
/// alone is not validated (hardware-dependent), so decline.
#[test]
fn declines_08_firmware_without_sending_a_set() {
    let flags = [0xFF, 0xFF, 0x01, 0x01, 0xFF, 0xFF, 0xFF];
    let mut t = MockTransport::always(Reply::good(identity_payload("0.8.3", &flags)));
    assert!(unlock(&mut t).expect("no fault").is_none());
    assert_eq!(t.calls(), 1, "only the IDENTITY probe");
}

// ── Feature sets ──────────────────────────────────────────────────────

#[test]
fn set_drive_rejection_is_not_applicable() {
    for reply in [Reply::illegal_request(), Reply::illegal_request_as_err()] {
        let mut t = MockTransport::always(reply.clone());
        let err = FreemkvUnlocker::new()
            .set(&mut t, Feature::Encryption, STATE_OFF)
            .unwrap_err();
        assert_eq!(err, UnlockError::NotApplicable, "{reply:?}");
    }
}

#[test]
fn set_transport_fault_propagates() {
    let mut t = MockTransport::always(Reply::TransportFault);
    let err = FreemkvUnlocker::new()
        .set(&mut t, Feature::Speed, SPEED_MAX)
        .unwrap_err();
    assert_eq!(err, UnlockError::Transport);
}

// ── full_unlock / unlock ─────────────────────────────────────────────

/// The full unlock runs IDENTITY → Set(Region) → Set(Speed) →
/// Set(Unrestricted) → Set(Encryption) → bare VID, with the exact wire
/// bytes for every vendor SET.
#[test]
fn full_unlock_issues_identity_region_speed_unrestricted_encryption_then_bare_vid() {
    let vid = [0x7Cu8; 16];
    let mut t = MockTransport::scripted(
        vec![
            Reply::good(freemkv_identity_payload()), // IDENTITY
            Reply::good(vec![]),                     // Set Region
            Reply::good(vec![]),                     // Set Speed
            Reply::good(vec![]),                     // Set Unrestricted
            Reply::good(vec![]),                     // Set Encryption (load-bearing)
            Reply::good(vid_ds_response(vid)),       // 0xAD bare VID
        ],
        Reply::TransportFault,
    );
    let out = unlock(&mut t)
        .expect("no fault")
        .expect("encryption off ⇒ unlocked");
    assert_eq!(out.vid, Some(vid));
    assert_eq!(out.bus_key, None);
    assert_eq!(t.cdbs.len(), 6);
    assert_eq!(t.cdbs[0], build_identity_cdb(RESP_LEN as u16));
    let set = |f: u8, s: u8| vec![0x3C, 0x0E, 0xC0, 0xDE, 0x02, f, s, 0x00, 0x40, 0x00];
    assert_eq!(t.cdbs[1], set(0x02, 0x0F), "Region = free");
    assert_eq!(t.cdbs[2], set(0x01, 0x00), "Speed = max");
    assert_eq!(t.cdbs[3], set(0x03, 0x01), "Unrestricted = on");
    assert_eq!(t.cdbs[4], set(0x06, 0x00), "Encryption = off");
    assert_eq!(t.cdbs[5][0], crate::scsi::SCSI_READ_DISC_STRUCTURE);
}

/// Missing region/speed/unrestricted features do not fail the unlock
/// (best-effort), whichever rejection shape the transport uses.
#[test]
fn full_unlock_tolerates_missing_best_effort_features() {
    let vid = [0x3Cu8; 16];
    for reject in [Reply::illegal_request(), Reply::illegal_request_as_err()] {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()),
                reject.clone(), // region
                reject.clone(), // speed
                reject.clone(), // unrestricted
                Reply::good(vec![]),
                Reply::good(vid_ds_response(vid)),
            ],
            Reply::TransportFault,
        );
        let out = unlock(&mut t).expect("no fault").expect("unlocked");
        assert_eq!(out.vid, Some(vid), "{reject:?}");
    }
}

/// Set(Encryption, off) is LOAD-BEARING: if the drive rejects it (either
/// shape), `unlock()` declines (`None`) and falls through.
#[test]
fn declines_when_disable_encryption_rejected() {
    for reject in [Reply::illegal_request(), Reply::illegal_request_as_err()] {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(freemkv_identity_payload()),
                Reply::good(vec![]),
                Reply::good(vec![]),
                Reply::good(vec![]),
                reject.clone(), // Set(Encryption,off) REJECTED
            ],
            Reply::TransportFault,
        );
        assert!(unlock(&mut t).expect("no fault").is_none(), "{reject:?}");
        assert_eq!(t.calls(), 5, "no VID read after the refusal");
    }
}

/// A dead bus at ANY step after IDENTITY aborts with `Transport` (never a
/// fall-through): each best-effort SET, the load-bearing SET, the VID read.
#[test]
fn dead_bus_after_identity_aborts_at_every_step() {
    for good_before_fault in 0..5 {
        let mut script = vec![Reply::good(freemkv_identity_payload())];
        script.extend(std::iter::repeat_n(Reply::good(vec![]), good_before_fault));
        let mut t = MockTransport::scripted(script, Reply::TransportFault);
        assert_eq!(
            unlock(&mut t).unwrap_err(),
            UnlockError::Transport,
            "fault after {good_before_fault} SETs"
        );
        assert_eq!(t.calls(), good_before_fault + 2, "aborted at the fault");
    }
}

/// Best-effort VID: Set(Encryption,off) succeeded (drive unlocked), but the
/// bare VID read was rejected — `unlock()` still returns `Some`, with
/// `vid: None`.
#[test]
fn unlocks_without_vid_when_bare_read_fails() {
    let mut t = MockTransport::scripted(
        vec![
            Reply::good(freemkv_identity_payload()),
            Reply::good(vec![]),
            Reply::good(vec![]),
            Reply::good(vec![]),
            Reply::good(vec![]),      // Set(Encryption,off)
            Reply::illegal_request(), // bare VID: no medium
        ],
        Reply::TransportFault,
    );
    let out = unlock(&mut t)
        .expect("no fault")
        .expect("unlocked despite no VID");
    assert_eq!(out.vid, None);
}

#[test]
fn declines_non_freemkv_drive() {
    let mut t = MockTransport::always(Reply::illegal_request());
    assert!(unlock(&mut t).expect("no fault").is_none());
}

#[test]
fn transport_fault_propagates() {
    let mut t = MockTransport::always(Reply::TransportFault);
    assert_eq!(unlock(&mut t).unwrap_err(), UnlockError::Transport);
}

// ── DumpAll ──────────────────────────────────────────────────────────

#[test]
fn dump_ram_builds_memread_cdb_and_returns_the_window() {
    let mut payload = vec![0xABu8; MEMREAD_LEN];
    payload[0] = 0xEE;
    let mut t = MockTransport::always(Reply::good(payload));
    let got = FreemkvUnlocker::new()
        .dump_ram(&mut t, 0x01F8_1234)
        .expect("dump ok");
    assert_eq!(got[0], 0xEE);
    assert_eq!(t.cdbs[0], build_memread_cdb(0x01F8_1234).to_vec());
}

/// A GOOD-status short DUMPALL is not a zero-padded RAM window.
#[test]
fn dump_ram_rejects_a_short_transfer() {
    let mut t = MockTransport::always(Reply::short(vec![0xAB; MEMREAD_LEN], MEMREAD_LEN - 1));
    assert_eq!(
        FreemkvUnlocker::new().dump_ram(&mut t, 0).unwrap_err(),
        UnlockError::NotApplicable
    );
}

#[test]
fn name_is_freemkv() {
    assert_eq!(FreemkvUnlocker::new().name(), "freemkv");
}
