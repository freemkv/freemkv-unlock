use super::*;
use crate::DiscKind;
use crate::scsi::{DataDirection, ScsiResult, ScsiTransport};

/// Unlock context for a fake drive id (kind/host-certs irrelevant to the
/// firmware unlocker — it keys off the drive identity).
fn ctx(id: &DriveId) -> UnlockCtx<'_> {
    UnlockCtx::new(id, DiscKind::Unknown)
}

/// A fake transport that fills the response buffer from a fixed payload and
/// reports a configurable transferred-byte count.
struct FakeTransport {
    payload: Vec<u8>,
    bytes_transferred: usize,
}
impl ScsiTransport for FakeTransport {
    fn execute(
        &mut self,
        _cdb: &[u8],
        _dir: DataDirection,
        data: &mut [u8],
        _timeout_ms: u32,
    ) -> crate::scsi::Result<ScsiResult> {
        let n = self.payload.len().min(data.len());
        data[..n].copy_from_slice(&self.payload[..n]);
        Ok(ScsiResult {
            status: 0,
            bytes_transferred: self.bytes_transferred,
            sense: [0u8; 32],
        })
    }
}

/// A DriveId for the bundled HL-DT-ST profile that carries a real
/// `read_vid_cdb`, so `read_oem_vid` finds a profile and issues the CDB.
fn known_vid_drive_id() -> DriveId {
    make_drive_id("HL-DT-ST", "1.01", "NM00100", "211711202000")
}

fn make_drive_id(vendor: &str, rev: &str, vs: &str, date: &str) -> DriveId {
    DriveId {
        vendor_id: vendor.to_string(),
        product_id: String::new(),
        product_revision: rev.to_string(),
        vendor_specific: vs.to_string(),
        firmware_date: date.to_string(),
    }
}

/// The bundled profile of the fixture drive (the one carrying a real
/// `read_vid_cdb`).
fn known_vid_profile() -> profile::DriveProfile {
    let m = profile::find_bundled(&known_vid_drive_id()).expect("profile match");
    assert!(
        m.profile.read_vid_cdb.is_some(),
        "test fixture drive must carry an OEM VID CDB"
    );
    m.profile
}

/// A well-formed 36-byte response (signature 00 22 00, VID at [4..20]) parses
/// to `Some(vid)`.
#[test]
fn read_oem_vid_parses_well_formed_response() {
    let mut payload = vec![0u8; 36];
    payload[0..3].copy_from_slice(&[0x00, 0x22, 0x00]);
    let vid = [0x3Cu8; 16];
    payload[4..20].copy_from_slice(&vid);
    let mut t = FakeTransport {
        payload,
        bytes_transferred: 36,
    };
    let got = LdUnlocker::new()
        .read_oem_vid(&mut t, &known_vid_profile())
        .expect("parse ok");
    assert_eq!(got, Some(vid), "VID parsed from [4..20]");
}

/// A short response → `Ok(None)` (drive unlocked, just no readable VID).
#[test]
fn read_oem_vid_short_response_is_none() {
    let mut t = FakeTransport {
        payload: vec![0u8; 36],
        bytes_transferred: 20,
    };
    let got = LdUnlocker::new()
        .read_oem_vid(&mut t, &known_vid_profile())
        .expect("short response is Ok(None)");
    assert_eq!(got, None);
}

/// A response whose 3-byte signature isn't `00 22 00` → `Ok(None)`.
#[test]
fn read_oem_vid_bad_header_is_none() {
    let mut payload = vec![0u8; 36];
    payload[0..3].copy_from_slice(&[0xDE, 0xAD, 0xBE]);
    let mut t = FakeTransport {
        payload,
        bytes_transferred: 36,
    };
    let got = LdUnlocker::new()
        .read_oem_vid(&mut t, &known_vid_profile())
        .expect("bad header is Ok(None)");
    assert_eq!(got, None);
}

/// Catches dropping the `result.status` check: a CHECK CONDITION arrives as
/// `Ok` per the transport contract, so without it the caller's zero-filled
/// buffer is parsed as a real 36-byte response.
#[test]
fn read_oem_vid_check_condition_is_none_not_a_vid() {
    use crate::scsi::mock::{MockTransport, Reply};
    let mut t = MockTransport::always(Reply::illegal_request());
    let got = LdUnlocker::new()
        .read_oem_vid(&mut t, &known_vid_profile())
        .expect("a drive sense is not a transport fault");
    assert_eq!(got, None, "a CHECK CONDITION must never yield a VID");
}

/// Catches swallowing a transport fault in the OEM-VID read: a dead bus must
/// propagate (→ `UnlockError::Transport`), never become `Ok(None)`.
#[test]
fn read_oem_vid_transport_fault_propagates() {
    use crate::scsi::mock::{MockTransport, Reply};
    let mut t = MockTransport::always(Reply::TransportFault);
    let err = LdUnlocker::new()
        .read_oem_vid(&mut t, &known_vid_profile())
        .expect_err("a dead bus must not be Ok(None)");
    assert!(err.is_transport_failure());
    assert_eq!(UnlockError::from(err), UnlockError::Transport);
}

/// A profile with no OEM-VID CDB → `Ok(None)` without touching the drive.
#[test]
fn read_oem_vid_no_cdb_is_none() {
    let mut p = known_vid_profile();
    p.read_vid_cdb = None;
    let mut t = FakeTransport {
        payload: vec![0u8; 36],
        bytes_transferred: 36,
    };
    let got = LdUnlocker::new()
        .read_oem_vid(&mut t, &p)
        .expect("no CDB is Ok(None)");
    assert_eq!(got, None);
}

/// Public catalog accessors: `profiles()` returns the bundled catalog and
/// `profile()` is `profiles().and_then(get)` for a known drive.
#[test]
fn public_catalog_accessors_find_the_bundled_fixture_drive() {
    assert!(super::profiles().is_some(), "bundled catalog must parse");
    let m = super::profile(&known_vid_drive_id()).expect("known fixture drive matches");
    assert!(m.profile.read_vid_cdb.is_some());
}

/// `unlock_features` on a drive with no matching profile → `NotApplicable`
/// (fall through), short-circuiting before any firmware handshake.
#[test]
fn unlock_no_profile_is_not_applicable() {
    let mut t = FakeTransport {
        payload: vec![0u8; 36],
        bytes_transferred: 36,
    };
    let unlocked = LdUnlocker::new()
        .unlock(
            &mut t,
            &ctx(&make_drive_id("FAKE-VND", "9.99", "XX12345", "")),
        )
        .expect("no profile → declines, not a hard error");
    assert!(unlocked.is_none());
}

// THE defect-1 test: response carries the signature + primary marker but not
// the secondary one, so init() succeeds but the drive isn't in extended-access
// state. Catches removing the `is_unlocked()` gate in `firmware_unlock`.
#[test]
fn half_unlocked_drive_falls_through_instead_of_claiming_unlocked() {
    use crate::scsi::mock::{MockTransport, Reply};
    let id = known_vid_drive_id();
    let sig = profile::find_bundled(&id)
        .expect("profile")
        .profile
        .signature;

    // 64-byte unlock response: signature + primary marker "MMkv" at [12..16],
    // secondary marker at [16..20] left zeroed.
    let mut resp = vec![0u8; 64];
    resp[0..4].copy_from_slice(&sig);
    resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]);

    let mut t = MockTransport::always(Reply::good(resp));
    let unlocked = LdUnlocker::new()
        .unlock(&mut t, &ctx(&id))
        .expect("a half-unlock declines, not a hard error");
    assert!(
        unlocked.is_none(),
        "a half-unlocked drive must fall through to cert-auth"
    );
}

/// The whole-unlock happy path still reports unlocked when BOTH firmware
/// markers are present — the `is_unlocked()` gate must not have made a
/// genuinely unlocked drive fall through.
#[test]
fn fully_unlocked_drive_reports_unlocked() {
    use crate::scsi::mock::{MockTransport, Reply};
    let id = known_vid_drive_id();
    let sig = profile::find_bundled(&id)
        .expect("profile")
        .profile
        .signature;

    let mut resp = vec![0u8; 64];
    resp[0..4].copy_from_slice(&sig);
    resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]);
    resp[16..20].copy_from_slice(&[0x4C, 0x62, 0x44, 0x72]);

    let mut t = MockTransport::always(Reply::good(resp));
    assert!(
        LdUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("no fault")
            .is_some(),
        "both markers → unlocked"
    );
}

// THE probe-disc dead-bus test: bus dies during speed calibration after a
// full unlock; must abort with Transport, not report a successful unlock.
#[test]
fn transport_fault_during_probe_disc_is_transport_not_a_successful_unlock() {
    let id = known_vid_drive_id();
    let sig = profile::find_bundled(&id)
        .expect("profile")
        .profile
        .signature;

    // A drive that unlocks fully but whose bus dies on the speed probe.
    struct ProbeFaultsDrive {
        resp: Vec<u8>,
    }
    impl ScsiTransport for ProbeFaultsDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            // READ_BUFFER (0x3C) / SUB_CMD_PROBE (0x14) is the speed probe.
            if cdb.first() == Some(&0x3C) && cdb.get(3) == Some(&0x14) {
                return Err(crate::scsi::ScsiError {
                    status: crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                    sense: None,
                });
            }
            let n = self.resp.len().min(data.len());
            data[..n].copy_from_slice(&self.resp[..n]);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }

    let mut resp = vec![0u8; 64];
    resp[0..4].copy_from_slice(&sig);
    resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]); // primary marker
    resp[16..20].copy_from_slice(&[0x4C, 0x62, 0x44, 0x72]); // secondary marker
    let mut t = ProbeFaultsDrive { resp };

    let err = LdUnlocker::new()
        .unlock(&mut t, &ctx(&id))
        .expect_err("a dead bus during probe must abort, not report success");
    assert_eq!(err, UnlockError::Transport);
}

// A drive-sense (not a dead bus) rejecting the speed probe is a genuine
// calibration miss: warn-and-continue on the default speed table, still
// reporting a full unlock. Non-transport sibling of the probe-fault test.
#[test]
fn drive_sense_during_probe_disc_still_reports_a_successful_unlock() {
    let id = known_vid_drive_id();
    let sig = profile::find_bundled(&id)
        .expect("profile")
        .profile
        .signature;

    let mut resp = vec![0u8; 64];
    resp[0..4].copy_from_slice(&sig);
    resp[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]); // primary marker
    resp[16..20].copy_from_slice(&[0x4C, 0x62, 0x44, 0x72]); // secondary marker

    struct ProbeSenseDrive {
        resp: Vec<u8>,
    }
    impl ScsiTransport for ProbeSenseDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            // READ_BUFFER (0x3C) / SUB_CMD_PROBE (0x14) is the speed probe.
            if cdb.first() == Some(&0x3C) && cdb.get(3) == Some(&0x14) {
                return Ok(ScsiResult {
                    status: 0x02,
                    bytes_transferred: 0,
                    sense: [0u8; 32],
                });
            }
            let n = self.resp.len().min(data.len());
            data[..n].copy_from_slice(&self.resp[..n]);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }
    let mut t = ProbeSenseDrive { resp };
    assert!(
        LdUnlocker::new()
            .unlock(&mut t, &ctx(&id))
            .expect("a calibration miss must not fail the whole unlock")
            .is_some()
    );
}

/// Catches classifying a dead bus as "not this unlocker's drive": the very
/// first unlock command faulting at the transport layer must abort the
/// consumer (`Transport`), not fall through to the next unlocker.
// Review of ST-D10: after a confirmed firmware upload, a drive whose media never
// becomes ready (the same 02/04/01 for 60 s, T6) must still report the unlock,
// and probe_disc + the VID read must still run (not `NotApplicable`).
#[test]
fn readiness_stall_after_upload_keeps_the_unlock() {
    use crate::scsi::{DataDirection, ScsiResult};
    use platform::mt1959::tests::{FakeClock, TEST_READY_CLOCK};
    struct UploadThenNotReady {
        sig: [u8; 4],
        unlock_calls: usize,
        cdbs: Vec<Vec<u8>>,
    }
    impl ScsiTransport for UploadThenNotReady {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            self.cdbs.push(cdb.to_vec());
            let unlock = cdb[0] == 0x3C && matches!(cdb[2], 0x44 | 0x77) && cdb[3] == 0;
            let (status, n) = if cdb[0] == 0x00 {
                let mut sense = [0u8; 32];
                (sense[2], sense[12], sense[13]) = (0x02, 0x04, 0x01);
                return Ok(ScsiResult {
                    status: 0x02,
                    bytes_transferred: 0,
                    sense,
                });
            } else if unlock && cdb[8] == 64 {
                self.unlock_calls += 1;
                data.fill(0);
                data[0..4].copy_from_slice(&self.sig);
                data[12..16].copy_from_slice(&[0x4D, 0x4D, 0x6B, 0x76]);
                data[16..20].copy_from_slice(&[0x4C, 0x62, 0x44, 0x72]);
                // The first unlock fails short, forcing the firmware upload.
                (0, if self.unlock_calls == 1 { 10 } else { 64 })
            } else {
                data.fill(0);
                (0, data.len())
            };
            Ok(ScsiResult {
                status,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }
    let id = known_vid_drive_id();
    let sig = profile::find_bundled(&id)
        .expect("profile")
        .profile
        .signature;
    let mut t = UploadThenNotReady {
        sig,
        unlock_calls: 0,
        cdbs: Vec::new(),
    };
    TEST_READY_CLOCK.set(Some(|| Box::new(FakeClock::new())));
    let r = LdUnlocker::new().unlock(&mut t, &ctx(&id));
    TEST_READY_CLOCK.set(None);
    let unlocked = r.expect("no fault");
    assert!(
        unlocked.is_some(),
        "the confirmed unlock stands despite the stall"
    );
    let uploaded = t.cdbs.iter().any(|c| matches!(c[0], 0x3B | 0x55));
    assert!(uploaded, "the firmware upload ran");
    let last_tur = t
        .cdbs
        .iter()
        .rposition(|c| c[0] == 0x00)
        .expect("polled TUR");
    let turs = t.cdbs.iter().filter(|c| c[0] == 0x00).count();
    assert_eq!(turs, 121, "polled until the 60 s stall (virtual clock)");
    let capacity = t
        .cdbs
        .iter()
        .rposition(|c| c[0] == 0x25)
        .expect("probe_disc ran");
    assert!(capacity > last_tur, "probe_disc runs after the poll");
}

#[test]
fn transport_fault_during_unlock_is_transport_not_not_applicable() {
    use crate::scsi::mock::{MockTransport, Reply};
    let mut t = MockTransport::always(Reply::TransportFault);
    let err = LdUnlocker::new()
        .unlock(&mut t, &ctx(&known_vid_drive_id()))
        .expect_err("dead bus");
    assert_eq!(err, UnlockError::Transport);
}
