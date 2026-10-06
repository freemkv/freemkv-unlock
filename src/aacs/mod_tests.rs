use super::*;

/// AES-128-ECB decrypt against the FIPS-197 Appendix B / NIST known-answer
/// test vector: decrypting the published ciphertext with the published key
/// must recover the published plaintext.
#[test]
fn aes_ecb_decrypt_matches_fips197_test_vector() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let ciphertext: [u8; 16] = [
        0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5,
        0x5A,
    ];
    let expected_plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
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

/// A freemkv fw front-end: answers the vendor knock (IDENTITY / SET / GET)
/// like fw `version` does, and delegates every other CDB to `inner`.
struct FwFront<T> {
    inner: T,
    version: &'static str,
    /// Feature flag table indexed by wire id (slot 0 unused).
    flags: [u8; 7],
    refuse_sets: bool,
    dead_after_identity: bool,
    cdbs: Vec<Vec<u8>>,
}

impl<T> FwFront<T> {
    fn new(inner: T) -> Self {
        FwFront {
            inner,
            version: "0.9.2",
            flags: [crate::firmware::STATE_PASSTHROUGH; 7],
            refuse_sets: false,
            dead_after_identity: false,
            cdbs: Vec::new(),
        }
    }
    /// Whether any cert-AKE command (REPORT KEY / SEND KEY) was issued.
    fn ran_cert_ake(&self) -> bool {
        self.cdbs
            .iter()
            .any(|c| c[0] == crate::scsi::SCSI_REPORT_KEY || c[0] == crate::scsi::SCSI_SEND_KEY)
    }
    fn sent_a_set(&self) -> bool {
        use crate::firmware::{CDB_VERB, READ_BUFFER_OPCODE, Verb};
        self.cdbs
            .iter()
            .any(|c| c[0] == READ_BUFFER_OPCODE && c[CDB_VERB] == Verb::Set as u8)
    }
}

impl<T: ScsiTransport> ScsiTransport for FwFront<T> {
    fn execute(
        &mut self,
        cdb: &[u8],
        dir: crate::scsi::DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
        use crate::firmware::{CDB_FEATURE, CDB_STATE, CDB_VERB, READ_BUFFER_OPCODE, Verb};
        self.cdbs.push(cdb.to_vec());
        if cdb[0] != READ_BUFFER_OPCODE {
            return self.inner.execute(cdb, dir, data, timeout_ms);
        }
        let status = |status: u8, n: usize| {
            Ok(crate::scsi::ScsiResult {
                status,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        };
        let verb = cdb[CDB_VERB];
        let f = (cdb[CDB_FEATURE] as usize).min(6);
        if verb == Verb::Identity as u8 {
            let mut flags = [0u8; 6];
            flags.copy_from_slice(&self.flags[1..]);
            let mut p = crate::firmware::identity_reply(self.version, flags);
            p.resize(data.len(), 0);
            data.copy_from_slice(&p[..data.len()]);
            return status(0, data.len());
        }
        if self.dead_after_identity {
            return Err(crate::scsi::ScsiError {
                status: crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                sense: None,
            });
        }
        if verb == Verb::Set as u8 {
            if self.refuse_sets {
                return status(crate::scsi::SCSI_STATUS_CHECK_CONDITION, 0);
            }
            self.flags[f] = cdb[CDB_STATE];
        } else if verb == Verb::Get as u8 {
            data.fill(0);
            data[0] = self.flags[f];
        }
        status(0, data.len())
    }
    // Forward the Stop methods (stop-design-v5 §2.3): the defaults would
    // swallow them, so wrapped tests would stop exercising cancellation.
    fn pause(&mut self, d: std::time::Duration) -> crate::scsi::Result<()> {
        self.inner.pause(d)
    }
    fn begin_critical(&mut self) -> crate::scsi::Result<()> {
        self.inner.begin_critical()
    }
    fn end_critical(&mut self) {
        self.inner.end_critical()
    }
    fn execute_cleanup(
        &mut self,
        cdb: &[u8],
        dir: crate::scsi::DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
        self.cdbs.push(cdb.to_vec());
        self.inner.execute_cleanup(cdb, dir, data, timeout_ms)
    }
}

// UT6 (stop-design-v5 §5.2; §2.3 "The test-only `FwFront<T>` … forwards all
// four"): otherwise every FwFront-wrapped test silently stops exercising Stop.
#[test]
fn fwfront_forwards_new_methods() {
    use crate::scsi::DataDirection;
    use crate::scsi::mock::{Ev, MockTransport, Reply, StopFake};
    let inner = StopFake::new(MockTransport::always(Reply::good(vec![0u8; 2])));
    let mut t = FwFront::new(inner);
    let d = std::time::Duration::from_millis(1);
    t.pause(d).expect("forwarded pause");
    t.begin_critical().expect("forwarded begin");
    t.end_critical();
    let rel = [0xA4, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0x3F, 0];
    t.execute_cleanup(&rel, DataDirection::FromDevice, &mut [0u8; 2], 5_000)
        .expect("forwarded cleanup");
    assert_eq!(
        t.inner.log,
        vec![Ev::Pause(d), Ev::Begin, Ev::End, Ev::Cleanup(rel.to_vec())],
        "all four reach the wrapped transport"
    );
    t.inner.cancelled = true;
    assert!(t.pause(d).is_err(), "a cancel reaches through the wrapper");
    assert!(t.begin_critical().is_err());
}

fn vid_reply(vid: [u8; 16]) -> crate::scsi::mock::MockTransport {
    use crate::scsi::mock::{MockTransport, Reply};
    let mut p = vec![0u8; 36];
    p[4..20].copy_from_slice(&vid);
    MockTransport::always(Reply::good(p))
}

fn aacs_ctx(id: &crate::DriveId) -> UnlockCtx<'_> {
    UnlockCtx::new(id, DiscKind::Aacs)
}

/// Opting in on a freemkv drive applies the recipe: BypassBd sends
/// Set(Hrl, off) and Set(Encryption, off), each verified, after the
/// IDENTITY gate and BEFORE the handshake would run.
#[test]
fn arm_on_freemkv_drive_applies_the_recipe() {
    use crate::firmware::{CDB_VERB, Feature, STATE_OFF, Verb, build_set_cdb};
    let mut t = FwFront::new(vid_reply([0x42; 16]));
    let u = AacsUnlocker::new(vec![host_cert()]).arm_before_unlock(ArmRecipe::BypassBd);
    assert!(u.maybe_arm(&mut t).expect("armed"));
    assert_eq!(t.flags[Feature::Hrl as usize], STATE_OFF);
    assert_eq!(t.flags[Feature::Encryption as usize], STATE_OFF);
    assert_eq!(t.cdbs.len(), 5);
    assert_eq!(t.cdbs[0][CDB_VERB], Verb::Identity as u8);
    assert_eq!(t.cdbs[1], build_set_cdb(Feature::Hrl, STATE_OFF));
    assert_eq!(t.cdbs[2][CDB_VERB], Verb::Get as u8);
    assert_eq!(t.cdbs[3], build_set_cdb(Feature::Encryption, STATE_OFF));
    assert_eq!(t.cdbs[4][CDB_VERB], Verb::Get as u8);
}

/// Regression: an Encryption=off recipe needs NO host cert. With an empty
/// cert list the drive is still armed and the unlock is the bare VID read —
/// no cert AKE, no bus key (content already comes back de-bussed).
#[test]
fn encryption_off_recipes_unlock_without_certs_via_the_bare_vid() {
    for recipe in [ArmRecipe::BypassBd, ArmRecipe::BypassUhd, ArmRecipe::OemUhd] {
        let mut t = FwFront::new(vid_reply([0x42; 16]));
        let id = id();
        let out = AacsUnlocker::new(vec![])
            .arm_before_unlock(recipe)
            .unlock(&mut t, &aacs_ctx(&id))
            .expect("no fault")
            .unwrap_or_else(|| panic!("{recipe:?}: armed drive is unlocked"));
        assert_eq!(out.vid, Some([0x42; 16]), "{recipe:?}");
        assert_eq!(out.bus_key, None, "{recipe:?}: no double bus-decrypt");
        assert!(!t.ran_cert_ake(), "{recipe:?}");
    }
}

/// Armed Encryption=off, then the bare VID read: a dead bus there aborts
/// with Transport; a drive rejection is still an unlock, just without a VID.
#[test]
fn encryption_off_arm_then_bare_vid_failure() {
    use crate::scsi::mock::{MockTransport, Reply};
    for (reply, want) in [
        (Reply::TransportFault, Err(UnlockError::Transport)),
        (Reply::illegal_request(), Ok(Some((None, None)))),
        (Reply::illegal_request_as_err(), Ok(Some((None, None)))),
    ] {
        let mut t = FwFront::new(MockTransport::always(reply));
        let id = id();
        let got = AacsUnlocker::new(vec![host_cert()])
            .arm_before_unlock(ArmRecipe::BypassBd)
            .unlock(&mut t, &aacs_ctx(&id))
            .map(|o| o.map(|u| (u.vid, u.bus_key)));
        assert_eq!(got, want);
        assert!(t.sent_a_set(), "the drive was armed first");
        assert!(!t.ran_cert_ake());
    }
}

/// Regression: with certs present, an Encryption=off arm still skips the
/// cert AKE and never reports a bus key.
#[test]
fn encryption_off_recipe_with_certs_skips_the_cert_ake() {
    let mut t = FwFront::new(vid_reply([0x42; 16]));
    let id = id();
    let out = AacsUnlocker::new(vec![host_cert()])
        .arm_before_unlock(ArmRecipe::BypassBd)
        .unlock(&mut t, &aacs_ctx(&id))
        .expect("no fault")
        .expect("unlocked");
    assert_eq!(out.bus_key, None);
    assert!(!t.ran_cert_ake());
}

/// A refused recipe (and OemBd, which leaves encryption on) proceeds to the
/// plain cert AKE, which still unlocks the drive and learns the bus key.
#[test]
fn refused_or_cert_recipes_run_the_cert_ake() {
    for (recipe, refuse) in [(ArmRecipe::BypassBd, true), (ArmRecipe::OemBd, false)] {
        let mut emu = handshake::tests::DriveEmu::new();
        emu.serve_data_keys = true;
        let (lax, lay) = (emu.la_x, emu.la_y);
        let mut t = FwFront::new(emu);
        t.refuse_sets = refuse;
        let id = id();
        let out = AacsUnlocker::new(vec![host_cert()])
            .with_test_v1_anchor(lax, lay)
            .arm_before_unlock(recipe)
            .unlock(&mut t, &aacs_ctx(&id))
            .expect("no fault")
            .expect("the cert route unlocks");
        assert_eq!(out.vid, Some([0x5Au8; 16]), "{recipe:?}");
        assert!(out.bus_key.is_some(), "{recipe:?}");
        assert!(t.ran_cert_ake(), "{recipe:?}");
    }
}

/// Regression: fw 0.8.x is below MIN_FW_VERSION, so the recipe is never
/// sent and the plain cert route runs.
#[test]
fn unsupported_firmware_is_not_armed() {
    let mut emu = handshake::tests::DriveEmu::new();
    emu.serve_data_keys = true;
    let (lax, lay) = (emu.la_x, emu.la_y);
    let mut t = FwFront::new(emu);
    t.version = "0.8.3";
    let id = id();
    let out = AacsUnlocker::new(vec![host_cert()])
        .with_test_v1_anchor(lax, lay)
        .arm_before_unlock(ArmRecipe::BypassBd)
        .unlock(&mut t, &aacs_ctx(&id))
        .expect("no fault")
        .expect("the cert route unlocks");
    assert!(out.bus_key.is_some());
    assert!(!t.sent_a_set(), "no recipe SET on unsupported firmware");
}

/// A dead bus mid-arm aborts the whole unlock, with or without certs.
#[test]
fn dead_bus_during_arm_aborts_the_unlock() {
    for certs in [vec![host_cert()], vec![]] {
        let mut t = FwFront::new(vid_reply([0x42; 16]));
        t.dead_after_identity = true;
        let id = id();
        let n = certs.len();
        let err = AacsUnlocker::new(certs)
            .arm_before_unlock(ArmRecipe::BypassBd)
            .unlock(&mut t, &aacs_ctx(&id))
            .unwrap_err();
        assert_eq!(err, UnlockError::Transport, "{n} certs");
        assert!(!t.ran_cert_ake());
    }
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
