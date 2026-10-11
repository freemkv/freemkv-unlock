use super::*;

// The canonical dispatch order the consumer assembles (freemkv → LD → cert → css). It lives in the consumer now (no factory), but the
// types are ours, so pin their names here so a rename is caught crate-local.
fn canonical_unlockers() -> Vec<Box<dyn Unlocker>> {
    vec![
        Box::new(FreemkvUnlocker::new()),
        Box::new(LdUnlocker::new()),
        Box::new(AacsUnlocker::new(Vec::new())),
        Box::new(DvdUnlocker::new()),
    ]
}

#[test]
fn unlocker_names_are_stable() {
    let names: Vec<&'static str> = canonical_unlockers().iter().map(|u| u.name()).collect();
    assert_eq!(names, vec!["freemkv", "LD", "AACS", "DVD"]);
}

/// The uniform contract every unlocker obeys, whatever its mechanism: on a
/// DEAD BUS, `unlock()` either declined before touching it (`Ok(false)`) or
/// engaged it and reported the fault (`Err(Transport)`) — but NEVER claims a
/// dead bus as unlocked, and NEVER surfaces a non-`Transport` hard error.
/// This is the guardrail that was missing: it holds the next new unlocker to
/// the same discipline the loop relies on.
#[test]
fn no_unlocker_claims_a_dead_bus_or_hard_errors() {
    let id = DriveId::default();
    let ctx = UnlockCtx::new(&id, DiscKind::Aacs);
    for u in canonical_unlockers() {
        let name = u.name();
        let mut t = scsi::mock::MockTransport::always(scsi::mock::Reply::TransportFault);
        match u.unlock(&mut t, &ctx) {
            Ok(None) => {}                    // declined before touching — fine
            Err(UnlockError::Transport) => {} // engaged, dead bus — fine
            other => panic!("{name} violated the dead-bus contract: {other:?}"),
        }
    }
}

/// `unlocker_name` is a PURE lookup — it must answer from the `DriveId`
/// alone, and only the identity-keyed unlocker can claim a drive this way.
#[test]
fn unlocker_name_is_a_pure_identity_lookup() {
    assert_eq!(unlocker_name(&DriveId::default()), None);
}

fn id_of(identity: &ld::Identity) -> DriveId {
    DriveId {
        vendor_id: identity.vendor_id.clone(),
        product_id: identity.product_id.clone(),
        product_revision: identity.product_revision.clone(),
        vendor_specific: identity.vendor_specific.clone(),
        firmware_date: identity.firmware_date.clone(),
    }
}

// One MT1959-A and one Renesas drive, distinct identities.
fn two_platform_catalog() -> ld::Profiles {
    let entry = |vendor: &str| {
        serde_json::json!({"identity": {"vendor_id": vendor, "product_id": "BD-RE",
            "product_revision": "1.00", "vendor_specific": "XX00000",
            "firmware_date": "200001010000"}, "signature": "aaaaaaaa", "firmware": ""})
    };
    serde_json::from_value(serde_json::json!({
        "mt1959_a": [entry("MTK")], "renesas": [entry("PIONEER")]
    }))
    .unwrap()
}

/// A bundled MT1959 drive is claimed by LD alone, and reported as "LD".
#[test]
fn bundled_mt1959_drive_is_claimed_by_ld_only() {
    let catalog = ld::profiles().expect("bundled catalog parses");
    for identity in [&catalog.mt1959_a[0].identity, &catalog.mt1959_b[0].identity] {
        let id = id_of(identity);
        assert!(LdUnlocker::new().claims(&id));
        assert!(!FreemkvUnlocker::new().claims(&id));
        assert_eq!(unlocker_name(&id), Some("LD"));
    }
}

/// The Renesas section belongs to freemkv, never LD: the "LD" label for a
/// Renesas drive was the bug. Each catalogued drive has exactly one claimant.
#[test]
fn renesas_profile_is_claimed_by_freemkv_not_ld() {
    let catalog = two_platform_catalog();
    let [mtk, renesas] = [&catalog.mt1959_a[0], &catalog.renesas[0]].map(|p| id_of(&p.identity));
    let fm = FreemkvUnlocker::new();
    assert!(fm.claims_in(Some(&catalog), &renesas));
    assert!(!LdUnlocker::claims_in(&catalog, &renesas));
    assert!(LdUnlocker::claims_in(&catalog, &mtk));
    assert!(!fm.claims_in(Some(&catalog), &mtk));
    assert!(!fm.claims_in(Some(&catalog), &DriveId::default()));
    assert!(!LdUnlocker::claims_in(&catalog, &DriveId::default()));
}

/// Disc-keyed unlockers claim no drive, whatever its identity.
#[test]
fn disc_keyed_unlockers_claim_no_drive() {
    let catalog = ld::profiles().expect("bundled catalog parses");
    let id = id_of(&catalog.mt1959_a[0].identity);
    assert!(!AacsUnlocker::new(Vec::new()).claims(&id));
    assert!(!DvdUnlocker::new().claims(&id));
}

/// A configured MediaTek live loader makes freemkv claim the drives it
/// recognises, even with no catalog.
#[test]
fn freemkv_claims_what_its_mediatek_loader_recognises() {
    struct Loader;
    impl freemkv::mediatek::LiveLoader for Loader {
        fn is_mediatek(&self, drive: &DriveId) -> bool {
            drive.vendor_id == "MTK"
        }
        fn load(&self, _: &mut dyn scsi::ScsiTransport) -> Result<(), UnlockError> {
            Err(UnlockError::NotApplicable)
        }
    }
    let fm = FreemkvUnlocker::new().with_mediatek_loader(Box::new(Loader));
    let mtk = DriveId {
        vendor_id: "MTK".into(),
        ..DriveId::default()
    };
    assert!(fm.claims_in(None, &mtk));
    assert!(!fm.claims_in(None, &DriveId::default()));
}

// `bus_key`/`vid` are key material; `Debug` must NOT print those bytes.
// MUTATION: restoring `#[derive(Debug)]` prints the raw byte arrays, so
// the marker bytes appear in the output and this test goes red.
#[test]
fn unlocked_debug_redacts_key_material() {
    let u = Unlocked {
        vid: Some([0xAB; 16]),
        bus_key: Some([0xCD; 16]),
    };
    let s = format!("{u:?}");
    // A derived Debug renders `[171, 171, ...]` (0xAB) / `[205, ...]` (0xCD).
    assert!(!s.contains("171"), "vid bytes must not appear: {s}");
    assert!(!s.contains("205"), "bus_key bytes must not appear: {s}");
    assert!(s.contains("[redacted]"), "must mark redaction: {s}");
    // Presence (Some/None) stays observable.
    assert!(s.contains("Some"), "must still show a key WAS present: {s}");
}

// `vid`/`bus_key` leave the crate in `Unlocked`; wipe them (and every
// clone) on drop. Fails to compile if the derive is removed.
#[test]
fn unlocked_zeroizes_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Unlocked>();
}

// `private_key`/`private_key_v2` are the raw host private keys; `Debug` must
// NOT print those bytes. Restoring `#[derive(Debug)]` renders the byte
// arrays (e.g. 0xAB → 171 / 0xCD → 205), turning this test red.
#[test]
fn host_cert_debug_redacts_private_keys() {
    let c = HostCert {
        private_key: [0xAB; 20],
        certificate: vec![0x01, 0x02],
        private_key_v2: Some([0xCD; 32]),
        certificate_v2: None,
    };
    let s = format!("{c:?}");
    assert!(!s.contains("171"), "private_key bytes must not appear: {s}");
    assert!(
        !s.contains("205"),
        "private_key_v2 bytes must not appear: {s}"
    );
    assert!(s.contains("[redacted]"), "must mark redaction: {s}");
    // Presence of the v2 key stays observable.
    assert!(
        s.contains("Some"),
        "must still show the v2 key WAS present: {s}"
    );
}
