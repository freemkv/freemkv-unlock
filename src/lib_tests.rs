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
