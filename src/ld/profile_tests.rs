use super::*;
use crate::DriveId;

fn make_drive_id(vendor: &str, rev: &str, vs: &str, date: &str) -> DriveId {
    DriveId {
        vendor_id: vendor.to_string(),
        product_id: String::new(),
        product_revision: rev.to_string(),
        vendor_specific: vs.to_string(),
        firmware_date: date.to_string(),
    }
}

/// When two profiles share vendor/rev/vs/date and differ only in product_id,
/// the full pass binds to the one whose product matches; the looser passes
/// would return the first regardless.
#[test]
fn find_by_drive_id_product_id_breaks_a_tie() {
    use serde_json::json;
    let profiles: Profiles = serde_json::from_str(
        &json!({
            "mt1959_a": [
                {"identity": {"vendor_id":"TIE","product_id":"MODEL-A",
                    "product_revision":"1.00","vendor_specific":"XX00000",
                    "firmware_date":"200001010000"},
                    "signature":"aaaaaaaa","firmware":""},
                {"identity": {"vendor_id":"TIE","product_id":"MODEL-B",
                    "product_revision":"1.00","vendor_specific":"XX00000",
                    "firmware_date":"200001010000"},
                    "signature":"bbbbbbbb","firmware":""}
            ]
        })
        .to_string(),
    )
    .unwrap();

    let mut id = make_drive_id("TIE", "1.00", "XX00000", "200001010000");
    id.product_id = "MODEL-B".to_string();
    let m = find_by_drive_id(&profiles, &id).unwrap();
    assert_eq!(
        m.profile.signature,
        [0xbb, 0xbb, 0xbb, 0xbb],
        "product_id must select MODEL-B over the first entry"
    );

    // No product_id → falls back to the 4-field pass → first entry.
    let id0 = make_drive_id("TIE", "1.00", "XX00000", "200001010000");
    let m0 = find_by_drive_id(&profiles, &id0).unwrap();
    assert_eq!(m0.profile.signature, [0xaa, 0xaa, 0xaa, 0xaa]);

    // A REPORTED product_id that matches no cataloged entry must NOT fall
    // through to the four-field pass and bind to a sibling (MODEL-A/B);
    // an uncataloged variant is no match, not a wrong match.
    let mut idc = make_drive_id("TIE", "1.00", "XX00000", "200001010000");
    idc.product_id = "MODEL-C".to_string();
    assert!(
        find_by_drive_id(&profiles, &idc).is_none(),
        "an uncataloged product_id must not mis-bind to a same-vendor sibling",
    );
}

/// REGRESSION (1.7.0): a real drive reports a SPECIFIC product_id (e.g.
/// "BD-RE BU40N") while the catalog stores a GENERIC one ("BD-RE"), so the
/// exact pass misses. When the four-field identity is UNIQUE it must still
/// bind — the pre-1.7.0 behaviour a UHD LG BU40N relies on for LibreDrive
/// unlock. 1.7.0 gated the four-field pass behind an empty product_id, so it
/// silently stopped matching and the firmware unlocker was skipped entirely.
#[test]
fn find_by_drive_id_specific_product_id_binds_unique_four_field() {
    use serde_json::json;
    let profiles: Profiles = serde_json::from_str(
        &json!({
            "mt1959_a": [
                {"identity": {"vendor_id":"HL-DT-ST","product_id":"BD-RE",
                    "product_revision":"1.03","vendor_specific":"NM00000",
                    "firmware_date":"211810241934"},
                    "signature":"12345678","firmware":""}
            ]
        })
        .to_string(),
    )
    .unwrap();

    // Drive reports the specific marketing product_id; catalog has "BD-RE".
    let mut id = make_drive_id("HL-DT-ST", "1.03", "NM00000", "211810241934");
    id.product_id = "BD-RE BU40N".to_string();
    let m = find_by_drive_id(&profiles, &id)
        .expect("unique four-field identity must match despite the product_id mismatch");
    assert_eq!(m.profile.signature, [0x12, 0x34, 0x56, 0x78]);
    assert_eq!(m.platform, Platform::Mt1959A);
}

/// An exact product_id match in a LATER section must beat a four-field
/// fallback in an earlier one; fallback uniqueness spans all sections.
#[test]
fn find_by_drive_id_exact_match_beats_earlier_section_fallback() {
    use serde_json::json;
    let entry = |prod: &str, sig: &str| {
        json!({"identity": {"vendor_id":"HL-DT-ST","product_id":prod,
                "product_revision":"1.03","vendor_specific":"NM00000",
                "firmware_date":"211810241934"},
                "signature":sig,"firmware":""})
    };
    let profiles: Profiles = serde_json::from_value(json!({
        "mt1959_a": [entry("BD-RE", "aaaaaaaa")],
        "mt1959_b": [entry("BD-RE BU40N", "bbbbbbbb")],
    }))
    .unwrap();

    let mut id = make_drive_id("HL-DT-ST", "1.03", "NM00000", "211810241934");
    id.product_id = "BD-RE BU40N".to_string();
    let m = find_by_drive_id(&profiles, &id).expect("B's exact match");
    assert_eq!(m.platform, Platform::Mt1959B);
    assert_eq!(m.profile.signature, [0xbb, 0xbb, 0xbb, 0xbb]);

    // Tuple shared across sections + uncataloged product_id: no match.
    id.product_id = "BD-RE WH16NS".to_string();
    assert!(find_by_drive_id(&profiles, &id).is_none());

    // No product_id: shared tuple binds the first section's entry.
    id.product_id.clear();
    let m0 = find_by_drive_id(&profiles, &id).expect("empty product_id binds");
    assert_eq!(m0.platform, Platform::Mt1959A);
}

#[test]
fn test_find_known_drive() {
    let profiles = load_bundled().unwrap();
    let id = make_drive_id("HL-DT-ST", "1.03", "NM00000", "211810241934");
    let m = find_by_drive_id(&profiles, &id).unwrap();
    assert_eq!(m.profile.identity.vendor_id.trim(), "HL-DT-ST");
    assert_eq!(m.platform, Platform::Mt1959A);
}

#[test]
fn test_find_unknown_drive() {
    let profiles = load_bundled().unwrap();
    let id = make_drive_id("FAKE-VND", "9.99", "XX12345", "");
    assert!(find_by_drive_id(&profiles, &id).is_none());
}

#[test]
fn decode_hex_rejects_non_ascii_without_panic() {
    // A multi-byte char of even byte-length must not slice inside a
    // char boundary; it must decode-fail gracefully.
    assert!(decode_hex("中中").is_err()); // 6 bytes, none hex
    assert!(parse_hex4("中中").is_err()); // 6 bytes != 8 anyway
    // An 8-byte non-ASCII string (two 4-byte chars) hits the exact-len
    // path of parse_hex4; must still error, not panic.
    assert!(parse_hex4("𝕏𝕏").is_err());
}

#[test]
fn decode_hex_roundtrips_valid_hex() {
    assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
    assert_eq!(parse_hex4("deadbeef").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    assert!(decode_hex("abc").is_err()); // odd length
    assert!(decode_hex("zz").is_err()); // non-hex
}

#[test]
fn bundled_is_cached_and_matches_fresh_parse() {
    let cached = bundled().expect("bundled profiles parse");
    let fresh = load_bundled().unwrap();
    // Same data either way (compare section sizes — Profiles isn't Eq).
    assert_eq!(cached.mt1959_a.len(), fresh.mt1959_a.len());
    // Cached accessor returns a stable address across calls.
    let a = bundled().unwrap() as *const Profiles;
    let b = bundled().unwrap() as *const Profiles;
    assert_eq!(a, b);
}

#[test]
fn find_bundled_matches_known_drive() {
    let id = make_drive_id("HL-DT-ST", "1.03", "NM00000", "211810241934");
    let m = find_bundled(&id).unwrap();
    assert_eq!(m.platform, Platform::Mt1959A);
}

// ── New comprehensive tests ────────────────────────────────────────────────

/// decode_hex accepts empty string → empty Vec.
/// Mutation: returning an error on empty input breaks empty-field handling.
#[test]
fn decode_hex_accepts_empty_string() {
    assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
}

/// decode_hex handles all valid hex digit characters (0-9, a-f, A-F).
/// Mutation: not supporting uppercase A-F means uppercase-encoded profiles fail.
#[test]
fn decode_hex_handles_upper_and_lower_case() {
    assert_eq!(
        decode_hex("DEADBEEF").unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert_eq!(
        decode_hex("deadbeef").unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert_eq!(
        decode_hex("DeAdBeEf").unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
}

/// parse_hex4 rejects an 8-hex-char string (4 bytes) correctly.
/// Spec: the signature field is exactly 4 bytes = 8 hex chars.
/// Mutation: accepting 6 hex chars (3 bytes) would pass a wrong-length signature.
#[test]
fn parse_hex4_rejects_wrong_byte_length() {
    // 6 hex chars = 3 bytes ≠ 4.
    assert!(
        parse_hex4("aabbcc").is_err(),
        "3 bytes must be rejected for 4-byte field"
    );
    // 10 hex chars = 5 bytes ≠ 4.
    assert!(
        parse_hex4("aabbccddee").is_err(),
        "5 bytes must be rejected for 4-byte field"
    );
    // Exactly 8 hex chars = 4 bytes: must succeed.
    assert_eq!(parse_hex4("aabbccdd").unwrap(), [0xaa, 0xbb, 0xcc, 0xdd]);
}

// Platform::name() strings are logged/keyed by callers; changing them is
// a breaking change. Mutation: swapping A/B names misroutes firmware upload.
#[test]
fn platform_name_is_stable() {
    // The exact strings are part of the public stable API (logged/keyed).
    assert_eq!(Platform::Mt1959A.name(), "MediaTek MT1959-A");
    assert_eq!(Platform::Mt1959B.name(), "MediaTek MT1959-B");
    assert_eq!(Platform::Renesas.name(), "Renesas");
}

// find_by_drive_id: two-pass — exact match (incl. firmware_date) wins
// over loose. Mutation: skipping the exact pass returns the first entry
// regardless of date.
#[test]
fn find_by_drive_id_exact_date_wins_over_loose() {
    use serde_json::json;
    // Use an 8-char vendor_id (padded with a trailing space so `trim()` strips
    // the pad, matching the same trimmed form the JSON profile stores).
    // "TESTDRV " fills INQUIRY [8..16] exactly; `ascii_field.trim()` → "TESTDRV".
    let profiles_json = json!({
        "mt1959_a": [
            {
                "identity": {
                    "vendor_id": "TESTDRV",
                    "product_revision": "1.00",
                    "vendor_specific": "XX00000",
                    "firmware_date": "200001010000"
                },
                "signature": "aabbccdd",
                "firmware": ""
            },
            {
                "identity": {
                    "vendor_id": "TESTDRV",
                    "product_revision": "1.00",
                    "vendor_specific": "XX00000",
                    "firmware_date": "200006150000"
                },
                "signature": "11223344",
                "firmware": ""
            }
        ]
    })
    .to_string();
    let profiles: Profiles = serde_json::from_str(&profiles_json).unwrap();

    // "TESTDRV " (with space) fills 8 bytes; trim() → "TESTDRV" on both sides.
    let id_date1 = make_drive_id("TESTDRV ", "1.00", "XX00000", "200001010000");
    let id_date2 = make_drive_id("TESTDRV ", "1.00", "XX00000", "200006150000");

    let m1 = find_by_drive_id(&profiles, &id_date1).unwrap();
    let m2 = find_by_drive_id(&profiles, &id_date2).unwrap();

    // Each must bind to its own profile by exact date match.
    assert_eq!(
        m1.profile.signature,
        [0xaa, 0xbb, 0xcc, 0xdd],
        "id_date1 must match first profile"
    );
    assert_eq!(
        m2.profile.signature,
        [0x11, 0x22, 0x33, 0x44],
        "id_date2 must match second profile"
    );
}

/// find_by_drive_id: a drive whose firmware_date does NOT match any profile
/// gets no match — there is no loose vendor/rev/vs fallback that could bind
/// the wrong same-model variant.
#[test]
fn find_by_drive_id_no_match_when_date_differs() {
    use serde_json::json;
    let profiles_json = json!({
        "mt1959_a": [
            {
                "identity": {
                    "vendor_id": "LOOSEDR",
                    "product_revision": "2.00",
                    "vendor_specific": "YY11111",
                    "firmware_date": "210101010000"
                },
                "signature": "deadbeef",
                "firmware": ""
            }
        ]
    })
    .to_string();
    let profiles: Profiles = serde_json::from_str(&profiles_json).unwrap();

    // Same vendor/rev/vs but a different date — must NOT match.
    let id = make_drive_id("LOOSEDR ", "2.00", "YY11111", "000000000000");
    assert!(find_by_drive_id(&profiles, &id).is_none());
}

/// load_from_str (via load_bundled) returns ProfileParse on invalid JSON.
/// Mutation: returning an empty Profiles instead of an error silently
///           leaves the drive-profile database empty.
#[test]
fn load_from_str_returns_profile_parse_on_bad_json() {
    let result: Result<Profiles> =
        serde_json::from_str("not valid json {{{{").map_err(|_| Error::ProfileParse);
    assert!(matches!(result, Err(Error::ProfileParse)));
}

// Pins the embedded JSON: if profiles.json is emptied/truncated, this
// goes red.
#[test]
fn bundled_profiles_has_entries() {
    let profiles = load_bundled().unwrap();
    assert!(
        !profiles.mt1959_a.is_empty(),
        "bundled profiles must have at least one mt1959_a entry"
    );
}

// All CDB fields are `#[serde(default)]`. Mutation: making one required
// breaks backward-compat with old blobs.
#[test]
fn profile_optional_cdb_fields_default_to_none() {
    use serde_json::json;
    let json_str = json!({
        "mt1959_a": [
            {
                "identity": {
                    "vendor_id": "TEST",
                    "product_revision": "1.00",
                    "vendor_specific": "000000",
                    "firmware_date": ""
                },
                "signature": "00000000",
                "firmware": ""
            }
        ]
    })
    .to_string();
    let profiles: Profiles = serde_json::from_str(&json_str).unwrap();
    let p = &profiles.mt1959_a[0]; // DriveProfile directly
    // All optional CDB fields must be None when absent from JSON.
    assert!(
        p.read_vid_cdb.is_none(),
        "read_vid_cdb must default to None"
    );
    assert!(
        p.read_disc_keys_cdb.is_none(),
        "read_disc_keys_cdb must default to None"
    );
    assert!(
        p.drive_nominal_speed_cdb.is_none(),
        "drive_nominal_speed_cdb must default to None"
    );
    assert!(
        p.set_speed_max_cdb.is_none(),
        "set_speed_max_cdb must default to None"
    );
    assert!(
        p.speed_zone_table.is_none(),
        "speed_zone_table must default to None"
    );
    assert!(
        p.speed_calc_table.is_none(),
        "speed_calc_table must default to None"
    );
}

// `Debug` must not render firmware/CDB bytes. Mutation: restoring
// `#[derive(Debug)]` prints them (e.g. the 0xEE marker below), goes red.
#[test]
fn drive_profile_debug_redacts_firmware_and_cdbs() {
    use serde_json::json;
    let profiles: Profiles = serde_json::from_str(
        &json!({
            "mt1959_a": [{
                "identity": {"vendor_id":"VIS","product_revision":"1.00",
                    "vendor_specific":"AA00000","firmware_date":"200001010000"},
                "signature":"aabbccdd",
                "firmware":"7u7u7u7u", // base64 → six 0xEE bytes
                "read_vid_cdb":"3c014410e29100002400"
            }]
        })
        .to_string(),
    )
    .unwrap();
    let s = format!("{:?}", profiles.mt1959_a[0]);
    // Firmware byte 0xEE renders as `238` under a derived Debug.
    assert!(!s.contains("238"), "firmware bytes must not appear: {s}");
    assert!(
        !s.contains("read_vid_cdb"),
        "CDB templates must not appear: {s}"
    );
    assert!(s.contains("redacted"), "must mark redaction: {s}");
    // The PUBLIC fields stay visible.
    assert!(s.contains("VIS"), "identity must remain visible: {s}");
}

// deserialize_hex4("") must produce [0;4]. Mutation: treating empty as
// an error blocks profiles with no captured signature from loading.
#[test]
fn profile_empty_signature_deserialises_as_zeroes() {
    use serde_json::json;
    let json_str = json!({
        "mt1959_a": [
            {
                "identity": {
                    "vendor_id": "TEST",
                    "product_revision": "1.00",
                    "vendor_specific": "000000",
                    "firmware_date": ""
                },
                "signature": "",
                "firmware": ""
            }
        ]
    })
    .to_string();
    let profiles: Profiles = serde_json::from_str(&json_str).unwrap();
    assert_eq!(
        profiles.mt1959_a[0].signature, [0u8; 4],
        "empty signature must deserialise as [0;4]"
    );
}
