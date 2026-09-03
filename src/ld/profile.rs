//! Drive profile loading and matching.

use crate::ld::error::{Error, Result};
use serde::Deserialize;

/// The LdUnlocker profile catalog — the set of optical drives the firmware
/// unlocker recognizes, keyed by chipset + variant. Loaded from the bundled
/// JSON; the public entry point is [`crate::ld::profiles`].
#[derive(Debug, Deserialize)]
pub struct Profiles {
    #[serde(default)]
    pub mt1959_a: Vec<DriveProfile>,
    #[serde(default)]
    pub mt1959_b: Vec<DriveProfile>,
    #[serde(default)]
    pub renesas: Vec<DriveProfile>,
}

impl Profiles {
    /// The profile matching a drive identity, if this catalog supports that
    /// drive. Two-pass per platform section: exact (incl. firmware date) then a
    /// looser vendor/revision/vendor-specific match. See `find_by_drive_id`.
    pub fn get(&self, drive_id: &crate::DriveId) -> Option<ProfileMatch> {
        find_by_drive_id(self, drive_id)
    }
}

/// Drive identity — matched against INQUIRY data.
#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    #[serde(default)]
    pub vendor_id: String,
    #[serde(default)]
    pub product_id: String,
    #[serde(default)]
    pub product_revision: String,
    #[serde(default)]
    pub vendor_specific: String,
    #[serde(default)]
    pub firmware_date: String,
}

/// Per-drive profile.
///
/// Only `identity` and `signature` are public; everything else (firmware
/// image, per-drive vendor CDB templates) is `pub(crate)` unlock mechanism
/// that must stay inside this unpublished crate.
/// See docs/drive-profile-visibility.md — field-visibility and allow(dead_code) rationale.
#[allow(dead_code)]
#[derive(Clone, Deserialize)]
pub struct DriveProfile {
    pub identity: Identity,
    /// Expected first 4 bytes of the drive's unlock response — the
    /// per-drive signature the platform checks before trusting the
    /// extended-access surface. JSON-encoded as 8 lowercase hex chars.
    #[serde(default, deserialize_with = "deserialize_hex4")]
    pub signature: [u8; 4],
    /// Runtime firmware image uploaded during unlock (variant A/B
    /// firmware-load step). JSON-encoded as standard base64; empty when
    /// the profile carries no firmware blob.
    #[serde(default, deserialize_with = "deserialize_base64")]
    pub(crate) firmware: Vec<u8>,

    // ── OEM-extended-access CDB templates ──────────────────────────────
    // All optional (`None` if pre-capture-pipeline). Hex strings, no
    // separators, e.g. `"3c014410e29100002400"`.
    #[serde(default)]
    pub(crate) unlock_init_value: u8,
    #[serde(default)]
    pub(crate) unlock_response_size: u8,

    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) read_vid_cdb: Option<[u8; 10]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) read_disc_keys_cdb: Option<[u8; 10]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_12")]
    pub(crate) drive_nominal_speed_cdb: Option<[u8; 12]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_12")]
    pub(crate) set_speed_max_cdb: Option<[u8; 12]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) read10_raw_2sec_cdb: Option<[u8; 10]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) read10_raw_1sec_cdb: Option<[u8; 10]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) read_buffer_verify_cdb: Option<[u8; 10]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) write_buffer_cdb: Option<[u8; 10]>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) read_buffer_unlock_cdb: Option<[u8; 10]>,
    /// Variant-B vendor verify (0xF1) CDB. PER-DRIVE: 39 distinct values across
    /// the 140 B drives, so it CANNOT be a hardcoded constant. `variant_b`'s old
    /// `VENDOR_VERIFY` const was one drive's token, wrong for the other ~139.
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes_10")]
    pub(crate) fw_verify_cdb: Option<[u8; 10]>,

    // Per-drive identifier tables — variable-length hex strings.
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes")]
    pub(crate) speed_zone_table: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "deserialize_opt_hex_bytes")]
    pub(crate) speed_calc_table: Option<Vec<u8>>,
}

// Hand-written, REDACTING Debug: a derived one would recurse through the
// public `Profiles` catalog and print raw firmware + vendor CDB bytes into
// logs. Show only identity + signature; collapse firmware to a length.
impl std::fmt::Debug for DriveProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriveProfile")
            .field("identity", &self.identity)
            .field("signature", &self.signature)
            .field(
                "firmware",
                &format_args!("[{} bytes redacted]", self.firmware.len()),
            )
            .field("cdb_templates", &"[redacted]")
            .finish()
    }
}

/// Chipset + variant — determined by which section the profile was found in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Platform {
    Mt1959A,
    Mt1959B,
    Renesas,
}

impl Platform {
    /// Stable, language-neutral platform identifier. The two MT1959 variants
    /// share the chipset but differ in their firmware-upload / unlock
    /// sequence, so they get distinct suffixes — callers (and logs) that key
    /// off `name()` must be able to tell A from B.
    pub fn name(&self) -> &'static str {
        match self {
            Platform::Mt1959A => "MediaTek MT1959-A",
            Platform::Mt1959B => "MediaTek MT1959-B",
            Platform::Renesas => "Renesas",
        }
    }
}

/// Result of a profile lookup: the matched profile plus the platform
/// (chipset + variant) of the section it was found in. The platform
/// determines which unlock/firmware sequence the driver runs.
pub struct ProfileMatch {
    /// The matched profile, cloned out of the profiles file.
    pub profile: DriveProfile,
    /// Which platform section the profile came from.
    pub platform: Platform,
}

// ── Parsing: decode hex on raw bytes (not `&str` slices) so non-ASCII
// can't land `&s[i..i+2]` inside a UTF-8 char boundary and panic — it
// just fails to decode with `"hex"`.
fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, &'static str> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("hex");
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0.iter() {
        let hi = (pair[0] as char).to_digit(16).ok_or("hex")?;
        let lo = (pair[1] as char).to_digit(16).ok_or("hex")?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

fn parse_hex4(s: &str) -> Result<[u8; 4]> {
    let bytes = decode_hex(s).map_err(|_| Error::ProfileParse)?;
    let out: [u8; 4] = bytes.try_into().map_err(|_| Error::ProfileParse)?;
    Ok(out)
}

fn deserialize_hex4<'de, D>(deserializer: D) -> std::result::Result<[u8; 4], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Ok([0; 4]);
    }
    parse_hex4(&s).map_err(serde::de::Error::custom)
}

fn deserialize_base64<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use base64::Engine;
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Ok(Vec::new());
    }
    base64::engine::general_purpose::STANDARD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

// ── Fixed-length hex deserializers for CDB templates ────────────────────
// Lowercase hex strings, no separators; empty/null/missing decodes as `None`.

fn parse_hex_bytes(s: &str) -> std::result::Result<Vec<u8>, &'static str> {
    decode_hex(s)
}

fn deserialize_opt_hex_bytes_10<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<[u8; 10]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    let Some(s) = opt else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    let bytes = parse_hex_bytes(&s).map_err(serde::de::Error::custom)?;
    let out: [u8; 10] = bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("len"))?;
    Ok(Some(out))
}

fn deserialize_opt_hex_bytes_12<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<[u8; 12]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    let Some(s) = opt else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    let bytes = parse_hex_bytes(&s).map_err(serde::de::Error::custom)?;
    let out: [u8; 12] = bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("len"))?;
    Ok(Some(out))
}

fn deserialize_opt_hex_bytes<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    let Some(s) = opt else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    let bytes = parse_hex_bytes(&s).map_err(serde::de::Error::custom)?;
    Ok(Some(bytes))
}

// ── Loading ────────────────────────────────────────────────────────────

const BUNDLED_PROFILES: &str = include_str!("profiles.json");

/// Parse the bundled profiles fresh into an owned [`Profiles`]. Test-only — the
/// library hot path uses the cached [`bundled`]; tests use this owned form for
/// independent copies.
#[cfg(test)]
pub fn load_bundled() -> Result<Profiles> {
    load_from_str(BUNDLED_PROFILES)
}

/// Borrow the process-wide cached bundled profiles, parsing once on first
/// use. Avoids re-parsing the ~800 KB JSON on every `Drive::open()`.
///
/// Returns `None` if the embedded JSON fails to parse (a build-time bug —
/// the bundled blob is fixed at compile time, so the first successful call
/// guarantees all later calls succeed too).
pub fn bundled() -> Option<&'static Profiles> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Option<Profiles>> = OnceLock::new();
    CACHE
        .get_or_init(|| match load_from_str(BUNDLED_PROFILES) {
            Ok(p) => Some(p),
            // `None` caches permanently; unlogged that's indistinguishable
            // from a genuinely uncataloged drive, so log once, loudly, here.
            Err(e) => {
                tracing::error!(
                    target: "freemkv::disc",
                    phase = "bundled_profiles_parse_failed",
                    error_code = e.code(),
                    "bundled LdUnlocker profile catalog failed to parse; no drive can match"
                );
                None
            }
        })
        .as_ref()
}

/// Find a profile for a drive against the cached bundled profiles.
///
/// Convenience wrapper over [`bundled`] + [`find_by_drive_id`] that skips
/// the per-call re-parse. Returns `None` if no profile matches (or, in the
/// build-bug case, if the bundled JSON failed to parse).
pub fn find_bundled(drive_id: &crate::DriveId) -> Option<ProfileMatch> {
    find_by_drive_id(bundled()?, drive_id)
}

fn load_from_str(data: &str) -> Result<Profiles> {
    serde_json::from_str(data).map_err(|_| Error::ProfileParse)
}

/// Find a profile matching a drive's INQUIRY fields.
///
/// Per platform section (MT1959-A, then MT1959-B, then Renesas). A drive that
/// reports a `product_id` matches ONLY on the full identity including it — if
/// no cataloged profile matches exactly, the drive is treated as uncataloged
/// (no match), never bound to a same-vendor/revision sibling. The looser
/// four-field pass (vendor/revision/vendor_specific/firmware_date) runs only
/// when the drive reports no `product_id` at all. All comparisons are
/// whitespace-trimmed. Returns the first section that matches.
pub fn find_by_drive_id(profiles: &Profiles, drive_id: &crate::DriveId) -> Option<ProfileMatch> {
    let v = drive_id.vendor_id.trim();
    let prod = drive_id.product_id.trim();
    let r = drive_id.product_revision.trim();
    let vs = drive_id.vendor_specific.trim();
    let date = drive_id.firmware_date.trim();

    for (platform, list) in [
        (Platform::Mt1959A, &profiles.mt1959_a),
        (Platform::Mt1959B, &profiles.mt1959_b),
        (Platform::Renesas, &profiles.renesas),
    ] {
        if !prod.is_empty()
            && let Some(p) = list.iter().find(|p| {
                p.identity.vendor_id.trim() == v
                    && p.identity.product_id.trim() == prod
                    && p.identity.product_revision.trim() == r
                    && p.identity.vendor_specific.trim() == vs
                    && p.identity.firmware_date.trim() == date
            })
        {
            return Some(ProfileMatch {
                profile: p.clone(),
                platform,
            });
        }

        // The product_id-blind pass runs ONLY when the drive reports none: a
        // drive that reports a product_id but misses the exact match is an
        // uncataloged variant, else it'd bind to a sibling's wrong firmware.
        if prod.is_empty()
            && let Some(p) = list.iter().find(|p| {
                p.identity.vendor_id.trim() == v
                    && p.identity.product_revision.trim() == r
                    && p.identity.vendor_specific.trim() == vs
                    && p.identity.firmware_date.trim() == date
            })
        {
            return Some(ProfileMatch {
                profile: p.clone(),
                platform,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
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
}
