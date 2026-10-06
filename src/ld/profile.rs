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
/// Only `identity` and `signature` are public; everything else (firmware image, per-drive
/// vendor CDB templates) is `pub(crate)` unlock mechanism that must stay inside this
/// unpublished crate.
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

/// Find a profile matching a drive's INQUIRY fields, whitespace-trimmed.
///
/// Over ALL platform sections (MT1959-A, -B, Renesas, in order): (1) exact
/// match including `product_id` when the drive reports one; then (2) a
/// product-id-blind fallback on vendor/revision/vendor_specific/firmware_date.
/// Catalogs store a GENERIC product_id ("BD-RE") vs a drive's specific one
/// ("BD-RE BU40N"), so pass 1 misses; pass 2 binds a four-field match UNIQUE
/// across all sections — a shared tuple binds only with no product_id.
pub fn find_by_drive_id(profiles: &Profiles, drive_id: &crate::DriveId) -> Option<ProfileMatch> {
    let v = drive_id.vendor_id.trim();
    let prod = drive_id.product_id.trim();
    let r = drive_id.product_revision.trim();
    let vs = drive_id.vendor_specific.trim();
    let date = drive_id.firmware_date.trim();

    let sections = [
        (Platform::Mt1959A, &profiles.mt1959_a),
        (Platform::Mt1959B, &profiles.mt1959_b),
        (Platform::Renesas, &profiles.renesas),
    ];
    let four_field = |p: &DriveProfile| {
        p.identity.vendor_id.trim() == v
            && p.identity.product_revision.trim() == r
            && p.identity.vendor_specific.trim() == vs
            && p.identity.firmware_date.trim() == date
    };
    let all = || {
        sections
            .iter()
            .flat_map(|(platform, list)| list.iter().map(move |p| (*platform, p)))
    };

    if !prod.is_empty()
        && let Some((platform, p)) =
            all().find(|(_, p)| four_field(p) && p.identity.product_id.trim() == prod)
    {
        return Some(ProfileMatch {
            profile: p.clone(),
            platform,
        });
    }

    // Unique across all sections: bind regardless of the reported product_id
    // (the common real-drive case a UHD LG BU40N relies on). A shared tuple
    // binds only with NO product_id; otherwise it's an uncataloged variant.
    let mut matches = all().filter(|(_, p)| four_field(p));
    let (platform, first) = matches.next()?;
    if matches.next().is_some() && !prod.is_empty() {
        return None;
    }
    Some(ProfileMatch {
        profile: first.clone(),
        platform,
    })
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
