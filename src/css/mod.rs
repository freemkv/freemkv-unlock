//! CSS drive bus-authentication — read-unlock primitive.
//!
//! A CSS-enforcing DVD drive refuses to return scrambled sectors until a
//! CSS bus-auth handshake has set its Authentication Success Flag (ASF=1).
//! [`unlock_css_reads`] runs that bus-auth challenge-response (which is what
//! actually opens scrambled-sector reads), then a best-effort, non-fatal
//! disc-key REPORT KEY. The bytes are NOT used as keys: descrambling here is
//! keyless — the descramble title key is recovered directly from the stream,
//! so no device or player key is derived or needed.

mod error;
use crate::css::error::{Error, Result, step_err};
use crate::scsi::{DataDirection, ScsiTransport};

// Issue ONE CSS bus-auth CDB, honouring the transport contract: treats a
// non-zero status as CssAuthFailed and checks bytes_transferred >= min_bytes
// rather than trusting an unfilled buffer. See docs/css-mod.md#css_scsi.
fn css_scsi(
    scsi: &mut dyn ScsiTransport,
    cdb: &[u8],
    dir: DataDirection,
    buf: &mut [u8],
    min_bytes: usize,
) -> Result<()> {
    let r = scsi.execute(cdb, dir, buf, 5_000).map_err(step_err)?;
    if r.status != 0 {
        tracing::debug!(
            target: "freemkv::css",
            phase = "css_step_check_condition",
            opcode = cdb.first().copied().unwrap_or(0),
            status = r.status,
            "CSS bus-auth step returned a drive sense"
        );
        return Err(Error::CssAuthFailed);
    }
    if r.bytes_transferred < min_bytes {
        tracing::debug!(
            target: "freemkv::css",
            phase = "css_step_short_response",
            opcode = cdb.first().copied().unwrap_or(0),
            bytes_transferred = r.bytes_transferred,
            "CSS bus-auth step returned a short response"
        );
        return Err(Error::CssAuthFailed);
    }
    Ok(())
}

// ── CryptKey tables ───────────────────────────────────────────────────────

const CRYPT_TAB0: [u8; 256] = [
    0xB7, 0xF4, 0x82, 0x57, 0xDA, 0x4D, 0xDB, 0xE2, 0x2F, 0x52, 0x1A, 0xA8, 0x68, 0x5A, 0x8A, 0xFF,
    0xFB, 0x0E, 0x6D, 0x35, 0xF7, 0x5C, 0x76, 0x12, 0xCE, 0x25, 0x79, 0x29, 0x39, 0x62, 0x08, 0x24,
    0xA5, 0x85, 0x7B, 0x56, 0x01, 0x23, 0x68, 0xCF, 0x0A, 0xE2, 0x5A, 0xED, 0x3D, 0x59, 0xB0, 0xA9,
    0xB0, 0x2C, 0xF2, 0xB8, 0xEF, 0x32, 0xA9, 0x40, 0x80, 0x71, 0xAF, 0x1E, 0xDE, 0x8F, 0x58, 0x88,
    0xB8, 0x3A, 0xD0, 0xFC, 0xC4, 0x1E, 0xB5, 0xA0, 0xBB, 0x3B, 0x0F, 0x01, 0x7E, 0x1F, 0x9F, 0xD9,
    0xAA, 0xB8, 0x3D, 0x9D, 0x74, 0x1E, 0x25, 0xDB, 0x37, 0x56, 0x8F, 0x16, 0xBA, 0x49, 0x2B, 0xAC,
    0xD0, 0xBD, 0x95, 0x20, 0xBE, 0x7A, 0x28, 0xD0, 0x51, 0x64, 0x63, 0x1C, 0x7F, 0x66, 0x10, 0xBB,
    0xC4, 0x56, 0x1A, 0x04, 0x6E, 0x0A, 0xEC, 0x9C, 0xD6, 0xE8, 0x9A, 0x7A, 0xCF, 0x8C, 0xDB, 0xB1,
    0xEF, 0x71, 0xDE, 0x31, 0xFF, 0x54, 0x3E, 0x5E, 0x07, 0x69, 0x96, 0xB0, 0xCF, 0xDD, 0x9E, 0x47,
    0xC7, 0x96, 0x8F, 0xE4, 0x2B, 0x59, 0xC6, 0xEE, 0xB9, 0x86, 0x9A, 0x64, 0x84, 0x72, 0xE2, 0x5B,
    0xA2, 0x96, 0x58, 0x99, 0x50, 0x03, 0xF5, 0x38, 0x4D, 0x02, 0x7D, 0xE7, 0x7D, 0x75, 0xA7, 0xB8,
    0x67, 0x87, 0x84, 0x3F, 0x1D, 0x11, 0xE5, 0xFC, 0x1E, 0xD3, 0x83, 0x16, 0xA5, 0x29, 0xF6, 0xC7,
    0x15, 0x61, 0x29, 0x1A, 0x43, 0x4F, 0x9B, 0xAF, 0xC5, 0x87, 0x34, 0x6C, 0x0F, 0x3B, 0xA8, 0x1D,
    0x45, 0x58, 0x25, 0xDC, 0xA8, 0xA3, 0x3B, 0xD1, 0x79, 0x1B, 0x48, 0xF2, 0xE9, 0x93, 0x1F, 0xFC,
    0xDB, 0x2A, 0x90, 0xA9, 0x8A, 0x3D, 0x39, 0x18, 0xA3, 0x8E, 0x58, 0x6C, 0xE0, 0x12, 0xBB, 0x25,
    0xCD, 0x71, 0x22, 0xA2, 0x64, 0xC6, 0xE7, 0xFB, 0xAD, 0x94, 0x77, 0x04, 0x9A, 0x39, 0xCF, 0x7C,
];

const CRYPT_TAB1: [u8; 256] = [
    0x8C, 0x47, 0xB0, 0xE1, 0xEB, 0xFC, 0xEB, 0x56, 0x10, 0xE5, 0x2C, 0x1A, 0x5D, 0xEF, 0xBE, 0x4F,
    0x08, 0x75, 0x97, 0x4B, 0x0E, 0x25, 0x8E, 0x6E, 0x39, 0x5A, 0x87, 0x53, 0xC4, 0x1F, 0xF4, 0x5C,
    0x4E, 0xE6, 0x99, 0x30, 0xE0, 0x42, 0x88, 0xAB, 0xE5, 0x85, 0xBC, 0x8F, 0xD8, 0x3C, 0x54, 0xC9,
    0x53, 0x47, 0x18, 0xD6, 0x06, 0x5B, 0x41, 0x2C, 0x67, 0x1E, 0x41, 0x74, 0x33, 0xE2, 0xB4, 0xE0,
    0x23, 0x29, 0x42, 0xEA, 0x55, 0x0F, 0x25, 0xB4, 0x24, 0x2C, 0x99, 0x13, 0xEB, 0x0A, 0x0B, 0xC9,
    0xF9, 0x63, 0x67, 0x43, 0x2D, 0xC7, 0x7D, 0x07, 0x60, 0x89, 0xD1, 0xCC, 0xE7, 0x94, 0x77, 0x74,
    0x9B, 0x7E, 0xD7, 0xE6, 0xFF, 0xBB, 0x68, 0x14, 0x1E, 0xA3, 0x25, 0xDE, 0x3A, 0xA3, 0x54, 0x7B,
    0x87, 0x9D, 0x50, 0xCA, 0x27, 0xC3, 0xA4, 0x50, 0x91, 0x27, 0xD4, 0xB0, 0x82, 0x41, 0x97, 0x79,
    0x94, 0x82, 0xAC, 0xC7, 0x8E, 0xA5, 0x4E, 0xAA, 0x78, 0x9E, 0xE0, 0x42, 0xBA, 0x28, 0xEA, 0xB7,
    0x74, 0xAD, 0x35, 0xDA, 0x92, 0x60, 0x7E, 0xD2, 0x0E, 0xB9, 0x24, 0x5E, 0x39, 0x4F, 0x5E, 0x63,
    0x09, 0xB5, 0xFA, 0xBF, 0xF1, 0x22, 0x55, 0x1C, 0xE2, 0x25, 0xDB, 0xC5, 0xD8, 0x50, 0x03, 0x98,
    0xC4, 0xAC, 0x2E, 0x11, 0xB4, 0x38, 0x4D, 0xD0, 0xB9, 0xFC, 0x2D, 0x3C, 0x08, 0x04, 0x5A, 0xEF,
    0xCE, 0x32, 0xFB, 0x4C, 0x92, 0x1E, 0x4B, 0xFB, 0x1A, 0xD0, 0xE2, 0x3E, 0xDA, 0x6E, 0x7C, 0x4D,
    0x56, 0xC3, 0x3F, 0x42, 0xB1, 0x3A, 0x23, 0x4D, 0x6E, 0x84, 0x56, 0x68, 0xF4, 0x0E, 0x03, 0x64,
    0xD0, 0xA9, 0x92, 0x2F, 0x8B, 0xBC, 0x39, 0x9C, 0xAC, 0x09, 0x5E, 0xEE, 0xE5, 0x97, 0xBF, 0xA5,
    0xCE, 0xFA, 0x28, 0x2C, 0x6D, 0x4F, 0xEF, 0x77, 0xAA, 0x1B, 0x79, 0x8E, 0x97, 0xB4, 0xC3, 0xF4,
];

const CRYPT_TAB2: [u8; 256] = [
    0xB7, 0x75, 0x81, 0xD5, 0xDC, 0xCA, 0xDE, 0x66, 0x23, 0xDF, 0x15, 0x26, 0x62, 0xD1, 0x83, 0x77,
    0xE3, 0x97, 0x76, 0xAF, 0xE9, 0xC3, 0x6B, 0x8E, 0xDA, 0xB0, 0x6E, 0xBF, 0x2B, 0xF1, 0x19, 0xB4,
    0x95, 0x34, 0x48, 0xE4, 0x37, 0x94, 0x5D, 0x7B, 0x36, 0x5F, 0x65, 0x53, 0x07, 0xE2, 0x89, 0x11,
    0x98, 0x85, 0xD9, 0x12, 0xC1, 0x9D, 0x84, 0xEC, 0xA4, 0xD4, 0x88, 0xB8, 0xFC, 0x2C, 0x79, 0x28,
    0xD8, 0xDB, 0xB3, 0x1E, 0xA2, 0xF9, 0xD0, 0x44, 0xD7, 0xD6, 0x60, 0xEF, 0x14, 0xF4, 0xF6, 0x31,
    0xD2, 0x41, 0x46, 0x67, 0x0A, 0xE1, 0x58, 0x27, 0x43, 0xA3, 0xF8, 0xE0, 0xC8, 0xBA, 0x5A, 0x5C,
    0x80, 0x6C, 0xC6, 0xF2, 0xE8, 0xAD, 0x7D, 0x04, 0x0D, 0xB9, 0x3C, 0xC2, 0x25, 0xBD, 0x49, 0x63,
    0x8C, 0x9F, 0x51, 0xCE, 0x20, 0xC5, 0xA1, 0x50, 0x92, 0x2D, 0xDD, 0xBC, 0x8D, 0x4F, 0x9A, 0x71,
    0x2F, 0x30, 0x1D, 0x73, 0x39, 0x13, 0xFB, 0x1A, 0xCB, 0x24, 0x59, 0xFE, 0x05, 0x96, 0x57, 0x0F,
    0x1F, 0xCF, 0x54, 0xBE, 0xF5, 0x06, 0x1B, 0xB2, 0x6D, 0xD3, 0x4D, 0x32, 0x56, 0x21, 0x33, 0x0B,
    0x52, 0xE7, 0xAB, 0xEB, 0xA6, 0x74, 0x00, 0x4C, 0xB1, 0x7F, 0x82, 0x99, 0x87, 0x0E, 0x5E, 0xC0,
    0x8F, 0xEE, 0x6F, 0x55, 0xF3, 0x7E, 0x08, 0x90, 0xFA, 0xB6, 0x64, 0x70, 0x47, 0x4A, 0x17, 0xA7,
    0xB5, 0x40, 0x8A, 0x38, 0xE5, 0x68, 0x3E, 0x8B, 0x69, 0xAA, 0x9B, 0x42, 0xA5, 0x10, 0x01, 0x35,
    0xFD, 0x61, 0x9E, 0xE6, 0x16, 0x9C, 0x86, 0xED, 0xCD, 0x2E, 0xFF, 0xC4, 0x5B, 0xA0, 0xAE, 0xCC,
    0x4B, 0x3B, 0x03, 0xBB, 0x1C, 0x2A, 0xAC, 0x0C, 0x3F, 0x93, 0xC7, 0x72, 0x7A, 0x09, 0x22, 0x3D,
    0x45, 0x78, 0xA9, 0xA8, 0xEA, 0xC9, 0x6A, 0xF7, 0x29, 0x91, 0xF0, 0x02, 0x18, 0x3A, 0x4E, 0x7C,
];

const CRYPT_TAB3: [u8; 256] = [
    0x73, 0x51, 0x95, 0xE1, 0x12, 0xE4, 0xC0, 0x58, 0xEE, 0xF2, 0x08, 0x1B, 0xA9, 0xFA, 0x98, 0x4C,
    0xA7, 0x33, 0xE2, 0x1B, 0xA7, 0x6D, 0xF5, 0x30, 0x97, 0x1D, 0xF3, 0x02, 0x60, 0x5A, 0x82, 0x0F,
    0x91, 0xD0, 0x9C, 0x10, 0x39, 0x7A, 0x83, 0x85, 0x3B, 0xB2, 0xB8, 0xAE, 0x0C, 0x09, 0x52, 0xEA,
    0x1C, 0xE1, 0x8D, 0x66, 0x4F, 0xF3, 0xDA, 0x92, 0x29, 0xB9, 0xD5, 0xC5, 0x77, 0x47, 0x22, 0x53,
    0x14, 0xF7, 0xAF, 0x22, 0x64, 0xDF, 0xC6, 0x72, 0x12, 0xF3, 0x75, 0xDA, 0xD7, 0xD7, 0xE5, 0x02,
    0x9E, 0xED, 0xDA, 0xDB, 0x4C, 0x47, 0xCE, 0x91, 0x06, 0x06, 0x6D, 0x55, 0x8B, 0x19, 0xC9, 0xEF,
    0x8C, 0x80, 0x1A, 0x0E, 0xEE, 0x4B, 0xAB, 0xF2, 0x08, 0x5C, 0xE9, 0x37, 0x26, 0x5E, 0x9A, 0x90,
    0x00, 0xF3, 0x0D, 0xB2, 0xA6, 0xA3, 0xF7, 0x26, 0x17, 0x48, 0x88, 0xC9, 0x0E, 0x2C, 0xC9, 0x02,
    0xE7, 0x18, 0x05, 0x4B, 0xF3, 0x39, 0xE1, 0x20, 0x02, 0x0D, 0x40, 0xC7, 0xCA, 0xB9, 0x48, 0x30,
    0x57, 0x67, 0xCC, 0x06, 0xBF, 0xAC, 0x81, 0x08, 0x24, 0x7A, 0xD4, 0x8B, 0x19, 0x8E, 0xAC, 0xB4,
    0x5A, 0x0F, 0x73, 0x13, 0xAC, 0x9E, 0xDA, 0xB6, 0xB8, 0x96, 0x5B, 0x60, 0x88, 0xE1, 0x81, 0x3F,
    0x07, 0x86, 0x37, 0x2D, 0x79, 0x14, 0x52, 0xEA, 0x73, 0xDF, 0x3D, 0x09, 0xC8, 0x25, 0x48, 0xD8,
    0x75, 0x60, 0x9A, 0x08, 0x27, 0x4A, 0x2C, 0xB9, 0xA8, 0x8B, 0x8A, 0x73, 0x62, 0x37, 0x16, 0x02,
    0xBD, 0xC1, 0x0E, 0x56, 0x54, 0x3E, 0x14, 0x5F, 0x8C, 0x8F, 0x6E, 0x75, 0x1C, 0x07, 0x39, 0x7B,
    0x4B, 0xDB, 0xD3, 0x4B, 0x1E, 0xC8, 0x7E, 0xFE, 0x3E, 0x72, 0x16, 0x83, 0x7D, 0xEE, 0xF5, 0xCA,
    0xC5, 0x18, 0xF9, 0xD8, 0x68, 0xAB, 0x38, 0x85, 0xA8, 0xF0, 0xA1, 0x73, 0x9F, 0x5D, 0x19, 0x0B,
];

const VARIANTS: [u8; 32] = [
    0xB7, 0x74, 0x85, 0xD0, 0xCC, 0xDB, 0xCA, 0x73, 0x03, 0xFE, 0x31, 0x03, 0x52, 0xE0, 0xB7, 0x42,
    0x63, 0x16, 0xF2, 0x2A, 0x79, 0x52, 0xFF, 0x1B, 0x7A, 0x11, 0xCA, 0x1A, 0x9B, 0x40, 0xAD, 0x01,
];

const SECRET: [u8; 5] = [0x55, 0xD6, 0xC4, 0xC5, 0x28];

const PERM_CHALLENGE: [[usize; 10]; 3] = [
    [1, 3, 0, 7, 5, 2, 9, 6, 4, 8],
    [6, 1, 9, 3, 8, 5, 7, 4, 0, 2],
    [4, 0, 3, 5, 7, 2, 8, 6, 1, 9],
];

const PERM_VARIANT: [[u8; 32]; 2] = [
    [
        0x0A, 0x08, 0x0E, 0x0C, 0x0B, 0x09, 0x0F, 0x0D, 0x1A, 0x18, 0x1E, 0x1C, 0x1B, 0x19, 0x1F,
        0x1D, 0x02, 0x00, 0x06, 0x04, 0x03, 0x01, 0x07, 0x05, 0x12, 0x10, 0x16, 0x14, 0x13, 0x11,
        0x17, 0x15,
    ],
    [
        0x12, 0x1A, 0x16, 0x1E, 0x02, 0x0A, 0x06, 0x0E, 0x10, 0x18, 0x14, 0x1C, 0x00, 0x08, 0x04,
        0x0C, 0x13, 0x1B, 0x17, 0x1F, 0x03, 0x0B, 0x07, 0x0F, 0x11, 0x19, 0x15, 0x1D, 0x01, 0x09,
        0x05, 0x0D,
    ],
];

// ── Public API ────────────────────────────────────────────────────────────

/// CSS bus-auth **unlock** primitive.
///
/// Runs the bus-auth challenge-response (which sets the drive's ASF=1 and is
/// what actually unlocks scrambled-sector reads), then a best-effort,
/// non-fatal disc-key REPORT KEY. The title-key REPORT KEY is NOT issued: it
/// is unnecessary (descrambling is keyless — the key is recovered directly
/// from the data, so no device key is derived) and its hard failure on some
/// USB bridges used to abort the whole unlock (the 7014 bug). The bytes are
/// discarded.
pub fn unlock_css_reads(scsi: &mut dyn ScsiTransport, lba: u32) -> Result<()> {
    let t0 = std::time::Instant::now();
    tracing::info!(target: "freemkv::css", phase = "unlock_css_reads", lba, "begin");
    let r = unlock_css_reads_inner(scsi, lba);
    tracing::info!(
        target: "freemkv::css",
        phase = "unlock_css_reads",
        lba,
        ok = r.is_ok(),
        elapsed_ms = t0.elapsed().as_millis() as u64,
        "end"
    );
    r
}

/// The DVD unlocker (registry name `"DVD"`) — the DVD peer of the firmware and
/// AACS-cert unlockers in the uniform [`crate::Unlocker`] registry. It removes
/// the DVD scrambled-read barrier (drive ASF=1) via bus-auth and learns no VID
/// or bus key — descrambling is keyless: the key is recovered directly from
/// the data downstream. Named for the medium it unlocks (DVD), not the CSS
/// scheme: the bus-auth is required to read a CSS-protected DVD at all, whether
/// or not any given sector turns out to be scrambled. Lives in the `css` module
/// beside the CSS-scheme primitives it drives.
pub struct DvdUnlocker;

impl DvdUnlocker {
    pub fn new() -> Self {
        DvdUnlocker
    }
}

impl Default for DvdUnlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::Unlocker for DvdUnlocker {
    fn name(&self) -> &'static str {
        // "DVD" names the medium this bus-auth unlocks, not the CSS scheme:
        // the bus-auth runs on any DVD regardless of whether the content is
        // actually scrambled. See docs/css-mod.md#dvdunlocker-name.
        "DVD"
    }

    /// CSS removes the scrambled-sector barrier (a bus-level concern); it
    /// provides no drive features. Self-guards against the hardware (below), so
    /// it declines cleanly when the consumer iterates it on a non-DVD.
    fn unlock_bus(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &crate::UnlockCtx,
    ) -> std::result::Result<crate::Unlocked, crate::UnlockError> {
        // Self-guard against the hardware, not just the caller-declared
        // DiscKind: refuse (NotApplicable) without issuing any CSS CDB when
        // the drive doesn't report a DVD profile.
        if !mounted_disc_is_dvd(scsi)? {
            tracing::debug!(
                target: "freemkv::css",
                phase = "dvd_unlocker_not_dvd",
                "DvdUnlocker invoked on a non-DVD profile; refusing (NotApplicable)"
            );
            return Err(crate::UnlockError::NotApplicable);
        }
        // The bus-auth handshake is what unlocks scrambled-sector reads; the lba
        // is not consumed by the unlock primitive (the disc-key REPORT KEY is
        // best-effort). CSS yields neither a Volume ID nor an AACS bus key.
        unlock_css_reads(scsi, 0)?;
        Ok(crate::Unlocked::default())
    }
}

// Probes GET CONFIGURATION current-profile (DVD family 0x0010..=0x001F) so
// DvdUnlocker can self-verify against the drive rather than trust the
// caller's DiscKind. See docs/css-mod.md#mounted_disc_is_dvd.
fn mounted_disc_is_dvd(
    scsi: &mut dyn ScsiTransport,
) -> std::result::Result<bool, crate::UnlockError> {
    // RT=0: the 8-byte feature header carries the Current Profile in bytes 6-7.
    let cdb = [
        crate::scsi::SCSI_GET_CONFIGURATION,
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
        Ok(r) if r.status == 0 && r.bytes_transferred >= 8 => {
            let profile = ((buf[6] as u16) << 8) | buf[7] as u16;
            Ok((0x0010..=0x001F).contains(&profile))
        }
        // A drive sense or a short reply genuinely means "can't tell / not a
        // DVD" — decline, but say so.
        Ok(r) => {
            tracing::debug!(
                target: "freemkv::css",
                phase = "dvd_profile_probe_inconclusive",
                status = r.status,
                bytes_transferred = r.bytes_transferred,
                "GET CONFIGURATION did not report a current profile"
            );
            Ok(false)
        }
        Err(e) => {
            let err = crate::css::error::step_err(e);
            tracing::warn!(
                target: "freemkv::css",
                phase = "dvd_profile_probe_failed",
                error_code = err.code(),
                transport_failure = err.is_transport_failure(),
                "GET CONFIGURATION failed while probing for a DVD"
            );
            Err(crate::UnlockError::from(err))
        }
    }
}

fn unlock_css_reads_inner(scsi: &mut dyn ScsiTransport, _lba: u32) -> Result<()> {
    tracing::debug!(target: "freemkv::css", "css unlock: begin");
    // The bus-auth challenge-response sets ASF=1, which is what opens
    // scrambled-sector reads. It's the only required step, so a failure
    // here is fatal.
    let agid = establish_authenticated_session(scsi).inspect_err(|e| {
        tracing::warn!(target: "freemkv::css", error_code = e.code(), "css unlock: bus authentication failed");
    })?;
    tracing::debug!(target: "freemkv::css", agid, "css unlock: bus authentication ok");
    // Disc-key REPORT KEY: best-effort only, for firmware that ties part of
    // its read-unlock to it; bytes are unused and failure is non-fatal.
    // See docs/css-mod.md#disc-key-report-key (7014 bug history).
    if let Err(e) = read_disc_key(scsi, agid) {
        tracing::debug!(target: "freemkv::css", error_code = e.code(), "css unlock: disc-key REPORT KEY skipped (non-fatal)");
    }
    tracing::debug!(target: "freemkv::css", "css unlock: ok");
    Ok(())
}

// ── Step 1: Bus Authentication ────────────────────────────────────────────

// Runs the CSS bus-auth handshake to set ASF=1 (invalidate AGIDs, allocate,
// challenge/response). Returns the AGID; no bus key is derived. See docs/css-mod.md.
fn establish_authenticated_session(scsi: &mut dyn ScsiTransport) -> Result<u8> {
    // Invalidate all AGIDs via REPORT KEY format 0x3F. This is also what makes
    // an abandoned AGID self-heal — which is not a reason to abandon one.
    for agid in 0..4u8 {
        release_agid(scsi, agid);
    }

    // Allocate AGID
    let mut buf = [0u8; 8];
    css_scsi(
        scsi,
        &report_key_cdb(0, 0x00, 8),
        DataDirection::FromDevice,
        &mut buf,
        8,
    )?;
    let agid = (buf[7] >> 6) & 0x03;

    // From here on we hold the AGID; release it on any failure (see
    // [`release_agid`]) instead of abandoning it.
    let r = authenticate_with_agid(scsi, agid);
    if r.is_err() {
        release_agid(scsi, agid);
    }
    r.map(|()| agid)
}

/// Release an AGID (REPORT KEY format 0x3F). Best-effort: a failure to release
/// is not a failure of the operation that is already failing.
fn release_agid(scsi: &mut dyn ScsiTransport, agid: u8) {
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_REPORT_KEY;
    cdb[10] = (agid << 6) | 0x3F;
    let mut buf = [0u8; 8];
    let _ = scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000);
}

/// The challenge-response half of [`establish_authenticated_session`], with the
/// AGID already allocated. Split out so its caller can release the AGID on any
/// failure without a Drop guard or a release at each early return.
fn authenticate_with_agid(scsi: &mut dyn ScsiTransport, agid: u8) -> Result<()> {
    // Host sends challenge. The spec wants a fresh per-session random nonce,
    // not a fixed constant — a predictable challenge weakens the bus-auth
    // handshake.
    let mut host_challenge = [0u8; 10];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut host_challenge);
    }
    let mut hc_buf = [0u8; 16];
    hc_buf[0] = 0x00;
    hc_buf[1] = 0x0E;
    for i in 0..10 {
        hc_buf[4 + i] = host_challenge[9 - i];
    }
    css_scsi(
        scsi,
        &send_key_cdb(agid, 0x01, 16),
        DataDirection::ToDevice,
        &mut hc_buf,
        0,
    )?;

    // Get Key1 from drive
    let mut dk_buf = [0u8; 12];
    css_scsi(
        scsi,
        &report_key_cdb(agid, 0x02, 12),
        DataDirection::FromDevice,
        &mut dk_buf,
        12,
    )?;
    let mut key1 = [0u8; 5];
    for i in 0..5 {
        key1[i] = dk_buf[4 + (4 - i)];
    }

    // Brute-force variant (0-31)
    let mut variant: Option<u8> = None;
    for v in 0..32u8 {
        if crypt_key(0, v, &host_challenge) == key1 {
            variant = Some(v);
            break;
        }
    }
    let variant = variant.ok_or(Error::CssAuthFailed)?;

    // Get drive challenge
    let mut dc_buf = [0u8; 16];
    css_scsi(
        scsi,
        &report_key_cdb(agid, 0x01, 16),
        DataDirection::FromDevice,
        &mut dc_buf,
        16,
    )?;
    let mut drive_challenge = [0u8; 10];
    for i in 0..10 {
        drive_challenge[i] = dc_buf[4 + (9 - i)];
    }

    // Compute Key2 and send it
    let key2 = crypt_key(1, variant, &drive_challenge);
    let mut hk_buf = [0u8; 12];
    hk_buf[0] = 0x00;
    hk_buf[1] = 0x0A;
    for i in 0..5 {
        hk_buf[4 + i] = key2[4 - i];
    }
    css_scsi(
        scsi,
        &send_key_cdb(agid, 0x03, 12),
        DataDirection::ToDevice,
        &mut hk_buf,
        0,
    )?;

    // The authenticated session (ASF=1) is now established — scrambled-sector
    // reads are unlocked. The CSS bus key would be CryptKey(2, variant,
    // key1 || key2), but has no consumer (descrambling is keyless).
    Ok(())
}

// ── Step 2: Disc Key ──────────────────────────────────────────────────────

// Issues READ DVD STRUCTURE format 0x02 (opcode 0xAD) purely for its
// bus-auth side effect; returned bytes are unused. See docs/css-mod.md#read_disc_key.
fn read_disc_key(scsi: &mut dyn ScsiTransport, agid: u8) -> Result<()> {
    // READ DVD STRUCTURE, format 0x02 (disc key), 2048+4 bytes
    let alloc_len: u16 = 2048 + 4;
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_READ_DISC_STRUCTURE;
    // bytes 2-5: address = 0
    cdb[6] = 0; // layer
    cdb[7] = 0x02; // format = disc key
    cdb[8] = (alloc_len >> 8) as u8;
    cdb[9] = alloc_len as u8;
    cdb[10] = agid << 6;

    // Best-effort by design (the caller logs and continues), but a transport
    // fault still has to be distinguishable from a drive that declined.
    let mut buf = vec![0u8; alloc_len as usize];
    css_scsi(scsi, &cdb, DataDirection::FromDevice, &mut buf, 0)?;

    Ok(())
}

// ── CSSCryptKey ───────────────────────────────────────────────────────────

fn crypt_key(key_type: usize, variant: u8, challenge: &[u8; 10]) -> [u8; 5] {
    // key_type indexes PERM_CHALLENGE ([_;3]); variant indexes
    // VARIANTS/PERM_VARIANT ([_;32]). Asserts turn an out-of-bounds index
    // into an explicit precondition violation. See docs/css-mod.md.
    debug_assert!(key_type < 3, "crypt_key: key_type out of range");
    debug_assert!((variant as usize) < 32, "crypt_key: variant out of range");
    let perm = &PERM_CHALLENGE[key_type];
    let mut scratch = [0u8; 10];
    for i in 0..10 {
        scratch[i] = challenge[perm[i]];
    }

    let css_variant = match key_type {
        0 => variant as usize,
        1 => PERM_VARIANT[0][variant as usize] as usize,
        _ => PERM_VARIANT[1][variant as usize] as usize,
    };

    let cse = VARIANTS[css_variant] ^ CRYPT_TAB2[css_variant];

    let mut tmp1 = [0u8; 5];
    for i in 0..5 {
        tmp1[i] = scratch[5 + i] ^ SECRET[i] ^ CRYPT_TAB2[i];
    }

    let mut lfsr0: u32 = ((tmp1[0] as u32) << 17)
        | ((tmp1[1] as u32) << 9)
        | (((tmp1[2] as u32) & !7) << 1)
        | 8
        | (tmp1[2] as u32 & 7);

    let mut lfsr1: u32 = ((tmp1[3] as u32) << 9) | 0x100 | (tmp1[4] as u32);

    let mut bits = [0u8; 30];
    let mut carry: u32 = 0;
    for idx in (0..30).rev() {
        let mut val: u8 = 0;
        for bit in 0..8u8 {
            let lfsr0_out = ((lfsr0 >> 24) ^ (lfsr0 >> 21) ^ (lfsr0 >> 20) ^ (lfsr0 >> 12)) & 1;
            lfsr0 = ((lfsr0 << 1) | lfsr0_out) & 0x1FFFFFF;

            let lfsr1_out = ((lfsr1 >> 16) ^ (lfsr1 >> 2)) & 1;
            lfsr1 = ((lfsr1 << 1) | lfsr1_out) & 0x1FFFF;

            let combined = ((!lfsr1_out) & 1) + carry + ((!lfsr0_out) & 1);
            carry = (combined >> 1) & 1;
            val |= ((combined & 1) as u8) << bit;
        }
        bits[idx] = val;
    }

    let mut tmp1 = [scratch[0], scratch[1], scratch[2], scratch[3], scratch[4]];
    let mut tmp2 = [0u8; 5];

    // Round 1: bits[25..29] ^ scratch -> tmp1 (term from original scratch)
    {
        let mut term: u8 = 0;
        for i in (0..5usize).rev() {
            let idx = (bits[25 + i] ^ tmp1[i]) as usize;
            let idx2 = (CRYPT_TAB1[idx] ^ (!CRYPT_TAB2[idx]) ^ cse) as usize;
            tmp1[i] = CRYPT_TAB2[idx2] ^ CRYPT_TAB3[idx2] ^ term;
            term = scratch[i]; // original challenge, NOT modified tmp1
        }
        tmp1[4] ^= tmp1[0];
    }

    // Round 2
    {
        let mut term: u8 = 0;
        for i in (0..5usize).rev() {
            let idx = (bits[20 + i] ^ tmp1[i]) as usize;
            let idx2 = (CRYPT_TAB1[idx] ^ (!CRYPT_TAB2[idx]) ^ cse) as usize;
            tmp2[i] = CRYPT_TAB2[idx2] ^ CRYPT_TAB3[idx2] ^ term;
            term = tmp1[i];
        }
        tmp2[4] ^= tmp2[0];
    }

    // Round 3 (uses CRYPT_TAB0)
    {
        let mut term: u8 = 0;
        for i in (0..5usize).rev() {
            let idx = (bits[15 + i] ^ tmp2[i]) as usize;
            let idx2 = (CRYPT_TAB1[idx] ^ (!CRYPT_TAB2[idx]) ^ cse) as usize;
            let idx3 = (CRYPT_TAB2[idx2] ^ CRYPT_TAB3[idx2] ^ term) as usize;
            tmp1[i] = CRYPT_TAB0[idx3] ^ CRYPT_TAB2[idx3];
            term = tmp2[i];
        }
        tmp1[4] ^= tmp1[0];
    }

    // Round 4 (uses CRYPT_TAB0)
    {
        let mut term: u8 = 0;
        for i in (0..5usize).rev() {
            let idx = (bits[10 + i] ^ tmp1[i]) as usize;
            let idx2 = (CRYPT_TAB1[idx] ^ (!CRYPT_TAB2[idx]) ^ cse) as usize;
            let idx3 = (CRYPT_TAB2[idx2] ^ CRYPT_TAB3[idx2] ^ term) as usize;
            tmp2[i] = CRYPT_TAB0[idx3] ^ CRYPT_TAB2[idx3];
            term = tmp1[i];
        }
        tmp2[4] ^= tmp2[0];
    }

    // Round 5
    {
        let mut term: u8 = 0;
        for i in (0..5usize).rev() {
            let idx = (bits[5 + i] ^ tmp2[i]) as usize;
            let idx2 = (CRYPT_TAB1[idx] ^ (!CRYPT_TAB2[idx]) ^ cse) as usize;
            tmp1[i] = CRYPT_TAB2[idx2] ^ CRYPT_TAB3[idx2] ^ term;
            term = tmp2[i];
        }
        tmp1[4] ^= tmp1[0];
    }

    // Round 6
    let mut key = [0u8; 5];
    {
        let mut term: u8 = 0;
        for i in (0..5usize).rev() {
            let idx = (bits[i] ^ tmp1[i]) as usize;
            let idx2 = (CRYPT_TAB1[idx] ^ (!CRYPT_TAB2[idx]) ^ cse) as usize;
            key[i] = CRYPT_TAB2[idx2] ^ CRYPT_TAB3[idx2] ^ term;
            term = tmp1[i];
        }
    }

    key
}

// ── SCSI CDB builders ────────────────────────────────────────────────────

fn report_key_cdb(agid: u8, format: u8, alloc_len: u16) -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_REPORT_KEY;
    cdb[8] = (alloc_len >> 8) as u8;
    cdb[9] = alloc_len as u8;
    cdb[10] = (agid << 6) | (format & 0x3F);
    cdb
}

fn send_key_cdb(agid: u8, format: u8, param_len: u16) -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_SEND_KEY;
    cdb[8] = (param_len >> 8) as u8;
    cdb[9] = param_len as u8;
    cdb[10] = (agid << 6) | (format & 0x3F);
    cdb
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // SECURITY REGRESSION GUARD: scans source files for a `tracing` field
    // binding a forbidden key name to a value expression (only a string
    // literal or `_fp` field is allowed). See docs/css-mod.md#key-guard.
    #[test]
    fn no_key_bytes_in_instrumentation() {
        use std::path::Path;

        // Forbidden field names whose VALUES must never be logged.
        const FORBIDDEN: &[&str] = &[
            "title_key",
            "disc_key",
            "unit_key",
            "vuk",
            "player_key",
            "bus_key",
        ];

        fn scan_dir(dir: &Path, forbidden: &[&str], violations: &mut Vec<String>) {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    scan_dir(&path, forbidden, violations);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let src = match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                for (lineno, line) in src.lines().enumerate() {
                    let trimmed = line.trim_start();
                    // Only inspect tracing instrumentation lines.
                    if !(trimmed.contains("tracing::")
                        || trimmed.starts_with("debug!")
                        || trimmed.starts_with("info!")
                        || trimmed.starts_with("warn!")
                        || trimmed.starts_with("trace!")
                        || trimmed.starts_with("error!"))
                    {
                        continue;
                    }
                    // This guard test itself contains the forbidden names.
                    if path.file_name().and_then(|n| n.to_str()) == Some("auth.rs")
                        && line.contains("FORBIDDEN")
                    {
                        continue;
                    }
                    for &name in forbidden {
                        // A fingerprint field (`<name>_fp = ...`) is allowed;
                        // match `<name>` then `=` with a value that is not a
                        // string-literal redaction marker.
                        if let Some(idx) = line.find(name) {
                            let after = &line[idx + name.len()..];
                            let after = after.trim_start();
                            // `<name>_fp` / `<name>_id` etc. are safe.
                            if after.starts_with('_') {
                                continue;
                            }
                            // Must be a field binding `name = ...`.
                            let Some(rest) = after.strip_prefix('=') else {
                                continue;
                            };
                            let rest = rest.trim_start();
                            // Redaction string literal is the only allowed value.
                            if rest.starts_with('"') {
                                continue;
                            }
                            // Anything else (`%expr`, `?expr`, bare expr) leaks bytes.
                            violations.push(format!(
                                "{}:{}: forbidden key field `{}` logged with a value: {}",
                                path.display(),
                                lineno + 1,
                                name,
                                line.trim()
                            ));
                        }
                    }
                }
            }
        }

        // Scan this crate's `src` plus sibling workspace crates so the
        // guard covers everything that can reach CSS/AACS internals.
        // Missing sibling dirs (standalone builds) are simply skipped.
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.parent().unwrap_or(manifest);
        let mut violations = Vec::new();
        scan_dir(&manifest.join("src"), FORBIDDEN, &mut violations);
        for sibling in ["autorip", "freemkv", "freemkv-keysources"] {
            let dir = workspace.join(sibling).join("src");
            if dir.is_dir() {
                scan_dir(&dir, FORBIDDEN, &mut violations);
            }
        }
        assert!(
            violations.is_empty(),
            "key material logged in instrumentation:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn crypt_key_is_deterministic() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        for v in 0..32u8 {
            let r1 = crypt_key(0, v, &challenge);
            let r2 = crypt_key(0, v, &challenge);
            assert_eq!(r1, r2);
        }
    }

    #[test]
    fn crypt_key_varies_by_variant() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_ne!(crypt_key(0, 0, &challenge), crypt_key(0, 1, &challenge));
    }

    #[test]
    fn crypt_key_varies_by_type() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_ne!(crypt_key(0, 5, &challenge), crypt_key(1, 5, &challenge));
    }

    #[test]
    fn crypt_key_nonzero() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        for v in 0..32u8 {
            assert_ne!(crypt_key(0, v, &challenge), [0u8; 5]);
        }
    }

    // ── CSS constant-table integrity ───────────────────────────────────────

    // Each PERM_CHALLENGE row must be a permutation of indices 0..10; a
    // non-permutation would drop/duplicate bytes. See docs/css-mod.md#perm-challenge-rows.
    #[test]
    fn perm_challenge_rows_are_permutations() {
        for (row, perm) in PERM_CHALLENGE.iter().enumerate() {
            let mut seen = [false; 10];
            for &idx in perm.iter() {
                assert!(idx < 10, "PERM_CHALLENGE[{row}] index {idx} out of range");
                assert!(!seen[idx], "PERM_CHALLENGE[{row}] duplicates index {idx}");
                seen[idx] = true;
            }
            assert!(
                seen.iter().all(|&b| b),
                "PERM_CHALLENGE[{row}] misses an index"
            );
        }
    }

    // Each PERM_VARIANT row must map the 32 variants to 32 distinct 5-bit
    // values; a collision would make two variants indistinguishable.
    // See docs/css-mod.md#perm-variant-rows.
    #[test]
    fn perm_variant_rows_are_permutations_of_0_31() {
        for (row, perm) in PERM_VARIANT.iter().enumerate() {
            let mut seen = [false; 32];
            for &v in perm.iter() {
                let v = v as usize;
                assert!(v < 32, "PERM_VARIANT[{row}] value {v} out of 0..32");
                assert!(!seen[v], "PERM_VARIANT[{row}] duplicates {v}");
                seen[v] = true;
            }
            assert!(
                seen.iter().all(|&b| b),
                "PERM_VARIANT[{row}] misses a value"
            );
        }
    }

    // ── crypt_key behaviour ────────────────────────────────────────────────

    // crypt_key's result must depend on every challenge byte: flipping any
    // single byte must change the output. See docs/css-mod.md#crypt-key-byte-dependence.
    #[test]
    fn crypt_key_depends_on_every_challenge_byte() {
        let base: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let base_out = crypt_key(0, 5, &base);
        for i in 0..10 {
            let mut c = base;
            c[i] ^= 0x55;
            assert_ne!(
                crypt_key(0, 5, &c),
                base_out,
                "flipping challenge byte {i} did not change the bus-key derivation"
            );
        }
    }

    // crypt_key(0, v, ..) must be distinct for each of the 32 variants:
    // bus-auth brute-forces the variant by matching against key1, so a
    // collision could select the wrong one. See docs/css-mod.md.
    #[test]
    fn crypt_key_type0_distinct_per_variant() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut outs = Vec::new();
        for v in 0..32u8 {
            let k = crypt_key(0, v, &challenge);
            assert!(
                !outs.contains(&k),
                "variant {v} collides with an earlier variant"
            );
            outs.push(k);
        }
    }

    // crypt_key's `key_type < 3` debug_assert must fire for key_type 3
    // (which would otherwise index PERM_CHALLENGE out of bounds).
    // See docs/css-mod.md#crypt-key-preconditions.
    #[test]
    #[should_panic]
    fn crypt_key_rejects_out_of_range_key_type() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let _ = crypt_key(3, 0, &challenge);
    }

    // crypt_key's `variant < 32` debug_assert must fire for variant 32
    // (which would otherwise index VARIANTS/PERM_VARIANT out of bounds).
    // See docs/css-mod.md#crypt-key-preconditions.
    #[test]
    #[should_panic]
    fn crypt_key_rejects_out_of_range_variant() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let _ = crypt_key(0, 32, &challenge);
    }

    // ── SCSI CDB builders (MMC REPORT KEY / SEND KEY layout) ───────────────

    // report_key_cdb encodes a 12-byte MMC REPORT KEY (opcode 0xA4) CDB:
    // byte 0=0xA4, bytes 8-9=big-endian len, byte 10=(AGID<<6)|(format&0x3F).
    #[test]
    fn report_key_cdb_matches_mmc_layout() {
        let cdb = report_key_cdb(0b10, 0x04, 0x010C); // AGID=2, format=0x04, len=268
        assert_eq!(cdb[0], 0xA4, "REPORT KEY opcode");
        assert_eq!(cdb[8], 0x01, "alloc_len high byte (big-endian)");
        assert_eq!(cdb[9], 0x0C, "alloc_len low byte");
        assert_eq!(
            cdb[10],
            (0b10 << 6) | 0x04,
            "AGID in bits 6-7, format in bits 0-5"
        );
        // Every other byte must be zero.
        for (i, &b) in cdb.iter().enumerate() {
            if ![0, 8, 9, 10].contains(&i) {
                assert_eq!(b, 0, "CDB byte {i} must be zero");
            }
        }
        assert_eq!(cdb.len(), 12, "REPORT KEY is a 12-byte CDB");
    }

    // The key-format field is masked to 6 bits so a format with high bits
    // set (e.g. 0xFF) cannot corrupt the AGID bits of byte 10.
    // See docs/css-mod.md#cdb-builders.
    #[test]
    fn report_key_cdb_masks_format_to_6_bits() {
        let cdb = report_key_cdb(0, 0xFF, 8);
        assert_eq!(cdb[10], 0x3F, "format masked to 6 bits, AGID stays 0");
    }

    // send_key_cdb encodes a 12-byte MMC SEND KEY (opcode 0xA3) CDB with the
    // parameter-list length at bytes 8-9 (big-endian) and AGID/format at
    // byte 10. See docs/css-mod.md#cdb-builders.
    #[test]
    fn send_key_cdb_matches_mmc_layout() {
        let cdb = send_key_cdb(0b11, 0x03, 0x000C); // AGID=3, format=3, param_len=12
        assert_eq!(cdb[0], 0xA3, "SEND KEY opcode");
        assert_eq!(cdb[8], 0x00, "param_len high byte");
        assert_eq!(cdb[9], 0x0C, "param_len low byte");
        assert_eq!(
            cdb[10],
            (0b11 << 6) | 0x03,
            "AGID bits 6-7, format bits 0-5"
        );
        assert_eq!(cdb.len(), 12);
    }

    // Allocation length > 255 must split across bytes 8 (high) and 9 (low)
    // as a 16-bit big-endian field, e.g. 0x0804 (the disc-key block size).
    // See docs/css-mod.md#cdb-builders.
    #[test]
    fn report_key_cdb_alloc_len_is_16bit_big_endian() {
        let cdb = report_key_cdb(0, 0x00, 0x0804);
        assert_eq!(cdb[8], 0x08, "high byte of 2052-byte transfer");
        assert_eq!(cdb[9], 0x04, "low byte of 2052-byte transfer");
    }

    // The unlocker's user-facing name is "DVD" (the medium), not "CSS" (the
    // scheme); apps render the unlocker report from this name, so it is a
    // stable contract.
    #[test]
    fn dvd_unlocker_is_named_dvd() {
        use crate::Unlocker;
        assert_eq!(DvdUnlocker::new().name(), "DVD");
    }

    /// `Default` must delegate to `new()` — there is only one way to build a
    /// `DvdUnlocker` (it is a unit struct), so this pins the two never drift.
    #[test]
    #[allow(clippy::default_constructed_unit_structs)]
    fn default_matches_new() {
        let _ = DvdUnlocker::default();
        let _ = DvdUnlocker::new();
    }

    /// DvdUnlocker provides bus removal only — it never provides drive features.
    #[test]
    fn dvd_unlocker_provides_no_features() {
        use crate::scsi::{DataDirection, ScsiResult};
        use crate::{DiscKind, DriveId, UnlockCtx, UnlockError, Unlocker};
        struct DeadTransport;
        impl ScsiTransport for DeadTransport {
            fn execute(
                &mut self,
                _cdb: &[u8],
                _dir: DataDirection,
                _data: &mut [u8],
                _timeout_ms: u32,
            ) -> crate::scsi::Result<ScsiResult> {
                panic!("unlock_features must not touch the transport");
            }
        }
        let id = DriveId::default();
        let mut t = DeadTransport;
        let r =
            DvdUnlocker::new().unlock_features(&mut t, &UnlockCtx::new(&id, DiscKind::Css, &[]));
        assert_eq!(r.unwrap_err(), UnlockError::NotApplicable);
    }

    // Defense in depth: even when the caller declares `DiscKind::Css`,
    // DvdUnlocker self-verifies against GET CONFIGURATION; a BD profile
    // must yield NotApplicable with no CSS CDB issued.
    #[test]
    fn dvd_unlocker_self_guards_against_non_dvd() {
        use crate::scsi::{DataDirection, ScsiResult};
        use crate::{DiscKind, DriveId, UnlockCtx, UnlockError, Unlocker};

        /// Reports a BD-ROM profile (0x0040) to GET CONFIGURATION and counts any
        /// other CDB (i.e. CSS bus-auth activity).
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
            ) -> crate::scsi::Result<ScsiResult> {
                if cdb[0] == crate::scsi::SCSI_GET_CONFIGURATION {
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

        let id = DriveId {
            vendor_id: "FAKEVNDR".to_string(),
            ..Default::default()
        };

        let mut t = BdTransport { non_config_cdbs: 0 };
        let r = DvdUnlocker::new().unlock_bus(&mut t, &UnlockCtx::new(&id, DiscKind::Css, &[]));
        assert_eq!(
            r.unwrap_err(),
            UnlockError::NotApplicable,
            "a BD-profile drive must be refused"
        );
        assert_eq!(
            t.non_config_cdbs, 0,
            "no CSS CDB may be issued at a non-DVD drive"
        );
    }
    // ── Transport-contract tests ────────────────────────────────────────────

    use crate::scsi::mock::{MockTransport, Reply};
    use crate::{DiscKind, DriveId, UnlockCtx, UnlockError, Unlocker};

    // Defect-7 regression: a transport fault on the first probe command
    // must abort as Transport, not fall through to NotApplicable (which
    // let the consumer keep probing a dead bus). See docs/css-mod.md.
    #[test]
    fn transport_fault_probing_for_a_dvd_aborts() {
        let id = DriveId::default();
        let mut t = MockTransport::always(Reply::TransportFault);
        let r = DvdUnlocker::new().unlock_bus(&mut t, &UnlockCtx::new(&id, DiscKind::Css, &[]));
        assert_eq!(r.unwrap_err(), UnlockError::Transport);
        assert_eq!(
            t.calls(),
            1,
            "must abort on the first command, not probe on"
        );
    }

    /// A drive that REFUSES GET CONFIGURATION (CHECK CONDITION, delivered as
    /// `Ok` per the contract) is inconclusive, not a dead bus → decline. Guards
    /// against over-correcting defect 7 into "any probe failure aborts the rip".
    #[test]
    fn check_condition_probing_for_a_dvd_declines() {
        let id = DriveId::default();
        let mut t = MockTransport::always(Reply::illegal_request());
        let r = DvdUnlocker::new().unlock_bus(&mut t, &UnlockCtx::new(&id, DiscKind::Css, &[]));
        assert_eq!(r.unwrap_err(), UnlockError::NotApplicable);
    }

    // Defect-2 regression: a DVD is mounted, then the bus dies mid
    // bus-auth — must abort as Transport, not collapse to CssAuthFailed /
    // NotApplicable. See docs/css-mod.md.
    #[test]
    fn transport_fault_during_bus_auth_aborts() {
        let id = DriveId::default();
        // GET CONFIGURATION reports a DVD-ROM profile (0x0010), then the bus dies.
        let mut config = vec![0u8; 8];
        config[6] = 0x00;
        config[7] = 0x10;
        let mut t = MockTransport::scripted(vec![Reply::good(config)], Reply::TransportFault);
        let r = DvdUnlocker::new().unlock_bus(&mut t, &UnlockCtx::new(&id, DiscKind::Css, &[]));
        assert_eq!(r.unwrap_err(), UnlockError::Transport);
    }

    /// The same shape with the drive REFUSING the bus-auth commands: a CSS
    /// auth failure is a fall-through, not an abort.
    #[test]
    fn drive_refusing_bus_auth_is_not_applicable() {
        let id = DriveId::default();
        let mut config = vec![0u8; 8];
        config[7] = 0x10;
        let mut t = MockTransport::scripted(vec![Reply::good(config)], Reply::illegal_request());
        let r = DvdUnlocker::new().unlock_bus(&mut t, &UnlockCtx::new(&id, DiscKind::Css, &[]));
        assert_eq!(r.unwrap_err(), UnlockError::NotApplicable);
    }

    // A CHECK CONDITION on AGID allocation must not let the handshake carry
    // on off the caller's own zero-filled buffer; catches a dropped
    // `status` check in `css_scsi`.
    #[test]
    fn agid_allocation_check_condition_fails_the_auth() {
        // 4 AGID invalidations are best-effort; the 5th command is the alloc.
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
            ],
            Reply::illegal_request(),
        );
        let e = establish_authenticated_session(&mut t).expect_err("refused alloc");
        assert!(matches!(e, Error::CssAuthFailed));
    }

    // Defect 18: an AGID lost to a failed challenge must be RELEASED
    // (REPORT KEY format 0x3F), not abandoned, even though a drive's four
    // AGIDs self-heal on the next session's invalidation pass.
    #[test]
    fn a_failed_handshake_releases_the_agid_it_allocated() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(vec![0u8; 8]), // 4 × AGID invalidate
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]), // AGID allocated
            ],
            Reply::illegal_request(), // every challenge step is refused
        );
        establish_authenticated_session(&mut t).expect_err("refused challenge");
        let last = t.cdbs.last().expect("commands were issued");
        assert_eq!(last[0], crate::scsi::SCSI_REPORT_KEY);
        assert_eq!(last[10] & 0x3F, 0x3F, "AGID released on the failure path");
    }

    /// A short AGID-allocation response is equally unusable — the AGID would be
    /// read out of bytes the drive never sent.
    #[test]
    fn short_agid_allocation_fails_the_auth() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
                Reply::good(vec![0u8; 8]),
            ],
            Reply::short(vec![0u8; 8], 3),
        );
        let e = establish_authenticated_session(&mut t).expect_err("short alloc");
        assert!(matches!(e, Error::CssAuthFailed));
    }

    // ── authenticate_with_agid step failures ────────────────────────────────

    /// The drive refuses the host-challenge SEND KEY (step 1) — the very first
    /// command `authenticate_with_agid` issues.
    #[test]
    fn host_challenge_send_failure_fails_the_auth() {
        let mut t =
            MockTransport::scripted(vec![Reply::illegal_request()], Reply::illegal_request());
        let e = authenticate_with_agid(&mut t, 0).expect_err("refused host challenge");
        assert!(matches!(e, Error::CssAuthFailed));
        assert_eq!(t.calls(), 1, "must not proceed past the first refused step");
    }

    /// The host challenge SEND KEY succeeds but the Key1 REPORT KEY (step 2) is
    /// refused.
    #[test]
    fn key1_report_failure_fails_the_auth() {
        let mut t = MockTransport::scripted(
            vec![Reply::good(vec![]), Reply::illegal_request()],
            Reply::illegal_request(),
        );
        let e = authenticate_with_agid(&mut t, 0).expect_err("refused Key1 report");
        assert!(matches!(e, Error::CssAuthFailed));
        assert_eq!(t.calls(), 2);
    }

    /// Both SCSI steps succeed but the drive's Key1 does not match any of the
    /// 32 CryptKey variants for the (randomly generated) host challenge — the
    /// brute-force loop exhausts and `variant.ok_or(CssAuthFailed)` fires.
    #[test]
    fn key1_matching_no_variant_fails_the_auth() {
        let mut t = MockTransport::scripted(
            vec![Reply::good(vec![]), Reply::good(vec![0xABu8; 12])],
            Reply::illegal_request(),
        );
        let e = authenticate_with_agid(&mut t, 0).expect_err("no variant matches");
        assert!(matches!(e, Error::CssAuthFailed));
        assert_eq!(
            t.calls(),
            2,
            "the brute-force loop issues no further SCSI commands"
        );
    }

    // Host challenge + Key1 succeed but the drive-challenge REPORT KEY
    // (step 3) is refused; distinct from the step-2 and step-4 failure
    // tests, each pinning a different `css_scsi` call site's `?`.
    #[test]
    fn drive_challenge_report_failure_fails_the_auth() {
        struct FailAtDriveChallenge(FakeDvdDrive);
        impl ScsiTransport for FailAtDriveChallenge {
            fn execute(
                &mut self,
                cdb: &[u8],
                dir: DataDirection,
                data: &mut [u8],
                timeout_ms: u32,
            ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
                if cdb[0] == crate::scsi::SCSI_REPORT_KEY && cdb[10] & 0x3F == 0x01 {
                    return Ok(crate::scsi::ScsiResult {
                        status: 0x02,
                        bytes_transferred: 0,
                        sense: [0u8; 32],
                    });
                }
                self.0.execute(cdb, dir, data, timeout_ms)
            }
        }
        let mut t = FailAtDriveChallenge(FakeDvdDrive {
            variant: 4,
            host_challenge: [0u8; 10],
        });
        let e = authenticate_with_agid(&mut t, 0).expect_err("refused drive challenge");
        assert!(matches!(e, Error::CssAuthFailed));
    }

    /// Host challenge, Key1, and the drive challenge all succeed, but the
    /// Key2 SEND KEY (step 4, the last command in the handshake) is refused.
    #[test]
    fn key2_send_failure_fails_the_auth() {
        struct FailAtKey2Send(FakeDvdDrive);
        impl ScsiTransport for FailAtKey2Send {
            fn execute(
                &mut self,
                cdb: &[u8],
                dir: DataDirection,
                data: &mut [u8],
                timeout_ms: u32,
            ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
                if cdb[0] == crate::scsi::SCSI_SEND_KEY && cdb[10] & 0x3F == 0x03 {
                    return Ok(crate::scsi::ScsiResult {
                        status: 0x02,
                        bytes_transferred: 0,
                        sense: [0u8; 32],
                    });
                }
                self.0.execute(cdb, dir, data, timeout_ms)
            }
        }
        let mut t = FailAtKey2Send(FakeDvdDrive {
            variant: 4,
            host_challenge: [0u8; 10],
        });
        let e = authenticate_with_agid(&mut t, 0).expect_err("refused Key2 send");
        assert!(matches!(e, Error::CssAuthFailed));
    }

    // ── read_disc_key ────────────────────────────────────────────────────────

    /// The best-effort disc-key REPORT KEY is refused — `read_disc_key` must
    /// surface the failure to its caller (who treats it as non-fatal), not
    /// silently return `Ok`.
    #[test]
    fn read_disc_key_refused_is_an_error() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let e = read_disc_key(&mut t, 0).expect_err("drive refused disc-key read");
        assert!(matches!(e, Error::CssAuthFailed));
    }

    /// A transport fault reading the disc key must classify as a transport
    /// failure, not a generic auth failure.
    #[test]
    fn read_disc_key_transport_fault_is_transport_failure() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let e = read_disc_key(&mut t, 0).expect_err("dead bus");
        assert!(e.is_transport_failure());
    }

    // ── Full happy-path bus-auth ────────────────────────────────────────────

    // A fake drive that plays its half of the CSS handshake for real:
    // answers Key1 honestly, and DVD/disc-key probes as success.
    struct FakeDvdDrive {
        variant: u8,
        host_challenge: [u8; 10],
    }

    impl ScsiTransport for FakeDvdDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            use crate::scsi::ScsiResult;
            let ok = |bytes_transferred: usize| ScsiResult {
                status: 0,
                bytes_transferred,
                sense: [0u8; 32],
            };
            match cdb[0] {
                crate::scsi::SCSI_GET_CONFIGURATION => {
                    data[6] = 0x00;
                    data[7] = 0x10; // DVD-ROM current profile
                    Ok(ok(8))
                }
                crate::scsi::SCSI_SEND_KEY => {
                    let format = cdb[10] & 0x3F;
                    if format == 0x01 {
                        // Host challenge: capture it for the Key1 answer.
                        for i in 0..10 {
                            self.host_challenge[i] = data[4 + (9 - i)];
                        }
                    }
                    // format 0x03 (Key2) is accepted unconditionally: the
                    // real handshake never verifies it drive-side in this
                    // primitive (ASF=1 is set on the drive's own say-so).
                    Ok(ok(0))
                }
                crate::scsi::SCSI_REPORT_KEY => {
                    match cdb[10] & 0x3F {
                        0x00 => {
                            // Allocate AGID 0.
                            data[7] = 0x00;
                            Ok(ok(8))
                        }
                        0x02 => {
                            // Key1, honestly derived from the captured challenge.
                            let key1 = crypt_key(0, self.variant, &self.host_challenge);
                            for i in 0..5 {
                                data[4 + (4 - i)] = key1[i];
                            }
                            Ok(ok(12))
                        }
                        0x01 => {
                            // Drive challenge (arbitrary, fixed).
                            let drive_challenge: [u8; 10] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
                            for i in 0..10 {
                                data[4 + (9 - i)] = drive_challenge[i];
                            }
                            Ok(ok(16))
                        }
                        _ => Ok(ok(0)), // 0x3F release, best-effort
                    }
                }
                crate::scsi::SCSI_READ_DISC_STRUCTURE => Ok(ok(2048 + 4)),
                _ => Ok(ok(0)),
            }
        }
    }

    // End-to-end happy path for the bus-auth handshake (AGID, challenge,
    // Key1/Key2, disc-key REPORT KEY), exercising the `Ok` returns that
    // the failure-path tests above never reach.
    #[test]
    fn full_bus_auth_and_disc_key_succeed() {
        let mut t = FakeDvdDrive {
            variant: 7,
            host_challenge: [0u8; 10],
        };
        let agid =
            establish_authenticated_session(&mut t).expect("full bus-auth handshake succeeds");
        assert_eq!(agid, 0);
        read_disc_key(&mut t, agid).expect("disc-key REPORT KEY succeeds");
    }

    // The same happy path through the public `unlock_bus` entry point,
    // proving it returns `Ok(Unlocked::default())` on success — the path
    // every failure-injection test above deliberately avoids.
    #[test]
    fn dvd_unlocker_succeeds_end_to_end() {
        let id = DriveId::default();
        let mut t = FakeDvdDrive {
            variant: 3,
            host_challenge: [0u8; 10],
        };
        let r = DvdUnlocker::new().unlock_bus(&mut t, &UnlockCtx::new(&id, DiscKind::Css, &[]));
        let unlocked = r.expect("full unlock succeeds");
        assert!(unlocked.vid.is_none(), "CSS yields no Volume ID");
        assert!(unlocked.bus_key.is_none(), "CSS yields no AACS bus key");
        assert!(
            !unlocked.drive_unlocked,
            "CSS is a bus-auth unlock, not a firmware drive-unlock"
        );
    }

    /// `unlock_css_reads` (the crate-level public entry point, distinct from
    /// the `DvdUnlocker` wrapper) also succeeds end to end.
    #[test]
    fn unlock_css_reads_succeeds() {
        let mut t = FakeDvdDrive {
            variant: 11,
            host_challenge: [0u8; 10],
        };
        // unlock_css_reads doesn't probe GET CONFIGURATION itself (that's
        // DvdUnlocker's job); it goes straight to bus-auth.
        unlock_css_reads(&mut t, 0).expect("css bus-auth + best-effort disc key succeed");
    }

    // A drive whose bus-auth succeeds but refuses the best-effort disc-key
    // REPORT KEY; `unlock_css_reads_inner` must swallow that failure since
    // the read barrier is already open from bus-auth.
    struct DiscKeyRefusingDrive(FakeDvdDrive);

    impl ScsiTransport for DiscKeyRefusingDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            dir: DataDirection,
            data: &mut [u8],
            timeout_ms: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            if cdb[0] == crate::scsi::SCSI_READ_DISC_STRUCTURE {
                return Ok(crate::scsi::ScsiResult {
                    status: 0x02,
                    bytes_transferred: 0,
                    sense: [0u8; 32],
                });
            }
            self.0.execute(cdb, dir, data, timeout_ms)
        }
    }

    #[test]
    fn disc_key_refusal_is_non_fatal_to_the_overall_unlock() {
        let mut t = DiscKeyRefusingDrive(FakeDvdDrive {
            variant: 5,
            host_challenge: [0u8; 10],
        });
        unlock_css_reads(&mut t, 0)
            .expect("bus-auth succeeded; a refused best-effort disc-key read must not fail it");
    }

    // `crypt_key`'s key_type==2 arm (`PERM_VARIANT[1]`) has no production
    // caller (only 0 and 1 are invoked from `authenticate_with_agid`) but
    // is a pure, directly-testable function.
    #[test]
    fn crypt_key_type2_is_deterministic_and_distinct_from_type1() {
        let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let a = crypt_key(2, 9, &challenge);
        let b = crypt_key(2, 9, &challenge);
        assert_eq!(a, b, "crypt_key(2, ..) must be deterministic");
        assert_ne!(
            crypt_key(1, 9, &challenge),
            crypt_key(2, 9, &challenge),
            "key_type 1 and 2 must diverge (distinct PERM_VARIANT rows)"
        );
    }
}
