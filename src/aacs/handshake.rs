//! AACS bus authentication handshake — ECDH key agreement + bus key derivation.
//!
//! Implements the AACS SCSI authentication protocol to obtain the Volume ID
//! (needed for VUK derivation) and, for AACS 2.0 (UHD), the Read Data Key:
//! allocate an AGID, exchange host/drive certs and key points, verify
//! signatures, derive the bus key via ECDH, then read VID / Read Data Keys.
//!
//! Supports AACS 1.0 and AACS 2.0 cert chains; see docs/aacs-handshake.md
//! for the full step list and cert-fallback rules, and
//! [`run_cert_handshake`] for the dispatch.
use crate::aacs::error::{Error, Result};
use crate::scsi::{DataDirection, ScsiTransport};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

// Map a SCSI-layer error onto a cert/key-specific code, unless it's a
// transport-layer wedge (replug/power-cycle) — else the operator gets sent
// down a keydb/host-cert rabbit hole for what is really a dead transport.
fn handshake_err(err: Error, fallback: Error) -> Error {
    if err.is_scsi_transport_failure() {
        err
    } else {
        fallback
    }
}

// See docs/aacs-handshake.md — why status/length are checked here, at the
// seam, instead of trusting `ScsiTransport::execute`'s `Ok` result.
fn scsi_read(session: &mut dyn ScsiTransport, cdb: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let r = session.execute(cdb, DataDirection::FromDevice, &mut buf, 5_000)?;
    check_status(cdb, &r)?;
    if r.bytes_transferred < len {
        return Err(Error::ShortTransfer {
            opcode: cdb.first().copied().unwrap_or(0),
            expected: len,
            got: r.bytes_transferred,
        });
    }
    Ok(buf)
}

// See docs/aacs-handshake.md — shares scsi_read's status-check reasoning:
// a drive REFUSING the host cert answers `Ok` + CHECK CONDITION.
fn scsi_write(session: &mut dyn ScsiTransport, cdb: &[u8], data: &[u8]) -> Result<()> {
    let mut buf = data.to_vec();
    let r = session.execute(cdb, DataDirection::ToDevice, &mut buf, 5_000)?;
    check_status(cdb, &r)
}

/// Turn a non-GOOD SCSI status into the structured `Scsi` error, carrying the
/// parsed sense so the wedge guard in [`run_cert_handshake`] can still read
/// ILLEGAL REQUEST off it.
fn check_status(cdb: &[u8], r: &crate::scsi::ScsiResult) -> Result<()> {
    if r.status == 0 {
        return Ok(());
    }
    Err(Error::Scsi {
        opcode: cdb.first().copied().unwrap_or(0),
        status: r.status,
        sense: Some(crate::scsi::ScsiSense::from_buf(&r.sense)),
    })
}

/// The 6-byte AACS Host ID of a host certificate, as lowercase hex, for
/// diagnostics only. It lives at `cert[4..10]` (after the 4-byte type/length
/// header, before the reserved bytes and the public key at `[12..]`). Returns
/// `"unknown"` for a short cert. Logs the cert's IDENTITY only — NEVER any
/// private-key or public-key bytes.
fn cert_host_id_hex(cert: &[u8]) -> String {
    if cert.len() < 10 {
        return "unknown".to_string();
    }
    cert[4..10].iter().map(|b| format!("{b:02x}")).collect()
}

// Release an AGID (REPORT KEY format 0x3F). A drive has only four, so avoid
// leaving one held between attempts. Best-effort: a release failure isn't a
// failure of the operation that's already failing.
fn release_agid(session: &mut dyn ScsiTransport, agid: u8) {
    let cdb = cdb_report_key(agid, 0x3F, 2);
    let _ = scsi_read(session, &cdb, 2);
}

// ── AACS 1.0 elliptic curve parameters (160-bit) ───────────────────────────

const EC_P: [u8; 20] = [
    0x9D, 0xC9, 0xD8, 0x13, 0x55, 0xEC, 0xCE, 0xB5, 0x60, 0xBD, 0xB0, 0x9E, 0xF9, 0xEA, 0xE7, 0xC4,
    0x79, 0xA7, 0xD7, 0xDF,
];
const EC_A: [u8; 20] = [
    0x9D, 0xC9, 0xD8, 0x13, 0x55, 0xEC, 0xCE, 0xB5, 0x60, 0xBD, 0xB0, 0x9E, 0xF9, 0xEA, 0xE7, 0xC4,
    0x79, 0xA7, 0xD7, 0xDC,
];
const EC_B: [u8; 20] = [
    0x40, 0x2D, 0xAD, 0x3E, 0xC1, 0xCB, 0xCD, 0x16, 0x52, 0x48, 0xD6, 0x8E, 0x12, 0x45, 0xE0, 0xC4,
    0xDA, 0xAC, 0xB1, 0xD8,
];
const EC_N: [u8; 20] = [
    0x9D, 0xC9, 0xD8, 0x13, 0x55, 0xEC, 0xCE, 0xB5, 0x60, 0xBD, 0xC4, 0x4F, 0x54, 0x81, 0x7B, 0x2C,
    0x7F, 0x5A, 0xB0, 0x17,
];
const EC_GX: [u8; 20] = [
    0x2E, 0x64, 0xFC, 0x22, 0x57, 0x83, 0x51, 0xE6, 0xF4, 0xCC, 0xA7, 0xEB, 0x81, 0xD0, 0xA4, 0xBD,
    0xC5, 0x4C, 0xCE, 0xC6,
];
const EC_GY: [u8; 20] = [
    0x09, 0x14, 0xA2, 0x5D, 0xD0, 0x54, 0x42, 0x88, 0x9D, 0xB4, 0x55, 0xC7, 0xF2, 0x3C, 0x9A, 0x07,
    0x07, 0xF5, 0xCB, 0xB9,
];

// ── AACS 2.0 elliptic curve parameters (P-256 / secp256r1 / NIST prime256v1)

const P256_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];
const P256_A: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
];
const P256_B: [u8; 32] = [
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
];
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
const P256_GX: [u8; 32] = [
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
];
const P256_GY: [u8; 32] = [
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

// AACS 2.0 LA public key for cert verification (P-256), big-endian; used to
// verify type 0x11 drive certificates. Confirmed on-curve by
// `la_anchor_keys_are_on_curve` (the earlier compiled-in value was OFF-CURVE).
const AACS2_LA_PUB_X: [u8; 32] = [
    0xDC, 0x88, 0x52, 0xA0, 0xA7, 0xF0, 0xD0, 0x24, 0xD4, 0xC4, 0xCA, 0xC3, 0x1F, 0x32, 0x5F, 0x90,
    0x3D, 0x0D, 0x23, 0xFC, 0x65, 0xEE, 0xBB, 0x1C, 0x75, 0x90, 0xB9, 0x62, 0xDB, 0x57, 0x43, 0x2E,
];
const AACS2_LA_PUB_Y: [u8; 32] = [
    0xF0, 0xD4, 0x81, 0x42, 0xB3, 0x32, 0xD7, 0x3B, 0x41, 0xE0, 0xFB, 0x84, 0x4C, 0x86, 0xEF, 0x66,
    0x0F, 0x68, 0x4A, 0x05, 0x96, 0xE9, 0xCE, 0x00, 0xC4, 0xD3, 0xFE, 0x6E, 0x24, 0x45, 0x4D, 0xD0,
];

// EXPERIMENTAL gate for the native AACS 2.0 (P-256) AKE at the production API
// boundary. The 2.0 cert byte offsets (`verify_cert_p256`, `cert_pub_key_p256`)
// are PROVISIONAL — self-described unverified against a genuine captured 2.0
// cert (see docs/aacs-handshake.md) — so running the real-anchor P-256 verify
// could silently mis-verify. Keep DISABLED until a captured test vector confirms
// the offsets (see the `#[ignore]`d
// `real_aacs2_cert_verifies_under_the_published_la_anchor`). The AKE code and its
// fall-through wiring stay fully exercised by tests through the anchor-
// parametrised entry points; only the production `run_cert_handshake`
// real-anchor attempt is gated. Flip to `true` once a real cert lands.
const AACS2_P256_EXPERIMENTAL: bool = false;

// AACS 1.0 LA (Licensing Administrator) public key on the 160-bit curve,
// big-endian; validated on-curve and against a genuine LA-signed host cert
// (the prior compiled-in value was OFF-CURVE, rejecting every real cert).
const AACS_LA_PUB_X: [u8; 20] = [
    0x63, 0xC2, 0x1D, 0xFF, 0xB2, 0xB2, 0x79, 0x8A, 0x13, 0xB5, 0x8D, 0x61, 0x16, 0x6C, 0x4E, 0x4A,
    0xAC, 0x8A, 0x07, 0x72,
];
const AACS_LA_PUB_Y: [u8; 20] = [
    0x13, 0x7E, 0xC6, 0x38, 0x81, 0x8F, 0xD9, 0x8F, 0xA4, 0xC3, 0x0B, 0x99, 0x67, 0x28, 0xBF, 0x4B,
    0x91, 0x7F, 0x6A, 0x27,
];

// ── Elliptic curve arithmetic over GF(p) ───────────────────────────────────

#[derive(Clone, Debug)]
struct EcPoint {
    x: BigUint,
    y: BigUint,
    infinity: bool,
}

impl EcPoint {
    fn infinity() -> Self {
        EcPoint {
            x: BigUint::zero(),
            y: BigUint::zero(),
            infinity: true,
        }
    }

    fn new(x: BigUint, y: BigUint) -> Self {
        EcPoint {
            x,
            y,
            infinity: false,
        }
    }

    fn from_bytes(x_bytes: &[u8], y_bytes: &[u8]) -> Self {
        EcPoint::new(
            BigUint::from_bytes_be(x_bytes),
            BigUint::from_bytes_be(y_bytes),
        )
    }
}

/// Modular inverse using extended Euclidean algorithm.
fn mod_inv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_traits::Signed;

    let a = BigInt::from(a.clone());
    let m = BigInt::from(m.clone());

    let (mut old_r, mut r) = (a, m.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());

    while !r.is_zero() {
        let q = &old_r / &r;
        let temp_r = r.clone();
        r = old_r - &q * &r;
        old_r = temp_r;
        let temp_s = s.clone();
        s = old_s - &q * &s;
        old_s = temp_s;
    }

    if old_r != BigInt::one() {
        return None;
    }

    if old_s.is_negative() {
        old_s += &m;
    }
    Some(old_s.to_biguint().unwrap())
}

/// EC point addition on curve y² = x³ + ax + b (mod p).
fn ec_add(p1: &EcPoint, p2: &EcPoint, a: &BigUint, p: &BigUint) -> EcPoint {
    if p1.infinity {
        return p2.clone();
    }
    if p2.infinity {
        return p1.clone();
    }

    if p1.x == p2.x {
        if p1.y == p2.y && !p1.y.is_zero() {
            return ec_double(p1, a, p);
        }
        return EcPoint::infinity();
    }

    // λ = (y2 - y1) / (x2 - x1) mod p
    let dy = if p2.y >= p1.y {
        (&p2.y - &p1.y) % p
    } else {
        (p - (&p1.y - &p2.y) % p) % p
    };
    let dx = if p2.x >= p1.x {
        (&p2.x - &p1.x) % p
    } else {
        (p - (&p1.x - &p2.x) % p) % p
    };

    let dx_inv = match mod_inv(&dx, p) {
        Some(v) => v,
        None => return EcPoint::infinity(),
    };
    let lam = (&dy * &dx_inv) % p;

    // x3 = λ² - x1 - x2 mod p
    let x3 = {
        let lam2 = (&lam * &lam) % p;
        let sum = (&p1.x + &p2.x) % p;
        if lam2 >= sum {
            (lam2 - sum) % p
        } else {
            (p - (sum - lam2) % p) % p
        }
    };

    // y3 = λ(x1 - x3) - y1 mod p
    let y3 = {
        let diff = if p1.x >= x3 {
            (&p1.x - &x3) % p
        } else {
            (p - (&x3 - &p1.x) % p) % p
        };
        let prod = (&lam * &diff) % p;
        if prod >= p1.y {
            (prod - &p1.y) % p
        } else {
            (p - (&p1.y - prod) % p) % p
        }
    };

    EcPoint::new(x3, y3)
}

/// EC point doubling.
fn ec_double(pt: &EcPoint, a: &BigUint, p: &BigUint) -> EcPoint {
    if pt.infinity || pt.y.is_zero() {
        return EcPoint::infinity();
    }

    // λ = (3x² + a) / (2y) mod p
    let three = BigUint::from(3u32);
    let two = BigUint::from(2u32);

    let numerator = (&three * &pt.x * &pt.x + a) % p;
    let denominator = (&two * &pt.y) % p;
    let denom_inv = match mod_inv(&denominator, p) {
        Some(v) => v,
        None => return EcPoint::infinity(),
    };
    let lam = (&numerator * &denom_inv) % p;

    // x3 = λ² - 2x mod p
    let x3 = {
        let lam2 = (&lam * &lam) % p;
        let two_x = (&two * &pt.x) % p;
        if lam2 >= two_x {
            (lam2 - two_x) % p
        } else {
            (p - (two_x - lam2) % p) % p
        }
    };

    // y3 = λ(x - x3) - y mod p
    let y3 = {
        let diff = if pt.x >= x3 {
            (&pt.x - &x3) % p
        } else {
            (p - (&x3 - &pt.x) % p) % p
        };
        let prod = (&lam * &diff) % p;
        if prod >= pt.y {
            (prod - &pt.y) % p
        } else {
            (p - (&pt.y - prod) % p) % p
        }
    };

    EcPoint::new(x3, y3)
}

// Scalar multiplication using double-and-add. Not constant-time (timing
// depends on the secret scalar) — accepted tradeoff for a local, once-per-
// disc handshake. See docs/aacs-handshake.md for the full rationale.
fn ec_mul(k: &BigUint, pt: &EcPoint, a: &BigUint, p: &BigUint) -> EcPoint {
    if k.is_zero() {
        return EcPoint::infinity();
    }

    let mut result = EcPoint::infinity();
    let mut base = pt.clone();
    let mut scalar = k.clone();

    while !scalar.is_zero() {
        if scalar.bit(0) {
            result = ec_add(&result, &base, a, p);
        }
        base = ec_double(&base, a, p);
        scalar >>= 1;
    }

    result
}

// True if (x, y) satisfies y² ≡ x³ + ax + b (mod p) and lies in the field.
// Guards ECDH against the invalid-curve attack: an off-curve drive key point
// can steer the scalar multiply onto a weak curve. Caller must reject on false.
fn point_on_curve(x: &BigUint, y: &BigUint, a: &BigUint, b: &BigUint, p: &BigUint) -> bool {
    if x >= p || y >= p {
        return false;
    }
    let lhs = (y * y) % p;
    let rhs = (((x * x) % p) * x + a * x + b) % p;
    lhs == rhs
}

/// Convert BigUint to fixed-size big-endian bytes, zero-padded.
fn to_bytes_be_padded(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    if bytes.len() >= len {
        bytes[bytes.len() - len..].to_vec()
    } else {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        padded
    }
}

// ── ECDSA ───────────────────────────────────────────────────────────────────

/// ECDSA sign: sign SHA-1(data) with private key on AACS curve.
/// Returns (r, s) each 20 bytes.
fn ecdsa_sign(priv_key: &[u8; 20], data: &[u8]) -> ([u8; 20], [u8; 20]) {
    let p = BigUint::from_bytes_be(&EC_P);
    let a = BigUint::from_bytes_be(&EC_A);
    let n = BigUint::from_bytes_be(&EC_N);
    let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
    let d = BigUint::from_bytes_be(priv_key);

    let hash = Sha1::digest(data);
    let z = BigUint::from_bytes_be(&hash);

    loop {
        // Rejection sampling for k: reducing raw RNG bytes mod n would bias
        // k toward small values (n isn't a power of two), a known ECDSA
        // key-recovery weakness — redraw any candidate >= n instead.
        let mut k_bytes = [0u8; 20];
        use rand::Rng;
        rand::rng().fill_bytes(&mut k_bytes);
        let k = BigUint::from_bytes_be(&k_bytes);
        if k.is_zero() || k >= n {
            continue;
        }

        // R = k × G
        let r_point = ec_mul(&k, &g, &a, &p);
        let r = &r_point.x % &n;
        if r.is_zero() {
            continue;
        }

        // s = k⁻¹(z + r·d) mod n
        let k_inv = match mod_inv(&k, &n) {
            Some(v) => v,
            None => continue,
        };
        let s = (&k_inv * ((&z + &r * &d) % &n)) % &n;
        if s.is_zero() {
            continue;
        }

        let r_bytes = to_bytes_be_padded(&r, 20);
        let s_bytes = to_bytes_be_padded(&s, 20);

        let mut r_out = [0u8; 20];
        let mut s_out = [0u8; 20];
        r_out.copy_from_slice(&r_bytes);
        s_out.copy_from_slice(&s_bytes);

        return (r_out, s_out);
    }
}

/// ECDSA verify: verify signature (r, s) against SHA-1(data) using public key.
fn ecdsa_verify(
    pub_x: &[u8; 20],
    pub_y: &[u8; 20],
    sig_r: &[u8; 20],
    sig_s: &[u8; 20],
    data: &[u8],
) -> bool {
    let p = BigUint::from_bytes_be(&EC_P);
    let a = BigUint::from_bytes_be(&EC_A);
    let b = BigUint::from_bytes_be(&EC_B);
    let n = BigUint::from_bytes_be(&EC_N);
    let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
    let q = EcPoint::from_bytes(pub_x, pub_y);

    // Validate the public key BEFORE using it: without this, Q=(0,0) makes
    // `u2·Q` the point at infinity, so verification collapses to
    // `r == x(u1·G) mod n` — forgeable with no private-key knowledge.
    if !point_on_curve(&q.x, &q.y, &a, &b, &p) {
        return false;
    }

    let r = BigUint::from_bytes_be(sig_r);
    let s = BigUint::from_bytes_be(sig_s);

    if r.is_zero() || r >= n || s.is_zero() || s >= n {
        return false;
    }

    let hash = Sha1::digest(data);
    let z = BigUint::from_bytes_be(&hash);

    let s_inv = match mod_inv(&s, &n) {
        Some(v) => v,
        None => return false,
    };

    let u1 = (&z * &s_inv) % &n;
    let u2 = (&r * &s_inv) % &n;

    let p1 = ec_mul(&u1, &g, &a, &p);
    let p2 = ec_mul(&u2, &q, &a, &p);
    let r_point = ec_add(&p1, &p2, &a, &p);

    if r_point.infinity {
        return false;
    }

    &r_point.x % &n == r
}

// ── P-256 ECDSA (SHA-256) for AACS 2.0 ─────────────────────────────────────

/// ECDSA sign with P-256/SHA-256. Returns (r, s) each 32 bytes.
fn ecdsa_sign_p256(priv_key: &[u8; 32], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    use sha2::{Digest as Sha2Digest, Sha256};

    let p = BigUint::from_bytes_be(&P256_P);
    let a = BigUint::from_bytes_be(&P256_A);
    let n = BigUint::from_bytes_be(&P256_N);
    let g = EcPoint::from_bytes(&P256_GX, &P256_GY);
    let d = BigUint::from_bytes_be(priv_key);

    let hash = Sha256::digest(data);
    let z = BigUint::from_bytes_be(&hash);

    loop {
        // Rejection sampling for the nonce — see ecdsa_sign for rationale
        // (avoid the modulo bias that reducing raw RNG bytes mod n would
        // introduce).
        let mut k_bytes = [0u8; 32];
        use rand::Rng;
        rand::rng().fill_bytes(&mut k_bytes);
        let k = BigUint::from_bytes_be(&k_bytes);
        if k.is_zero() || k >= n {
            continue;
        }

        let r_point = ec_mul(&k, &g, &a, &p);
        let r = &r_point.x % &n;
        if r.is_zero() {
            continue;
        }

        let k_inv = match mod_inv(&k, &n) {
            Some(v) => v,
            None => continue,
        };
        let s = (&k_inv * ((&z + &r * &d) % &n)) % &n;
        if s.is_zero() {
            continue;
        }

        let r_bytes = to_bytes_be_padded(&r, 32);
        let s_bytes = to_bytes_be_padded(&s, 32);

        let mut r_out = [0u8; 32];
        let mut s_out = [0u8; 32];
        r_out.copy_from_slice(&r_bytes);
        s_out.copy_from_slice(&s_bytes);

        return (r_out, s_out);
    }
}

/// ECDSA verify with P-256/SHA-256.
fn ecdsa_verify_p256(pub_x: &[u8], pub_y: &[u8], sig_r: &[u8], sig_s: &[u8], data: &[u8]) -> bool {
    use sha2::{Digest as Sha2Digest, Sha256};

    let p = BigUint::from_bytes_be(&P256_P);
    let a = BigUint::from_bytes_be(&P256_A);
    let b = BigUint::from_bytes_be(&P256_B);
    let n = BigUint::from_bytes_be(&P256_N);
    let g = EcPoint::from_bytes(&P256_GX, &P256_GY);
    let q = EcPoint::new(BigUint::from_bytes_be(pub_x), BigUint::from_bytes_be(pub_y));

    // Validate Q before use — see `ecdsa_verify`. A Q of (0,0) collapses the
    // check to `r == x(u1·G) mod n`, forgeable with no key; `point_on_curve`
    // also range-checks and rejects (0,0) (rhs is `b` != 0).
    if !point_on_curve(&q.x, &q.y, &a, &b, &p) {
        return false;
    }

    let r = BigUint::from_bytes_be(sig_r);
    let s = BigUint::from_bytes_be(sig_s);

    if r.is_zero() || r >= n || s.is_zero() || s >= n {
        return false;
    }

    let hash = Sha256::digest(data);
    let z = BigUint::from_bytes_be(&hash);

    let s_inv = match mod_inv(&s, &n) {
        Some(v) => v,
        None => return false,
    };

    let u1 = (&z * &s_inv) % &n;
    let u2 = (&r * &s_inv) % &n;

    let p1 = ec_mul(&u1, &g, &a, &p);
    let p2 = ec_mul(&u2, &q, &a, &p);
    let r_point = ec_add(&p1, &p2, &a, &p);

    if r_point.infinity {
        return false;
    }

    &r_point.x % &n == r
}

// Verify an AACS 2.0 drive cert (type 0x11) against an AACS 2.0 LA key. See
// docs/aacs-handshake.md — offsets are PROVISIONAL pending a real captured
// cert; LA anchor is a parameter so tests can drive it standalone.
fn verify_cert_p256(cert: &[u8], la_x: &[u8; 32], la_y: &[u8; 32]) -> bool {
    if cert.len() < 132 {
        return false;
    }
    let sig_r = &cert[68..100];
    let sig_s = &cert[100..132];
    ecdsa_verify_p256(la_x, la_y, sig_r, sig_s, &cert[..68])
}

// Extract public key from an AACS 2.0 cert (32-byte x,y). Returns zeroed
// key pair if `cert` is too short for the fixed offsets (matches the
// `>= 132` guard in `verify_cert_p256`) so a hostile cert can't panic.
fn cert_pub_key_p256(cert: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    if cert.len() < 68 {
        return (x, y);
    }
    x.copy_from_slice(&cert[4..36]);
    y.copy_from_slice(&cert[36..68]);
    (x, y)
}

/// Compute bus key via ECDH on P-256 curve.
fn compute_bus_key_p256(
    host_priv: &[u8; 32],
    drive_key_point_x: &[u8],
    drive_key_point_y: &[u8],
) -> Option<[u8; 16]> {
    let p = BigUint::from_bytes_be(&P256_P);
    let a = BigUint::from_bytes_be(&P256_A);
    let b = BigUint::from_bytes_be(&P256_B);

    let d = BigUint::from_bytes_be(host_priv);
    let dx = BigUint::from_bytes_be(drive_key_point_x);
    let dy = BigUint::from_bytes_be(drive_key_point_y);

    // Reject an off-curve drive point before the multiply (invalid-curve attack).
    if !point_on_curve(&dx, &dy, &a, &b, &p) {
        return None;
    }
    let dkp = EcPoint::new(dx, dy);

    let shared = ec_mul(&d, &dkp, &a, &p);
    // Defensive: a shared point at infinity has no usable x-coordinate (its
    // stored x is 0), so it must never be reduced to a bus key. Cannot happen
    // for d in [1, n) against an on-curve point in the prime-order subgroup, but
    // guard rather than silently derive an all-zero-ish key.
    if shared.infinity {
        return None;
    }

    // Bus key = lowest 128 bits of x-coordinate. The shared x is secret; wipe the
    // byte buffer on drop. LIMITATION: `d` and `shared.x` are `BigUint`s whose
    // heap limbs zeroize cannot reach (see the AACS 1.0 sibling) — best-effort.
    let x_bytes = Zeroizing::new(to_bytes_be_padded(&shared.x, 32));
    let mut bus_key = [0u8; 16];
    bus_key.copy_from_slice(&x_bytes[16..32]);
    Some(bus_key)
}

// ── AACS certificate handling ───────────────────────────────────────────────

/// Verify an AACS certificate (92 bytes) against the production AACS 1.0 LA
/// public key. Production verifies via [`verify_cert_with_anchor`] (the live
/// path threads the real anchor there); this real-anchor convenience is
/// exercised by the genuine-cert tests.
#[cfg_attr(not(test), allow(dead_code))]
fn verify_cert(cert: &[u8]) -> bool {
    verify_cert_with_anchor(cert, &AACS_LA_PUB_X, &AACS_LA_PUB_Y)
}

/// `verify_cert` with the LA trust anchor as a parameter, so a drive-side test
/// emulator can present a certificate signed by a self-generated test LA key
/// (the production anchor's private half doesn't exist). Production threads
/// `AACS_LA_PUB_X/Y` via [`verify_cert`].
fn verify_cert_with_anchor(cert: &[u8], la_x: &[u8; 20], la_y: &[u8; 20]) -> bool {
    if cert.len() < 92 {
        return false;
    }
    // Format (92 bytes, 12-byte header): pub_x(20)@[12..32], pub_y(20)@[32..52],
    // sig_r(20)@[52..72], sig_s(20)@[72..92]; signed over first 52 bytes.
    let mut sig_r = [0u8; 20];
    let mut sig_s = [0u8; 20];
    sig_r.copy_from_slice(&cert[52..72]);
    sig_s.copy_from_slice(&cert[72..92]);

    ecdsa_verify(la_x, la_y, &sig_r, &sig_s, &cert[..52])
}

// Extract public key from certificate. Returns a zeroed key pair if `cert`
// is too short for the fixed offsets (matches the `>= 92` guard in
// `verify_cert`), so a short/hostile cert cannot panic on the slice index.
fn cert_pub_key(cert: &[u8]) -> ([u8; 20], [u8; 20]) {
    let mut x = [0u8; 20];
    let mut y = [0u8; 20];
    if cert.len() < 52 {
        return (x, y);
    }
    x.copy_from_slice(&cert[12..32]);
    y.copy_from_slice(&cert[32..52]);
    (x, y)
}

/// True iff the stored host private key matches the certificate's public key on
/// the AACS 1.0 curve (`private_key · G == cert_pub_key(cert)`). A genuine,
/// LA-signed cert can still be paired in a keydb with the WRONG private key,
/// which can never establish a bus key ("KEY NOT ESTABLISHED"): this is what
/// distinguishes a DEAD pairing from a live one. Returns `false` (never panics)
/// on a short cert, a private key outside `[1, n)`, or a point at infinity.
/// Reuses the live handshake's own curve math, so "valid here" == "authenticates".
pub fn aacs1_keypair_matches(private_key: &[u8; 20], cert: &[u8]) -> bool {
    if cert.len() < 52 {
        return false;
    }
    let p = BigUint::from_bytes_be(&EC_P);
    let a = BigUint::from_bytes_be(&EC_A);
    let n = BigUint::from_bytes_be(&EC_N);
    let d = BigUint::from_bytes_be(private_key);
    // A real scalar is in [1, n): 0 and >= n never produce a usable public point.
    if d.is_zero() || d >= n {
        return false;
    }
    let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
    let q = ec_mul(&d, &g, &a, &p);
    if q.infinity {
        return false;
    }
    let (cx, cy) = cert_pub_key(cert);
    q.x == BigUint::from_bytes_be(&cx) && q.y == BigUint::from_bytes_be(&cy)
}

// ── Bus key derivation (ECDH) ───────────────────────────────────────────────

/// Compute bus key via ECDH: bus_key = low 128 bits of (host_priv × drive_key_point).x
fn compute_bus_key(
    host_priv: &[u8; 20],
    drive_key_point_x: &[u8; 20],
    drive_key_point_y: &[u8; 20],
) -> Option<[u8; 16]> {
    let p = BigUint::from_bytes_be(&EC_P);
    let a = BigUint::from_bytes_be(&EC_A);
    let b = BigUint::from_bytes_be(&EC_B);

    let d = BigUint::from_bytes_be(host_priv);
    let dx = BigUint::from_bytes_be(drive_key_point_x);
    let dy = BigUint::from_bytes_be(drive_key_point_y);

    // Reject an off-curve drive point before the multiply (invalid-curve attack).
    if !point_on_curve(&dx, &dy, &a, &b, &p) {
        return None;
    }
    let dkp = EcPoint::new(dx, dy);

    let shared = ec_mul(&d, &dkp, &a, &p);
    // Defensive: a shared point at infinity has no usable x-coordinate, so it
    // must never be reduced to a bus key (mirrors compute_bus_key_p256).
    if shared.infinity {
        return None;
    }

    // Bus key = lowest 128 bits (last 16 bytes) of x-coordinate. The full shared
    // x is a secret; wipe the byte buffer on drop. LIMITATION: the `BigUint`s `d`
    // (private scalar) and `shared.x` hold secret bytes on heap limbs that
    // `zeroize` cannot reach (num-bigint exposes no clear/Zeroize) — a known
    // best-effort residual until num-bigint offers zeroization.
    let x_bytes = Zeroizing::new(to_bytes_be_padded(&shared.x, 20));
    let mut bus_key = [0u8; 16];
    bus_key.copy_from_slice(&x_bytes[4..20]); // last 16 of 20
    Some(bus_key)
}

/// Generate P-256 ephemeral key pair for AACS 2.0: (private_key, public_point_x, public_point_y).
fn generate_host_key_pair_p256() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let p_mod = BigUint::from_bytes_be(&P256_P);
    let a = BigUint::from_bytes_be(&P256_A);
    let n = BigUint::from_bytes_be(&P256_N);
    let g = EcPoint::from_bytes(&P256_GX, &P256_GY);

    let (d, q) = loop {
        // Raw private-scalar bytes are secret; wipe the buffer on drop each draw.
        let mut priv_bytes = Zeroizing::new([0u8; 32]);
        use rand::Rng;
        rand::rng().fill_bytes(priv_bytes.as_mut_slice());
        // Rejection-sample d in [1, n): reducing raw RNG bytes mod n would bias
        // d toward small values (n isn't a power of two), the same modulo bias
        // the ECDSA nonce path rejects. Redraw any candidate that is 0 or >= n,
        // matching the AACS 1.0 sibling generate_host_key_pair.
        let d = BigUint::from_bytes_be(priv_bytes.as_slice());
        if d.is_zero() || d >= n {
            continue;
        }
        let q = ec_mul(&d, &g, &a, &p_mod);
        break (d, q);
    };

    // The private scalar is returned to the caller (who wraps it in `Zeroizing`);
    // wipe the intermediate byte buffer here. LIMITATION: `d` is a `BigUint` whose
    // heap limbs zeroize cannot reach — a best-effort residual (see compute_bus_key).
    let mut key = [0u8; 32];
    let mut pub_x = [0u8; 32];
    let mut pub_y = [0u8; 32];
    key.copy_from_slice(&Zeroizing::new(to_bytes_be_padded(&d, 32)));
    pub_x.copy_from_slice(&to_bytes_be_padded(&q.x, 32));
    pub_y.copy_from_slice(&to_bytes_be_padded(&q.y, 32));

    (key, pub_x, pub_y)
}

/// Generate AACS 1.0 ephemeral key pair.
fn generate_host_key_pair() -> ([u8; 20], [u8; 20], [u8; 20]) {
    let p_mod = BigUint::from_bytes_be(&EC_P);
    let a = BigUint::from_bytes_be(&EC_A);
    let n = BigUint::from_bytes_be(&EC_N);
    let g = EcPoint::from_bytes(&EC_GX, &EC_GY);

    let (d, q) = loop {
        // Raw private-scalar bytes are secret; wipe the buffer on drop each draw.
        let mut priv_bytes = Zeroizing::new([0u8; 20]);
        use rand::Rng;
        rand::rng().fill_bytes(priv_bytes.as_mut_slice());
        // Rejection-sample d in [1, n): `raw % n` would bias d toward small
        // values (n isn't a power of two), the same modulo bias the ECDSA nonce
        // path rejects. Redraw any candidate that is 0 or >= n.
        let d = BigUint::from_bytes_be(priv_bytes.as_slice());
        if d.is_zero() || d >= n {
            continue;
        }
        let q = ec_mul(&d, &g, &a, &p_mod);
        break (d, q);
    };

    // The private scalar is returned to the caller (who wraps it in `Zeroizing`);
    // wipe the intermediate byte buffer. LIMITATION: `d` is a `BigUint` whose heap
    // limbs zeroize cannot reach — a best-effort residual (see compute_bus_key).
    let d_bytes = Zeroizing::new(to_bytes_be_padded(&d, 20));
    let qx = to_bytes_be_padded(&q.x, 20);
    let qy = to_bytes_be_padded(&q.y, 20);

    let mut key = [0u8; 20];
    let mut pub_x = [0u8; 20];
    let mut pub_y = [0u8; 20];
    key.copy_from_slice(&d_bytes);
    pub_x.copy_from_slice(&qx);
    pub_y.copy_from_slice(&qy);

    (key, pub_x, pub_y)
}

// ── AES-CMAC (for MAC verification) ── single-complete-block case ONLY:
// derives subkey K1 and XORs one full block, no K2 / `0x80` 10*-padding.
// Correct only for 16-byte input (enforced by `&[u8; 16]`) — don't generalize.
fn aes_cmac_16(data: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    use aes::Aes128;
    use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

    let cipher = Aes128::new(&(*key).into());

    // For single-block CMAC:
    // 1. Generate subkey K1
    let mut l: Array<u8, _> = [0u8; 16].into();
    cipher.encrypt_block(&mut l);

    let mut k1 = [0u8; 16];
    let carry = (l[0] >> 7) & 1;
    for i in 0..15 {
        k1[i] = (l[i] << 1) | (l[i + 1] >> 7);
    }
    k1[15] = l[15] << 1;
    if carry == 1 {
        k1[15] ^= 0x87; // Rb for AES-128
    }

    // 2. XOR data with K1, encrypt
    let mut block = [0u8; 16];
    for i in 0..16 {
        block[i] = data[i] ^ k1[i];
    }
    let mut ga: Array<u8, _> = block.into();
    cipher.encrypt_block(&mut ga);

    let mut mac = [0u8; 16];
    mac.copy_from_slice(&ga);
    mac
}

// ── SCSI command builders ───────────────────────────────────────────────────

/// Build REPORT KEY CDB (0xA4).
fn cdb_report_key(agid: u8, format: u8, len: u16) -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_REPORT_KEY;
    cdb[7] = crate::scsi::AACS_KEY_CLASS;
    cdb[8] = (len >> 8) as u8;
    cdb[9] = (len & 0xFF) as u8;
    cdb[10] = (agid << 6) | (format & 0x3F);
    cdb
}

/// Build SEND KEY CDB (0xA3).
fn cdb_send_key(agid: u8, format: u8, len: u16) -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_SEND_KEY;
    cdb[7] = crate::scsi::AACS_KEY_CLASS;
    cdb[8] = (len >> 8) as u8;
    cdb[9] = (len & 0xFF) as u8;
    cdb[10] = (agid << 6) | (format & 0x3F);
    cdb
}

/// Build REPORT DISC STRUCTURE CDB (0xAD).
fn cdb_report_disc_structure(agid: u8, format: u8, len: u16) -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = crate::scsi::SCSI_READ_DISC_STRUCTURE;
    cdb[1] = 0x01; // Blu-ray
    cdb[7] = format;
    cdb[8] = (len >> 8) as u8;
    cdb[9] = (len & 0xFF) as u8;
    cdb[10] = agid << 6;
    cdb
}

// ── High-level handshake ────────────────────────────────────────────────────

/// Result of a successful AACS authentication handshake.
///
/// `Debug` is implemented manually so the session key material
/// (`bus_key`, `volume_id`, `read_data_key`) is never rendered into logs
/// or `dbg!` output — only its presence is reported.
// `ZeroizeOnDrop` wipes the derived session secrets (`bus_key`, `volume_id`,
// `read_data_key`) when the auth is dropped — defence in depth atop the redacting
// `Debug`. `agid` is a non-secret session handle, so it is `#[zeroize(skip)]`.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct AacsAuth {
    /// Bus key (16 bytes) — derived from ECDH
    pub bus_key: [u8; 16],
    /// AGID used for this session
    #[zeroize(skip)]
    pub agid: u8,
    /// Volume ID (16 bytes) — read after auth
    pub volume_id: Option<[u8; 16]>,
    /// Read data key (16 bytes) — for AACS 2.0 bus decryption
    pub read_data_key: Option<[u8; 16]>,
}

// Manual Debug: bus_key, volume_id, and read_data_key are key material (the
// VID feeds VUK derivation), so they are redacted — a `dbg!`/tracing of
// AacsAuth must never dump them in plaintext.
impl std::fmt::Debug for AacsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AacsAuth")
            .field("bus_key", &"[redacted]")
            .field("agid", &self.agid)
            .field("volume_id", &self.volume_id.map(|_| "[redacted]"))
            .field("read_data_key", &self.read_data_key.map(|_| "[redacted]"))
            .finish()
    }
}

/// Perform the full AACS authentication handshake against the production AACS
/// 1.0 LA anchor.
///
/// Requires a host private key (20 bytes) and host certificate (92 bytes)
/// from the KEYDB.cfg HC entry. The orchestration entry [`run_cert_handshake`]
/// drives the live path via [`aacs_authenticate_with_anchor`]; this real-anchor
/// convenience is exercised directly by the AKE tests.
#[cfg_attr(not(test), allow(dead_code))]
pub fn aacs_authenticate(
    session: &mut dyn ScsiTransport,
    host_priv_key: &[u8; 20],
    host_cert: &[u8],
) -> Result<AacsAuth> {
    aacs_authenticate_with_anchor(
        session,
        host_priv_key,
        host_cert,
        &AACS_LA_PUB_X,
        &AACS_LA_PUB_Y,
    )
}

/// [`aacs_authenticate`] with the AACS 1.0 LA trust anchor as a parameter, so a
/// drive-side test emulator can present a certificate signed by a self-generated
/// test LA key (the production anchor's private half doesn't exist). Production
/// threads `AACS_LA_PUB_X/Y` via [`aacs_authenticate`]. Mirrors the P-256 twin
/// [`aacs2_authenticate_p256_with_anchor`].
fn aacs_authenticate_with_anchor(
    session: &mut dyn ScsiTransport,
    host_priv_key: &[u8; 20],
    host_cert: &[u8],
    la_x: &[u8; 20],
    la_y: &[u8; 20],
) -> Result<AacsAuth> {
    if host_cert.len() < 92 {
        return Err(Error::AacsCertShort);
    }

    // Step 1: Invalidate all AGIDs
    for agid in 0..4u8 {
        let cdb = cdb_report_key(agid, 0x3F, 2);
        let _ = scsi_read(session, &cdb, 2);
    }

    // Step 2: Allocate AGID
    let cdb = cdb_report_key(0, 0x00, 8);
    let response =
        scsi_read(session, &cdb, 8).map_err(|e| handshake_err(e, Error::AacsAgidAlloc))?;
    let agid = (response[7] >> 6) & 0x03;

    // From here on we HOLD the AGID. Every failure below used to abandon it
    // (see [`release_agid`]); release it on the way out instead.
    let r = aacs_authenticate_with_agid(session, agid, host_priv_key, host_cert, la_x, la_y);
    if r.is_err() {
        release_agid(session, agid);
    }
    r
}

/// Steps 3-9 of [`aacs_authenticate`], with the AGID already allocated. Split
/// out so the single caller can release the AGID on ANY failure without a Drop
/// guard or a release call at each of the seven early returns.
fn aacs_authenticate_with_agid(
    session: &mut dyn ScsiTransport,
    agid: u8,
    host_priv_key: &[u8; 20],
    host_cert: &[u8],
    la_x: &[u8; 20],
    la_y: &[u8; 20],
) -> Result<AacsAuth> {
    // Step 3: Generate host nonce and ephemeral key pair
    let mut host_nonce = [0u8; 20];
    use rand::Rng;
    rand::rng().fill_bytes(&mut host_nonce);
    let (host_key, host_key_point_x, host_key_point_y) = generate_host_key_pair();
    // The ephemeral ECDH private scalar is a session secret; wipe it on drop.
    // (The public key point x/y travel to the drive in the clear — not secret.)
    let host_key = Zeroizing::new(host_key);

    // Step 4: Send host certificate + nonce (SEND KEY format 0x01)
    let mut send_buf = [0u8; 116];
    send_buf[1] = 0x72; // data length
    send_buf[4..24].copy_from_slice(&host_nonce);
    send_buf[24..116].copy_from_slice(&host_cert[..92]);

    let cdb = cdb_send_key(agid, 0x01, 116);
    scsi_write(session, &cdb, &send_buf).map_err(|e| handshake_err(e, Error::AacsCertRejected))?;

    // Step 5: Read drive certificate + nonce (REPORT KEY format 0x01)
    let cdb = cdb_report_key(agid, 0x01, 116);
    let response =
        scsi_read(session, &cdb, 116).map_err(|e| handshake_err(e, Error::AacsCertRead))?;

    let mut drive_nonce = [0u8; 20];
    let mut drive_cert = [0u8; 92];
    drive_nonce.copy_from_slice(&response[4..24]);
    drive_cert.copy_from_slice(&response[24..116]);

    // Verify drive certificate against the LA anchor. Only a type-0x01 AACS 1.0
    // cert is verifiable on this 1.0 path. A type-0x11 (AACS 2.0) cert must NOT
    // be accepted here: doing so previously SKIPPED both this LA verification
    // AND the step-6 drive-key-point signature verify, then still ran ECDH and
    // returned Ok — an attacker-chosen-bus-key hole. Reject any non-0x01 type
    // (0x11 included); `run_cert_handshake` routes a genuine 0x11 drive to the
    // native P-256 AKE via the v2-cred fallback instead. See docs/aacs-handshake.md.
    if drive_cert[0] == 0x01 {
        if !verify_cert_with_anchor(&drive_cert, la_x, la_y) {
            return Err(Error::AacsCertVerify);
        }
    } else {
        tracing::warn!(
            target: "freemkv::disc",
            phase = "aacs_cert_unsupported_type",
            cert_type = drive_cert[0],
            "drive certificate is not a verifiable AACS 1.0 (type 0x01) cert on the \
             1.0 path; rejecting (a genuine 0x11 drive is retried on the native P-256 path)"
        );
        return Err(Error::AacsCertVerify);
    }

    // Step 6: Read drive key point + signature (REPORT KEY format 0x02)
    let cdb = cdb_report_key(agid, 0x02, 84);
    let response =
        scsi_read(session, &cdb, 84).map_err(|e| handshake_err(e, Error::AacsKeyRead))?;

    let mut drive_key_point = [0u8; 40]; // x(20) + y(20)
    let mut drive_key_sig = [0u8; 40]; // r(20) + s(20)
    drive_key_point.copy_from_slice(&response[4..44]);
    drive_key_sig.copy_from_slice(&response[44..84]);

    // Verify sign(host_nonce || drive_key_point) against the (now LA-verified)
    // drive cert's public key. Always runs: the only cert type that reaches here
    // is the type-0x01 one verified above, so `cert_pub_key`'s AACS-1.0 offsets
    // are correct. (Previously skipped for 0x11, which — paired with the skipped
    // cert verify — let the drive choose the bus key.)
    {
        let (drive_pub_x, drive_pub_y) = cert_pub_key(&drive_cert);
        let mut verify_data = [0u8; 60];
        verify_data[..20].copy_from_slice(&host_nonce);
        verify_data[20..60].copy_from_slice(&drive_key_point);

        let mut sig_r = [0u8; 20];
        let mut sig_s = [0u8; 20];
        sig_r.copy_from_slice(&drive_key_sig[..20]);
        sig_s.copy_from_slice(&drive_key_sig[20..40]);

        if !ecdsa_verify(&drive_pub_x, &drive_pub_y, &sig_r, &sig_s, &verify_data) {
            return Err(Error::AacsKeyVerify);
        }
    }

    // Step 7: Sign host key point (ECDSA over drive_nonce || host_key_point)
    let mut sign_data = [0u8; 60];
    sign_data[..20].copy_from_slice(&drive_nonce);
    sign_data[20..40].copy_from_slice(&host_key_point_x);
    sign_data[40..60].copy_from_slice(&host_key_point_y);

    let (host_sig_r, host_sig_s) = ecdsa_sign(host_priv_key, &sign_data);

    // Self-verify guard (libaacs parity): our OWN signature must verify against
    // our host cert's public key before we ship it, else the cert's private key
    // is mispaired with its certificate — fail fast (see Error::AacsHostSignVerify).
    let (host_pub_x, host_pub_y) = cert_pub_key(host_cert);
    if !ecdsa_verify(
        &host_pub_x,
        &host_pub_y,
        &host_sig_r,
        &host_sig_s,
        &sign_data,
    ) {
        return Err(Error::AacsHostSignVerify);
    }

    // Step 8: Send host key point + signature (SEND KEY format 0x02)
    let mut send_buf = [0u8; 84];
    send_buf[1] = 0x52;
    send_buf[4..24].copy_from_slice(&host_key_point_x);
    send_buf[24..44].copy_from_slice(&host_key_point_y);
    send_buf[44..64].copy_from_slice(&host_sig_r);
    send_buf[64..84].copy_from_slice(&host_sig_s);

    let cdb = cdb_send_key(agid, 0x02, 84);
    scsi_write(session, &cdb, &send_buf).map_err(|e| handshake_err(e, Error::AacsKeyRejected))?;

    // Step 9: Compute bus key via ECDH
    let mut dkp_x = [0u8; 20];
    let mut dkp_y = [0u8; 20];
    dkp_x.copy_from_slice(&drive_key_point[..20]);
    dkp_y.copy_from_slice(&drive_key_point[20..40]);

    let bus_key = compute_bus_key(&host_key, &dkp_x, &dkp_y).ok_or(Error::AacsKeyVerify)?;

    Ok(AacsAuth {
        bus_key,
        agid,
        volume_id: None,
        read_data_key: None,
    })
}

// Native AACS 2.0 handshake using P-256/SHA-256 with the LA trust anchor as a
// parameter, so tests can exercise the full AKE under a test LA keypair (the
// real anchor's private half doesn't exist). Same SCSI protocol as the 1.0 AKE,
// larger payloads.
//
// The production 2.0 cert offsets this consumes are PROVISIONAL/unverified
// against a genuine captured 2.0 cert (see `verify_cert_p256` and
// docs/aacs-handshake.md), so the production entry `run_cert_handshake` keeps
// this path DISABLED behind `AACS2_P256_EXPERIMENTAL` — it must not be reached
// with the real anchor until a captured test vector confirms the offsets, or it
// could silently mis-verify. Tests reach it directly with a test anchor.
fn aacs2_authenticate_p256_with_anchor(
    session: &mut dyn ScsiTransport,
    host_priv_key: &[u8; 32],
    host_cert: &[u8],
    la_x: &[u8; 32],
    la_y: &[u8; 32],
) -> Result<AacsAuth> {
    if host_cert.len() < 132 {
        return Err(Error::AacsCertShort);
    }

    // Step 1: Invalidate all AGIDs
    for agid in 0..4u8 {
        let cdb = cdb_report_key(agid, 0x3F, 2);
        let _ = scsi_read(session, &cdb, 2);
    }

    // Step 2: Allocate AGID
    let cdb = cdb_report_key(0, 0x00, 8);
    let response =
        scsi_read(session, &cdb, 8).map_err(|e| handshake_err(e, Error::AacsAgidAlloc))?;
    let agid = (response[7] >> 6) & 0x03;

    // From here we HOLD the AGID; release on ANY failure below, mirroring
    // the leak fix (`975315d`) applied to the AACS 1.0 twin.
    let r = aacs2_authenticate_p256_with_agid(session, agid, host_priv_key, host_cert, la_x, la_y);
    if r.is_err() {
        release_agid(session, agid);
    }
    r
}

/// Steps 3-9 of [`aacs2_authenticate_p256`] with the AGID already allocated,
/// split out so the single caller can release the AGID on any of the seven
/// fallible exits without a per-return release call or a Drop guard.
fn aacs2_authenticate_p256_with_agid(
    session: &mut dyn ScsiTransport,
    agid: u8,
    host_priv_key: &[u8; 32],
    host_cert: &[u8],
    la_x: &[u8; 32],
    la_y: &[u8; 32],
) -> Result<AacsAuth> {
    // Step 3: Generate host nonce + P-256 ephemeral key pair
    let mut host_nonce = [0u8; 20];
    use rand::Rng;
    rand::rng().fill_bytes(&mut host_nonce);
    let (host_eph_key, host_eph_pub_x, host_eph_pub_y) = generate_host_key_pair_p256();
    // Ephemeral P-256 ECDH private scalar — session secret; wipe it on drop.
    let host_eph_key = Zeroizing::new(host_eph_key);

    // Step 4: Send AACS 2.0 host certificate + nonce
    // AACS 2.0: cert is 132 bytes, total payload = 4 + 20 + 132 = 156
    let mut send_buf = vec![0u8; 156];
    send_buf[1] = 0x9a; // data length (154)
    send_buf[4..24].copy_from_slice(&host_nonce);
    send_buf[24..156].copy_from_slice(&host_cert[..132]);

    let cdb = cdb_send_key(agid, 0x01, 156);
    scsi_write(session, &cdb, &send_buf).map_err(|e| handshake_err(e, Error::AacsCertRejected))?;

    // Step 5: Read drive certificate + nonce
    // AACS 2.0 drive cert is also 132 bytes
    let cdb = cdb_report_key(agid, 0x01, 156);
    let response =
        scsi_read(session, &cdb, 156).map_err(|e| handshake_err(e, Error::AacsCertRead))?;

    let mut drive_nonce = [0u8; 20];
    drive_nonce.copy_from_slice(&response[4..24]);
    let drive_cert = &response[24..156];

    // Chain-of-trust gate, mandatory on this live path (see
    // docs/aacs-handshake.md): (a) reject any non-0x11 cert type outright,
    // (b) treat cert verify failure as FATAL, not logged-and-continued.
    if drive_cert[0] != 0x11 {
        tracing::warn!(
            target: "freemkv::disc",
            phase = "aacs2_cert_unknown_type",
            cert_type = drive_cert[0],
            "AACS 2.0 drive certificate carries an unexpected type byte; rejecting"
        );
        return Err(Error::AacsCertVerify);
    }
    if !verify_cert_p256(drive_cert, la_x, la_y) {
        tracing::warn!(
            target: "freemkv::disc",
            phase = "aacs2_cert_verify_failed",
            "AACS 2.0 drive certificate failed P-256 LA verification; rejecting"
        );
        return Err(Error::AacsCertVerify);
    }

    // Step 6: Read drive key point + signature (P-256: 64+64 = 128 bytes)
    let cdb = cdb_report_key(agid, 0x02, 132);
    let response =
        scsi_read(session, &cdb, 132).map_err(|e| handshake_err(e, Error::AacsKeyRead))?;

    let drive_key_x = &response[4..36];
    let drive_key_y = &response[36..68];
    let drive_sig_r = &response[68..100];
    let drive_sig_s = &response[100..132];

    // Verify drive key signature
    let (drive_pub_x, drive_pub_y) = cert_pub_key_p256(drive_cert);
    let mut verify_data = Vec::with_capacity(84);
    verify_data.extend_from_slice(&host_nonce);
    verify_data.extend_from_slice(drive_key_x);
    verify_data.extend_from_slice(drive_key_y);

    if !ecdsa_verify_p256(
        &drive_pub_x,
        &drive_pub_y,
        drive_sig_r,
        drive_sig_s,
        &verify_data,
    ) {
        return Err(Error::AacsKeyVerify);
    }

    // Step 7: Sign host key point
    let mut sign_data = Vec::with_capacity(84);
    sign_data.extend_from_slice(&drive_nonce);
    sign_data.extend_from_slice(&host_eph_pub_x);
    sign_data.extend_from_slice(&host_eph_pub_y);

    let (host_sig_r, host_sig_s) = ecdsa_sign_p256(host_priv_key, &sign_data);

    // Self-verify guard (libaacs parity): the P-256 twin of the AACS 1.0 guard
    // — a host cert whose private key is mispaired with its certificate is
    // caught host-side rather than shipped as an unverifiable signature.
    let (host_pub_x, host_pub_y) = cert_pub_key_p256(host_cert);
    if !ecdsa_verify_p256(
        &host_pub_x,
        &host_pub_y,
        &host_sig_r,
        &host_sig_s,
        &sign_data,
    ) {
        return Err(Error::AacsHostSignVerify);
    }

    // Step 8: Send host key point + signature (P-256: 64+64 = 128 bytes payload)
    let mut send_buf = vec![0u8; 132];
    send_buf[1] = 0x82; // data length
    send_buf[4..36].copy_from_slice(&host_eph_pub_x);
    send_buf[36..68].copy_from_slice(&host_eph_pub_y);
    send_buf[68..100].copy_from_slice(&host_sig_r);
    send_buf[100..132].copy_from_slice(&host_sig_s);

    let cdb = cdb_send_key(agid, 0x02, 132);
    scsi_write(session, &cdb, &send_buf).map_err(|e| handshake_err(e, Error::AacsKeyRejected))?;

    // Step 9: Compute bus key via P-256 ECDH
    let bus_key = compute_bus_key_p256(&host_eph_key, drive_key_x, drive_key_y)
        .ok_or(Error::AacsKeyVerify)?;

    Ok(AacsAuth {
        bus_key,
        agid,
        volume_id: None,
        read_data_key: None,
    })
}

/// Constant-time equality for two 16-byte MACs — no early exit, so the time
/// taken does not depend on WHERE the first difference is.
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    std::hint::black_box(diff) == 0
}

/// Read Volume ID after successful authentication.
pub fn read_volume_id(session: &mut dyn ScsiTransport, auth: &mut AacsAuth) -> Result<[u8; 16]> {
    // REPORT DISC STRUCTURE format 0x80
    let cdb = cdb_report_disc_structure(auth.agid, 0x80, 36);
    let response =
        scsi_read(session, &cdb, 36).map_err(|e| handshake_err(e, Error::AacsVidRead))?;

    let mut vid = [0u8; 16];
    let mut mac = [0u8; 16];
    vid.copy_from_slice(&response[4..20]);
    mac.copy_from_slice(&response[20..36]);

    // Verify MAC = AES-CMAC(VID, bus_key), constant-time: a malicious USB
    // bridge could otherwise time a `!=` short-circuit to learn the MAC
    // prefix byte by byte.
    let calc_mac = aes_cmac_16(&vid, &auth.bus_key);
    if !ct_eq_16(&calc_mac, &mac) {
        return Err(Error::AacsVidMac);
    }

    auth.volume_id = Some(vid);
    Ok(vid)
}

/// Read data keys after successful authentication (for AACS 2.0 bus encryption).
pub fn read_data_keys(
    session: &mut dyn ScsiTransport,
    auth: &mut AacsAuth,
) -> Result<([u8; 16], [u8; 16])> {
    // REPORT DISC STRUCTURE format 0x84
    let cdb = cdb_report_disc_structure(auth.agid, 0x84, 36);
    let response =
        scsi_read(session, &cdb, 36).map_err(|e| handshake_err(e, Error::AacsDataKey))?;

    let mut enc_rdk = [0u8; 16];
    let mut enc_wdk = [0u8; 16];
    enc_rdk.copy_from_slice(&response[4..20]);
    enc_wdk.copy_from_slice(&response[20..36]);

    // Format 0x84 carries no MAC to verify, but an all-zero key block is a
    // response the drive plainly didn't fill — refuse it, since decrypting
    // with a garbage key would otherwise look like a successful `Ok`.
    if enc_rdk == [0u8; 16] && enc_wdk == [0u8; 16] {
        return Err(Error::AacsDataKey);
    }

    // Decrypt with bus key (AES-ECB)
    let read_data_key = crate::aacs::aes_ecb_decrypt(&auth.bus_key, &enc_rdk);
    let write_data_key = crate::aacs::aes_ecb_decrypt(&auth.bus_key, &enc_wdk);

    auth.read_data_key = Some(read_data_key);
    Ok((read_data_key, write_data_key))
}

// ── Cert-handshake orchestration (shared by the in-tree path + the external
//    freemkv-unlock-aacs plugin) ─────────────────────────────────────────────

/// What a completed AACS host-certificate handshake learned: the Volume ID, the
/// AACS 2.x bus key (`read_data_key`) when the drive served one, and — when the
/// bus-key read was attempted and FAILED — its numeric error code (so the
/// downstream bus-key gate can log WHY the bus key is missing).
// `ZeroizeOnDrop` wipes the finished handshake's secrets (`volume_id` feeds VUK
// derivation; `read_data_key` IS the bus key) — the same material the redacting
// `Debug` hides. `read_data_key_err` is a non-secret diagnostic code (skipped).
#[derive(zeroize::ZeroizeOnDrop)]
pub struct CertHandshake {
    pub volume_id: [u8; 16],
    pub read_data_key: Option<[u8; 16]>,
    #[zeroize(skip)]
    pub read_data_key_err: Option<u16>,
}

// Manual Debug, mirroring [`AacsAuth`]: the Volume ID feeds VUK derivation and
// the read_data_key IS the bus key, so neither may ever reach a log or a test
// failure message in plaintext.
impl std::fmt::Debug for CertHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertHandshake")
            .field("volume_id", &"[redacted]")
            .field("read_data_key", &self.read_data_key.map(|_| "[redacted]"))
            .field("read_data_key_err", &self.read_data_key_err)
            .finish()
    }
}

/// Run the host-certificate mutual-auth handshake over `scsi` against the given
/// host certs (already collected — see [`collect_host_certs`]) and, on success,
/// read the Volume ID + `read_data_key`. This is the cert "remove bus
/// encryption" primitive, shared by the in-tree path and the external
/// `freemkv-unlock-aacs` plugin. Wedge-guarded: caps attempts, sleeps between,
/// and bails on the drive's ILLEGAL_REQUEST sense. Every no-VID outcome is a
/// structured [`crate::UnlockError`].
pub fn run_cert_handshake(
    scsi: &mut dyn ScsiTransport,
    host_certs: &[crate::HostCert],
) -> std::result::Result<CertHandshake, crate::UnlockError> {
    // Production threads the real LA anchors. The native P-256 (AACS 2.0) path
    // is DISABLED at this boundary while its cert offsets are provisional (see
    // `AACS2_P256_EXPERIMENTAL`), so it can't silently mis-verify a real disc.
    run_cert_handshake_with_anchors(
        scsi,
        host_certs,
        (&AACS_LA_PUB_X, &AACS_LA_PUB_Y),
        (&AACS2_LA_PUB_X, &AACS2_LA_PUB_Y),
        AACS2_P256_EXPERIMENTAL,
    )
}

/// Why reading the VID + data keys for a completed auth did not yield a
/// finished handshake.
enum FinishErr {
    /// Dead bus during the VID or data-key read — abort the whole handshake.
    Transport,
    /// Post-auth VID MAC failure: the auth completed but the drive's VID MAC did
    /// not verify under the derived bus key. Eligible for a native P-256 retry
    /// when the cert carries v2 creds — a backward-compat 2.0 drive that
    /// completed the 1.0 AKE whose 1.0 bus key cannot authenticate the VID.
    VidMac,
    /// Any other non-transport VID read failure — terminal for this cert.
    VidUnavailable,
}

/// Read the Volume ID + data keys for a completed auth and assemble the finished
/// [`CertHandshake`]. Releases the AGID on EVERY exit — including the
/// fully-successful one (previously leaked, slowly draining the drive's 4-AGID
/// pool across discs), since nothing downstream needs the AGID once the VID and
/// data keys are read. `idx` is for log correlation only.
fn finish_auth(
    scsi: &mut dyn ScsiTransport,
    mut auth: AacsAuth,
    idx: usize,
) -> std::result::Result<CertHandshake, FinishErr> {
    let volume_id = match read_volume_id(scsi, &mut auth) {
        Ok(vid) => vid,
        Err(e) => {
            let transport = e.is_scsi_transport_failure();
            let vid_mac = matches!(e, Error::AacsVidMac);
            tracing::warn!(
                target: "freemkv::disc",
                phase = "handshake_vid_read_failed",
                cert_index = idx,
                error_code = e.code(),
                transport_failure = transport,
                "auth ok but volume ID read failed"
            );
            // We authenticated, so we hold an AGID; release it before giving up
            // rather than leaving the drive one short until the next attempt
            // invalidates all four.
            release_agid(scsi, auth.agid);
            // A dead bus is NOT "the drive has no Volume ID" — that told the
            // consumer to fall through and keep working a transport that is gone.
            return Err(if transport {
                FinishErr::Transport
            } else if vid_mac {
                FinishErr::VidMac
            } else {
                FinishErr::VidUnavailable
            });
        }
    };
    let (read_data_key, read_data_key_err) = match read_data_keys(scsi, &mut auth) {
        Ok((rdk, _)) => (Some(rdk), None),
        Err(e) => {
            let transport = e.is_scsi_transport_failure();
            tracing::debug!(
                target: "freemkv::disc",
                phase = "handshake_read_data_key_failed",
                cert_index = idx,
                error_code = e.code(),
                transport_failure = transport,
                "auth + VID read OK, but the drive served no read_data_key (bus key); \
                 a bus-encrypted disc stays undecryptable until it does"
            );
            // A dead bus here is NOT "no data key served" — left unclassified it
            // returned a successful-looking unlock with read_data_key: None.
            // Release AGID, abort like VID.
            if transport {
                release_agid(scsi, auth.agid);
                return Err(FinishErr::Transport);
            }
            (None, Some(e.code()))
        }
    };
    tracing::debug!(
        target: "freemkv::disc",
        phase = "handshake_ok",
        cert_index = idx,
        has_volume_id = volume_id != [0u8; 16],
        has_read_data_key = read_data_key.is_some(),
        "AACS bus-auth handshake complete"
    );
    // Release the AGID on the fully-successful path too: the VID and data keys
    // are already read, so nothing downstream needs it, and holding it slowly
    // leaks the drive's 4-AGID pool across discs.
    release_agid(scsi, auth.agid);
    Ok(CertHandshake {
        volume_id,
        read_data_key,
        read_data_key_err,
    })
}

/// The result of one cert's drive round-trip, dispatched by the loop below.
enum CertOutcome {
    Ok(CertHandshake),
    /// Dead bus — abort the whole handshake.
    Transport,
    /// Auth completed but no usable VID — terminal.
    VidUnavailable,
    /// Drive returned ILLEGAL_REQUEST — wedge; bail with HandshakeRejected.
    Wedge(crate::scsi::ScsiSense),
    /// Cert-level rejection (non-transport, non-wedge) — record + try next cert.
    Reject(u16),
}

/// A non-transport SCSI error becomes a wedge (ILLEGAL_REQUEST) or an ordinary
/// cert rejection. Wedge sense comes from the structured `ScsiSense`, not
/// `e.code()` (flat for every ScsiError).
fn classify_cert_err(e: &Error) -> CertOutcome {
    match e.scsi_sense() {
        Some(sense) if sense.is_illegal_request() => CertOutcome::Wedge(sense),
        _ => CertOutcome::Reject(e.code()),
    }
}

/// One host cert's drive round-trip: AACS 1.0 AKE first (also the backward-compat
/// path a 2.0 drive accepts), then the native P-256 (AACS 2.0) AKE when the cert
/// carries usable v2 creds AND either the 1.0 AKE was cert-rejected OR it
/// completed but its VID MAC failed (so a 0x11/backward-compat drive that fails
/// the 1.0 VID MAC still reaches the P-256 path). `allow_p256` gates the 2.0 path
/// off in production while its cert offsets are provisional.
fn attempt_one_cert(
    scsi: &mut dyn ScsiTransport,
    hc: &crate::HostCert,
    idx: usize,
    la_v1: (&[u8; 20], &[u8; 20]),
    la_v2: (&[u8; 32], &[u8; 32]),
    allow_p256: bool,
) -> CertOutcome {
    let has_v2 = allow_p256 && hc.private_key_v2.is_some() && hc.certificate_v2.is_some();

    match aacs_authenticate_with_anchor(scsi, &hc.private_key, &hc.certificate, la_v1.0, la_v1.1) {
        Ok(auth) => match finish_auth(scsi, auth, idx) {
            Ok(ch) => return CertOutcome::Ok(ch),
            Err(FinishErr::Transport) => return CertOutcome::Transport,
            // Post-auth VID/MAC failure with v2 creds available: fall through to
            // the native P-256 AKE below instead of a terminal early return.
            Err(FinishErr::VidMac) if has_v2 => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "aacs1_vid_mac_p256_fallback",
                    cert_index = idx,
                    "1.0 AKE completed but the VID MAC failed; retrying the native P-256 AKE"
                );
            }
            Err(FinishErr::VidMac) | Err(FinishErr::VidUnavailable) => {
                return CertOutcome::VidUnavailable;
            }
        },
        Err(e) if e.is_scsi_transport_failure() => return CertOutcome::Transport,
        Err(e) if has_v2 => {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "aacs1_reject_p256_fallback",
                cert_index = idx,
                error_code = e.code(),
                "AACS 1.0 AKE rejected; falling through to the native P-256 AKE"
            );
        }
        Err(e) => return classify_cert_err(&e),
    }

    // Native AACS 2.0 (P-256) AKE. Reached only when `has_v2` and the 1.0 path
    // was either cert-rejected or completed with a failed VID MAC.
    let (Some(k), Some(c)) = (hc.private_key_v2.as_ref(), hc.certificate_v2.as_deref()) else {
        // `has_v2` guarantees both are Some; unreachable in practice.
        return CertOutcome::VidUnavailable;
    };
    match aacs2_authenticate_p256_with_anchor(scsi, k, c, la_v2.0, la_v2.1) {
        Ok(auth) => match finish_auth(scsi, auth, idx) {
            Ok(ch) => CertOutcome::Ok(ch),
            Err(FinishErr::Transport) => CertOutcome::Transport,
            // A VID failure on the P-256 path is terminal for this cert.
            Err(FinishErr::VidMac) | Err(FinishErr::VidUnavailable) => CertOutcome::VidUnavailable,
        },
        Err(e) if e.is_scsi_transport_failure() => CertOutcome::Transport,
        Err(e) => classify_cert_err(&e),
    }
}

/// [`run_cert_handshake`] with the LA trust anchors and the P-256-enable flag as
/// parameters, so tests can drive the full 1.0 and 2.0 AKEs under self-generated
/// test anchors (the production anchors' private halves don't exist) and exercise
/// the P-256 fall-through that production keeps gated off. Production threads the
/// real anchors + `AACS2_P256_EXPERIMENTAL` via [`run_cert_handshake`].
pub(crate) fn run_cert_handshake_with_anchors(
    scsi: &mut dyn ScsiTransport,
    host_certs: &[crate::HostCert],
    la_v1: (&[u8; 20], &[u8; 20]),
    la_v2: (&[u8; 32], &[u8; 32]),
    allow_p256: bool,
) -> std::result::Result<CertHandshake, crate::UnlockError> {
    use crate::UnlockError;

    let host_cert_count = host_certs.len();
    tracing::debug!(
        target: "freemkv::disc",
        phase = "handshake_start",
        host_cert_count,
        "handshake starting"
    );

    // Cert-attempt wedge guard: an earlier version fired attempts back-to-back
    // with no pause, which can drive consumer optical drives into a fast-fail
    // firmware wedge. Defense-in-depth: cap attempts, sleep between, bail early.
    const MAX_CERT_ATTEMPTS: usize = 3;
    const PER_CERT_BACKOFF_MS: u64 = 1000;
    let mut last_err_code: Option<u16> = None;
    // The wedge guard caps attempts that TOUCH the drive; the free up-front
    // skip below does not consume it, so bad keydb entries at the front of the
    // list can't exhaust the cap before a VALID cert further down is tried.
    let mut drive_attempts = 0usize;
    for (idx, hc) in host_certs.iter().enumerate() {
        // Up-front host-side validity gate (no drive round-trip): a stored key
        // that fails priv·G == cert pubkey can only earn "KEY NOT ESTABLISHED",
        // so skip it — unless the cert also carries v2 creds the attempt can try.
        let host_id = cert_host_id_hex(&hc.certificate);
        let v1_paired = aacs1_keypair_matches(&hc.private_key, &hc.certificate);
        // Mirror `attempt_one_cert`'s `has_v2` gate exactly: in production
        // (`allow_p256 = false`) the v2 path is never attempted, so a cert whose
        // v1 pairing is dead offers nothing the drive round-trip could use and
        // must be skipped up front — otherwise it reaches the drive, fails the
        // step-7 self-verify, and burns a `MAX_CERT_ATTEMPTS` slot that a later
        // valid cert needs.
        let has_v2 = allow_p256 && hc.private_key_v2.is_some() && hc.certificate_v2.is_some();
        if !v1_paired && !has_v2 {
            tracing::info!(
                target: "freemkv::disc",
                phase = "cert_skip_dead_pairing",
                cert_index = idx,
                host_id = %host_id,
                "skipping host cert: its stored private key does not match its \
                 certificate public key (dead keydb pairing); no drive round-trip"
            );
            continue;
        }
        if drive_attempts >= MAX_CERT_ATTEMPTS {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "cert_attempt_cap_reached",
                max_attempts = MAX_CERT_ATTEMPTS,
                "reached the cert-attempt wedge-guard cap; not trying more certs"
            );
            break;
        }
        if drive_attempts > 0 {
            std::thread::sleep(std::time::Duration::from_millis(PER_CERT_BACKOFF_MS));
        }
        drive_attempts += 1;
        match attempt_one_cert(scsi, hc, idx, la_v1, la_v2, allow_p256) {
            CertOutcome::Ok(ch) => return Ok(ch),
            CertOutcome::Transport => {
                tracing::warn!(
                    target: "freemkv::disc",
                    phase = "handshake_transport_fault",
                    cert_index = idx,
                    "transport fault during AACS auth; aborting"
                );
                return Err(UnlockError::Transport);
            }
            CertOutcome::VidUnavailable => return Err(UnlockError::VidUnavailable),
            CertOutcome::Wedge(sense) => {
                tracing::warn!(
                    target: "freemkv::disc",
                    phase = "handshake_wedge_detected",
                    cert_index = idx,
                    sense_key = sense.sense_key,
                    asc = sense.asc,
                    ascq = sense.ascq,
                    "drive returned ILLEGAL_REQUEST during auth; bailing out to avoid wedge"
                );
                return Err(UnlockError::HandshakeRejected);
            }
            CertOutcome::Reject(code) => {
                last_err_code = Some(code);
                continue;
            }
        }
    }
    // No cert ever reached the drive (every cert skipped as a dead pairing, or
    // the list was empty): this is a keydb/host-cert problem, not a drive
    // rejection — report it as such rather than the less accurate
    // HandshakeRejected the drive never actually issued.
    if drive_attempts == 0 {
        tracing::info!(
            target: "freemkv::disc",
            phase = "no_usable_host_cert",
            host_cert_count,
            "no host certificate was usable (all skipped as dead keydb pairings); \
             no drive round-trip was made"
        );
        return Err(UnlockError::NoUsableHostCert);
    }
    tracing::info!(
        target: "freemkv::disc",
        phase = "vid_cert_rejected",
        host_cert_count,
        tried = drive_attempts,
        last_error_code = last_err_code,
        "The drive rejected the AACS host certificate, so no Volume ID was obtained."
    );
    Err(UnlockError::HandshakeRejected)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scsi::mock::{MockTransport, Reply};

    /// Offline self-test of every host cert in a keydb: does its AACS-LA
    /// signature verify (the exact `verify_cert` check the DRIVE performs at
    /// SEND KEY 0x01), and does the paired private key match the cert public
    /// key? Env-gated on `FREEMKV_KEYDB` so CI skips it; run locally with e.g.
    /// `FREEMKV_KEYDB=~/Downloads/keydb.cfg cargo test la_sig_selftest -- --nocapture`.
    /// This answers "are the certs valid (drive is the problem)?" with no drive.
    #[test]
    fn keydb_host_certs_la_sig_selftest() {
        let Ok(path) = std::env::var("FREEMKV_KEYDB") else {
            eprintln!("FREEMKV_KEYDB unset — skipping offline keydb self-test");
            return;
        };
        let text = std::fs::read_to_string(&path).expect("read keydb");
        let unhex = |s: &str| -> Vec<u8> {
            let s = s.trim();
            let s = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
                .collect()
        };
        let mut n = 0;
        let (mut sig_ok, mut pair_ok) = (0, 0);
        for line in text.lines() {
            let l = line.trim_start();
            if l.starts_with("| HC2") || !l.starts_with("| HC") {
                continue;
            }
            let Some(pk) = l
                .split("HOST_PRIV_KEY")
                .nth(1)
                .map(|s| unhex(s.split('|').next().unwrap_or("")))
            else {
                continue;
            };
            let Some(cert) = l.split("HOST_CERT").nth(1).map(|s| {
                unhex(
                    s.split(';')
                        .next()
                        .unwrap_or("")
                        .split('|')
                        .next()
                        .unwrap_or(""),
                )
            }) else {
                continue;
            };
            if pk.len() != 20 || cert.len() < 92 {
                continue;
            }
            let cert = &cert[..92];
            let hcid: String = cert[4..10].iter().map(|b| format!("{b:02x}")).collect();
            let vc = verify_cert(cert);
            let mut pk20 = [0u8; 20];
            pk20.copy_from_slice(&pk);
            let km = aacs1_keypair_matches(&pk20, cert);
            eprintln!("hcid={hcid} la_sig_verifies={vc} keypair_matches={km}");
            n += 1;
            sig_ok += vc as usize;
            pair_ok += km as usize;
        }
        eprintln!("=== {n} certs: la_sig_ok={sig_ok} keypair_ok={pair_ok} ===");
        assert!(n > 0, "no host certs parsed from {path}");
    }

    // ── Transport-contract tests ── before these, every test here was pure
    // math: nothing drove the handshake fns through a transport that could
    // return `Err`/CHECK CONDITION, letting zero-filled buffers pass as data.

    /// A host cert good enough to reach the SCSI steps (the crypto is exercised
    /// by the math tests; these tests are about the transport contract).
    ///
    /// The private key and the certificate's embedded public key are a genuine
    /// matching pair (priv·G placed at the AACS-1.0 offsets 12/32), so the
    /// step-7 self-verify guard accepts it — a mispaired fixture would now be
    /// rejected before the SCSI steps under test are reached. See
    /// [`mispaired_host_cert`] for the deliberately-broken counterpart.
    pub(crate) fn dummy_cert() -> crate::HostCert {
        let (private_key, px, py) = generate_host_key_pair();
        let mut certificate = vec![0u8; 92];
        certificate[0] = 0x02; // AACS 1.0 host cert type
        certificate[12..32].copy_from_slice(&px);
        certificate[32..52].copy_from_slice(&py);
        crate::HostCert {
            private_key,
            certificate,
            private_key_v2: None,
            certificate_v2: None,
        }
    }

    /// A host cert whose private key does NOT match its certificate's public
    /// key — the exact shape of the corrupt `ffff80000210` keydb entry (its
    /// stored `pk` is a duplicate of another entry's, so `priv·G` yields the
    /// wrong public key). Used to prove the step-7 self-verify guard fires.
    pub(crate) fn mispaired_host_cert() -> crate::HostCert {
        // Two independent keypairs: certificate carries keypair A's public key,
        // private_key is keypair B's secret. priv_B·G != pub_A.
        let (_priv_a, ax, ay) = generate_host_key_pair();
        let (priv_b, _bx, _by) = generate_host_key_pair();
        let mut certificate = vec![0u8; 92];
        certificate[0] = 0x02;
        certificate[12..32].copy_from_slice(&ax);
        certificate[32..52].copy_from_slice(&ay);
        crate::HostCert {
            private_key: priv_b,
            certificate,
            private_key_v2: None,
            certificate_v2: None,
        }
    }

    /// A well-paired cert passes `aacs1_keypair_matches`; the mispaired one (the
    /// `ffff80000210` shape) fails it. This is the exact primitive the key
    /// service's host-cert health gate uses to mark a cert DEAD.
    #[test]
    fn keypair_matches_accepts_a_matched_pair_and_rejects_a_mispaired_one() {
        let good = dummy_cert();
        assert!(
            aacs1_keypair_matches(&good.private_key, &good.certificate),
            "priv·G must equal the cert's public key for a genuine pairing"
        );

        let bad = mispaired_host_cert();
        assert!(
            !aacs1_keypair_matches(&bad.private_key, &bad.certificate),
            "a private key that isn't the cert's must be rejected"
        );

        // Degenerate inputs never panic and are never "valid".
        assert!(!aacs1_keypair_matches(&[0u8; 20], &good.certificate));
        assert!(!aacs1_keypair_matches(
            &good.private_key,
            &good.certificate[..40]
        ));
    }

    /// Catches deleting the `status` check in `scsi_read`: per the transport
    /// contract a CHECK CONDITION is `Ok`, so without it the step returns the
    /// caller's ZERO-FILLED buffer as if the drive had sent it.
    #[test]
    fn scsi_read_rejects_a_check_condition_instead_of_returning_zeros() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let cdb = cdb_report_key(0, 0x01, 116);
        let e = scsi_read(&mut t, &cdb, 116).expect_err("a drive sense is not data");
        assert!(!e.is_scsi_transport_failure(), "a sense is not a bus fault");
        assert!(
            e.scsi_sense()
                .map(|s| s.is_illegal_request())
                .unwrap_or(false),
            "the parsed sense must survive so the wedge guard can read it"
        );
    }

    /// Catches deleting the length check in `scsi_read`: a GOOD status with zero
    /// bytes transferred is a command that moved no data, and parsing the
    /// untouched buffer yields a certificate / key point / VID made of zeros.
    #[test]
    fn scsi_read_rejects_a_zero_length_transfer() {
        let mut t = MockTransport::always(Reply::zero_transfer(116));
        let cdb = cdb_report_key(0, 0x01, 116);
        let e = scsi_read(&mut t, &cdb, 116).expect_err("no bytes is not a response");
        assert!(matches!(
            e,
            Error::ShortTransfer {
                expected: 116,
                got: 0,
                ..
            }
        ));
    }

    // Catches deleting the `status` check in `scsi_write`: a drive REFUSING
    // the cert answers `Ok` + CHECK CONDITION, which must not read as sent.
    #[test]
    fn scsi_write_rejects_a_check_condition() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let cdb = cdb_send_key(0, 0x01, 116);
        let e = scsi_write(&mut t, &cdb, &[0u8; 116]).expect_err("a refused send is not a send");
        assert!(!e.is_scsi_transport_failure());
    }

    /// A transport fault propagates out of `scsi_read` unchanged so
    /// `handshake_err` can preserve it.
    #[test]
    fn scsi_read_propagates_a_transport_fault() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let cdb = cdb_report_key(0, 0x00, 8);
        let e = scsi_read(&mut t, &cdb, 8).expect_err("dead bus");
        assert!(e.is_scsi_transport_failure());
    }

    // Defect-3: a dead bus must ABORT, not `continue` into every remaining
    // cert with backoff (a transport fault has no sense, so the wedge check
    // was false and it misreported HandshakeRejected for a replug).
    #[test]
    fn transport_fault_aborts_the_cert_loop_immediately() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let certs = vec![dummy_cert(), dummy_cert(), dummy_cert()];
        let started = std::time::Instant::now();
        let err = run_cert_handshake(&mut t, &certs).expect_err("dead bus");
        assert_eq!(err, crate::UnlockError::Transport);
        // 4 AGID invalidations + the AGID allocation that faulted. A second cert
        // attempt would show up as more calls AND a 1 s backoff.
        assert_eq!(t.calls(), 5, "must not try the remaining certs");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "must not have slept through a per-cert backoff"
        );
    }

    // A drive rejecting every cert with ILLEGAL REQUEST is a credentials /
    // wedge situation, NOT a dead bus: must still report HandshakeRejected
    // (guards against over-correcting defect 3 into "every failure aborts").
    #[test]
    fn drive_rejection_is_still_handshake_rejected_not_transport() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let certs = vec![dummy_cert()];
        let err = run_cert_handshake(&mut t, &certs).expect_err("rejected");
        assert_eq!(err, crate::UnlockError::HandshakeRejected);
    }

    // A cert-level rejection of the FIRST cert must roll on to the second,
    // gated by the per-cert backoff (`idx > 0`). Pins both the retry and
    // that the backoff genuinely elapses real time.
    #[test]
    fn a_rejected_first_cert_backs_off_and_tries_the_second() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let certs = vec![dummy_cert(), dummy_cert()];
        let started = std::time::Instant::now();
        let err = run_cert_handshake(&mut t, &certs).expect_err("both certs rejected");
        assert_eq!(err, crate::UnlockError::HandshakeRejected);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(900),
            "must have slept the per-cert backoff before the second attempt"
        );
        // Each attempt issues 4 invalidations + 1 AGID alloc (which is where
        // the rejection fires) = 5 CDBs; two attempts = 10.
        assert_eq!(t.calls(), 10, "must have actually issued a second attempt");
    }

    /// Build a synthetic 92-byte AACS 1.0 drive/host certificate carrying
    /// `(pub_x, pub_y)` at the 12/32 offsets, signed by the test LA private key
    /// over cert[..52] (SHA-1), with `type_byte` at offset 0. The AACS-1.0 twin
    /// of [`p256_synth_cert`], so a drive emulator can present a genuinely
    /// LA-verifiable cert under a self-generated test anchor.
    fn v1_synth_cert(
        type_byte: u8,
        pub_x: &[u8; 20],
        pub_y: &[u8; 20],
        la_priv: &[u8; 20],
    ) -> Vec<u8> {
        let mut cert = vec![0u8; 92];
        cert[0] = type_byte;
        cert[12..32].copy_from_slice(pub_x);
        cert[32..52].copy_from_slice(pub_y);
        let (r, s) = ecdsa_sign(la_priv, &cert[..52]);
        cert[52..72].copy_from_slice(&r);
        cert[72..92].copy_from_slice(&s);
        cert
    }

    // Convenience: drive the 1.0 orchestration under a DriveEmu's self-generated
    // test LA anchor (production verifies against the real anchor, which the emu
    // cannot sign for). P-256 stays disabled (unused v2 anchor placeholder).
    fn run_handshake_v1(
        emu: &mut DriveEmu,
        certs: &[crate::HostCert],
    ) -> std::result::Result<CertHandshake, crate::UnlockError> {
        let (lax, lay) = (emu.la_x, emu.la_y);
        run_cert_handshake_with_anchors(emu, certs, (&lax, &lay), (&[0u8; 32], &[0u8; 32]), false)
    }

    // Defect-9: auth SUCCEEDED, then the bus died during the VID read. Must
    // not return VidUnavailable unconditionally (telling the consumer to
    // carry on with a dead transport) — catches dropping that branch.
    #[test]
    fn transport_fault_reading_the_volume_id_is_transport_not_vid_unavailable() {
        let mut t = DriveEmu::new();
        t.fault_on_vid_read = true;
        let err = run_handshake_v1(&mut t, &[dummy_cert()]).expect_err("dead bus on VID read");
        assert_eq!(err, crate::UnlockError::Transport);
    }

    // Counterpart: a bad-MAC VID read really is VidUnavailable — the defect-9
    // fix must not turn every VID failure into a transport error (and, with no
    // v2 creds, there is no P-256 path to fall through to).
    #[test]
    fn bad_volume_id_mac_is_still_vid_unavailable() {
        let mut t = DriveEmu::new();
        t.bad_vid_mac = true;
        let err = run_handshake_v1(&mut t, &[dummy_cert()]).expect_err("bad MAC");
        assert_eq!(err, crate::UnlockError::VidUnavailable);

        // Defect 18: the AGID we authenticated with must be released on the way
        // out, not abandoned. REPORT KEY (0xA4) with format 0x3F in CDB byte 10.
        let last = t.cdbs.last().expect("commands were issued");
        assert_eq!(last[0], crate::scsi::SCSI_REPORT_KEY);
        assert_eq!(last[10] & 0x3F, 0x3F, "AGID released on the failure path");
    }

    // Defect-6: format 0x84 has no MAC, so an all-zero response used to
    // AES-decrypt to a plausible garbage bus key reported as `Ok`. Catches
    // removing the all-zero guard.
    #[test]
    fn read_data_keys_refuses_an_all_zero_response() {
        let mut t = MockTransport::always(Reply::good(vec![0u8; 36]));
        let mut auth = AacsAuth {
            bus_key: [0x42u8; 16],
            agid: 0,
            volume_id: None,
            read_data_key: None,
        };
        let e = read_data_keys(&mut t, &mut auth).expect_err("zeros are not keys");
        assert_eq!(e.code(), Error::AacsDataKey.code());
        assert!(auth.read_data_key.is_none(), "no key may be recorded");
    }

    // A non-zero key block still decrypts and is returned — the defect-6
    // guard must reject only a response the drive plainly never filled.
    #[test]
    fn read_data_keys_accepts_a_non_zero_response() {
        let mut resp = vec![0u8; 36];
        resp[4..20].copy_from_slice(&[0x5Au8; 16]);
        let mut t = MockTransport::always(Reply::good(resp));
        let mut auth = AacsAuth {
            bus_key: [0x42u8; 16],
            agid: 0,
            volume_id: None,
            read_data_key: None,
        };
        let (rdk, _wdk) = read_data_keys(&mut t, &mut auth).expect("decrypts");
        assert_eq!(auth.read_data_key, Some(rdk));
    }

    // BK→RDK derivation: the Read/Write Data Keys handed to the caller MUST be
    // exactly AES-128-ECB-decrypt(bus_key, enc_key). Plants a known bus_key +
    // wrapped keys and pins the exact unwrap (not just "a key was stored").
    #[test]
    fn read_data_keys_unwraps_rdk_by_ecb_decrypt_under_the_bus_key() {
        let bus_key = [0x42u8; 16];
        let enc_rdk = [0x7Bu8; 16];
        let enc_wdk = [0x7Cu8; 16];
        let mut resp = vec![0u8; 36];
        resp[4..20].copy_from_slice(&enc_rdk);
        resp[20..36].copy_from_slice(&enc_wdk);
        let mut t = MockTransport::always(Reply::good(resp));
        let mut auth = AacsAuth {
            bus_key,
            agid: 0,
            volume_id: None,
            read_data_key: None,
        };
        let (rdk, wdk) = read_data_keys(&mut t, &mut auth).expect("decrypts");
        assert_eq!(
            rdk,
            crate::aacs::aes_ecb_decrypt(&bus_key, &enc_rdk),
            "read_data_key must be AES-ECB-decrypt(bus_key, enc_rdk)"
        );
        assert_eq!(
            wdk,
            crate::aacs::aes_ecb_decrypt(&bus_key, &enc_wdk),
            "write_data_key must be AES-ECB-decrypt(bus_key, enc_wdk)"
        );
        assert_eq!(auth.read_data_key, Some(rdk), "the rdk must be recorded");
    }

    // Defect-D1: a cert type byte that's neither 0x01 nor 0x11 must be
    // REJECTED at the cert-type gate, not fall through to trust the drive's
    // own unverified key. `AacsCertVerify` pins it happens before any key is trusted.
    #[test]
    fn unknown_drive_cert_type_is_rejected_before_trusting_any_key() {
        let mut cert_resp = vec![0u8; 116];
        cert_resp[24] = 0x02; // unknown cert type (not 0x01, not 0x11)
        // A key point that WOULD ECDH-derive a bus key if step 6 were reached.
        let mut key_resp = vec![0u8; 84];
        key_resp[4..24].copy_from_slice(&EC_GX);
        key_resp[24..44].copy_from_slice(&EC_GY);
        let script = vec![
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 8]), // AGID alloc → agid 0
            Reply::good(vec![]),       // SEND KEY host cert
            Reply::good(cert_resp),    // REPORT KEY drive cert (type 0x02)
            Reply::good(key_resp),     // REPORT KEY drive key point (must NOT be trusted)
        ];
        let mut t = MockTransport::scripted(script, Reply::good(vec![0u8; 2]));
        let hc = dummy_cert();
        let err = aacs_authenticate(&mut t, &hc.private_key, &hc.certificate)
            .expect_err("an unknown cert type must be rejected, never trusted");
        assert!(
            matches!(err, Error::AacsCertVerify),
            "rejection must fire at the cert-type gate (AacsCertVerify), not fall \
             through to the step-6 key check; got {err:?}"
        );
    }

    // Fix 1: on the AACS 1.0 path a type-0x11 (AACS 2.0) drive cert must be
    // REJECTED at the cert gate — not accepted unverified (which used to skip
    // BOTH the LA cert verify AND the step-6 drive-key signature, then still run
    // ECDH: an attacker-chosen-bus-key hole). The orchestrator routes a genuine
    // 0x11 drive to the native P-256 path instead (see the HybridDrive test).
    #[test]
    fn type_0x11_drive_cert_is_rejected_on_the_1_0_path() {
        let mut cert_resp = vec![0u8; 116];
        cert_resp[24] = 0x11; // AACS 2.0 cert type on the 1.0 AKE
        // A generator-point drive key that WOULD ECDH-derive a bus key if the
        // (now-removed) 0x11 skip let step 6 through unverified.
        let mut key_resp = vec![0u8; 84];
        key_resp[4..24].copy_from_slice(&EC_GX);
        key_resp[24..44].copy_from_slice(&EC_GY);
        let script = vec![
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 8]), // AGID alloc → agid 0
            Reply::good(vec![]),       // SEND KEY host cert
            Reply::good(cert_resp),    // REPORT KEY drive cert (type 0x11)
            Reply::good(key_resp),     // REPORT KEY drive key point (must NOT be trusted)
        ];
        let mut t = MockTransport::scripted(script, Reply::good(vec![0u8; 2]));
        let hc = dummy_cert();
        let err = aacs_authenticate(&mut t, &hc.private_key, &hc.certificate)
            .expect_err("a 0x11 cert must be rejected on the 1.0 path, never accepted unverified");
        assert!(
            matches!(err, Error::AacsCertVerify),
            "a 0x11 cert must be rejected at the cert gate (AacsCertVerify); got {err:?}"
        );
    }

    // Plays the DRIVE side of a genuine AACS 1.0 handshake: presents a type-0x01
    // drive cert signed by its own self-generated test LA key (`la_x`/`la_y`),
    // signs the step-6 drive key point with the cert's long-term key, and derives
    // the same bus key as the host (ECDH is symmetric) so its VID MAC verifies.
    // Auth + VID read SUCCEED; by default it then dies on read-data-keys.
    pub(crate) struct DriveEmu {
        /// Self-generated AACS 1.0 LA test anchor public half. A test threads
        /// `la_x`/`la_y` into `run_cert_handshake_with_anchors` (production can't
        /// sign for the real anchor); the private half signs `cert` once, in
        /// `new`, and is not retained.
        pub(crate) la_x: [u8; 20],
        pub(crate) la_y: [u8; 20],
        /// Drive long-term (certificate) keypair: its public half is embedded in
        /// `cert`, and it signs the step-6 drive key point.
        lt_priv: [u8; 20],
        /// The 92-byte type-0x01 drive certificate (LA-signed, embeds the
        /// long-term public key).
        cert: Vec<u8>,
        /// Ephemeral ECDH keypair — the "drive key point" the host multiplies
        /// against, and the drive's own half of the shared bus key.
        eph_priv: [u8; 20],
        eph_x: [u8; 20],
        eph_y: [u8; 20],
        vid: [u8; 16],
        bus_key: Option<[u8; 16]>,
        /// The nonce the drive issues at step 5, which the host must sign at
        /// step 7 (over `drive_nonce || host_key_point_x || host_key_point_y`).
        drive_nonce: [u8; 20],
        /// The host nonce captured at step 4 (SEND KEY 0x01), which the drive
        /// signs at step 6 (over `host_nonce || drive_key_point`).
        host_nonce: [u8; 20],
        /// When set, the drive verifies the host's step-8 signature against
        /// this host-cert public key over the EXACT step-7 layout, and records
        /// the result in `host_sig_ok` — pinning the production signed-data
        /// layout the way a real drive checks it.
        pub(crate) host_cert_pub: Option<([u8; 20], [u8; 20])>,
        /// Result of the step-8 host-signature check (`None` until SEND KEY
        /// format 0x02 arrives, and only when `host_cert_pub` is set).
        pub(crate) host_sig_ok: Option<bool>,
        /// When set, format-0x84 (read-data-keys) is served a genuine non-zero
        /// response instead of the default dead-bus behaviour, letting
        /// `run_cert_handshake` run all the way to its `Ok` return.
        pub(crate) serve_data_keys: bool,
        /// When set, format-0x84 is served an all-ZERO (but GOOD-status)
        /// response: a non-transport `AacsDataKey` failure, so `run_cert_handshake`
        /// returns `Ok` with `read_data_key: None` + `read_data_key_err: Some` —
        /// the "auth+VID OK, drive served no bus key" path.
        pub(crate) serve_zero_data_keys: bool,
        /// When set, the VID read (format 0x80) faults the bus (transport error).
        pub(crate) fault_on_vid_read: bool,
        /// When set, the VID read returns a GOOD-status VID with a CORRUPTED MAC
        /// (Error::AacsVidMac), for the post-auth VID/MAC-failure paths.
        pub(crate) bad_vid_mac: bool,
        /// Every 92-byte host cert the host shipped at SEND KEY format 0x01
        /// (step 4), in order. Lets a test assert a locally-skipped cert never
        /// reached the drive at all (no wasted round-trip).
        pub(crate) certs_sent: Vec<Vec<u8>>,
        /// Reject this many initial SEND KEY format-0x01 cert-sends with a
        /// CHECK CONDITION / 6F/00 (AACS copy-protection key-exchange failure —
        /// the shape of an HRL revocation), then behave normally. Models a
        /// drive that revokes a structurally-valid host cert.
        pub(crate) revoke_cert_sends: usize,
        /// Every CDB issued, in order (lets a test assert the AGID was released).
        pub(crate) cdbs: Vec<Vec<u8>>,
    }

    impl DriveEmu {
        pub(crate) fn new() -> Self {
            let (la_priv, la_x, la_y) = generate_host_key_pair();
            let (lt_priv, lt_x, lt_y) = generate_host_key_pair();
            let (eph_priv, eph_x, eph_y) = generate_host_key_pair();
            let cert = v1_synth_cert(0x01, &lt_x, &lt_y, &la_priv);
            let mut drive_nonce = [0u8; 20];
            use rand::Rng;
            rand::rng().fill_bytes(&mut drive_nonce);
            DriveEmu {
                la_x,
                la_y,
                lt_priv,
                cert,
                eph_priv,
                eph_x,
                eph_y,
                vid: [0x5Au8; 16],
                bus_key: None,
                drive_nonce,
                host_nonce: [0u8; 20],
                host_cert_pub: None,
                host_sig_ok: None,
                serve_data_keys: false,
                serve_zero_data_keys: false,
                fault_on_vid_read: false,
                bad_vid_mac: false,
                certs_sent: Vec::new(),
                revoke_cert_sends: 0,
                cdbs: Vec::new(),
            }
        }
    }

    impl ScsiTransport for DriveEmu {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            self.cdbs.push(cdb.to_vec());
            let ok = |payload: Vec<u8>, data: &mut [u8]| {
                let n = payload.len().min(data.len());
                data[..n].copy_from_slice(&payload[..n]);
                Ok(crate::scsi::ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0u8; 32],
                })
            };
            match cdb[0] {
                crate::scsi::SCSI_REPORT_KEY => match cdb[10] & 0x3F {
                    0x3F => ok(vec![0u8; 2], data), // invalidate
                    0x00 => ok(vec![0u8; 8], data), // AGID alloc → agid 0
                    0x01 => {
                        // drive cert (type 0x01, LA-signed) + nonce.
                        let mut r = vec![0u8; 116];
                        r[4..24].copy_from_slice(&self.drive_nonce);
                        r[24..116].copy_from_slice(&self.cert);
                        ok(r, data)
                    }
                    0x02 => {
                        // drive key point x[4..24], y[24..44] + a signature over
                        // host_nonce||x||y by the LONG-TERM cert key (verified
                        // host-side against cert_pub_key(drive_cert)).
                        let mut signed = [0u8; 60];
                        signed[..20].copy_from_slice(&self.host_nonce);
                        signed[20..40].copy_from_slice(&self.eph_x);
                        signed[40..60].copy_from_slice(&self.eph_y);
                        let (sr, ss) = ecdsa_sign(&self.lt_priv, &signed);
                        let mut r = vec![0u8; 84];
                        r[4..24].copy_from_slice(&self.eph_x);
                        r[24..44].copy_from_slice(&self.eph_y);
                        r[44..64].copy_from_slice(&sr);
                        r[64..84].copy_from_slice(&ss);
                        ok(r, data)
                    }
                    _ => ok(vec![0u8; 2], data),
                },
                crate::scsi::SCSI_SEND_KEY => {
                    if cdb[10] & 0x3F == 0x01 {
                        // Step 4: host cert + nonce. Capture the host nonce (the
                        // drive signs it at step 6) and record the cert bytes so a
                        // test can prove a locally-skipped cert never got here.
                        self.host_nonce.copy_from_slice(&data[4..24]);
                        self.certs_sent.push(data[24..116].to_vec());
                        if self.certs_sent.len() <= self.revoke_cert_sends {
                            // Revoke this cert: CHECK CONDITION / 6F/00.
                            let mut sense = [0u8; 32];
                            sense[2] = 0x05; // ILLEGAL REQUEST
                            sense[12] = 0x6F; // copy-protection key-exchange failure
                            sense[13] = 0x00;
                            return Ok(crate::scsi::ScsiResult {
                                status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
                                bytes_transferred: 0,
                                sense,
                            });
                        }
                    }
                    if cdb[10] & 0x3F == 0x02 {
                        // host key point arrives in the ToDevice buffer; derive
                        // the shared bus key from the drive side (eph_priv ×
                        // host_point) — equals host_priv × drive_point.
                        let mut hx = [0u8; 20];
                        let mut hy = [0u8; 20];
                        hx.copy_from_slice(&data[4..24]);
                        hy.copy_from_slice(&data[24..44]);
                        self.bus_key = compute_bus_key(&self.eph_priv, &hx, &hy);

                        // If asked to, verify the host's signature exactly as a
                        // real drive would: over drive_nonce || host_x || host_y
                        // (the step-7 layout), using the host cert public key.
                        if let Some((hpx, hpy)) = self.host_cert_pub {
                            let mut sr = [0u8; 20];
                            let mut ss = [0u8; 20];
                            sr.copy_from_slice(&data[44..64]);
                            ss.copy_from_slice(&data[64..84]);
                            let mut signed = [0u8; 60];
                            signed[..20].copy_from_slice(&self.drive_nonce);
                            signed[20..40].copy_from_slice(&hx);
                            signed[40..60].copy_from_slice(&hy);
                            self.host_sig_ok = Some(ecdsa_verify(&hpx, &hpy, &sr, &ss, &signed));
                        }
                    }
                    ok(vec![], data)
                }
                crate::scsi::SCSI_READ_DISC_STRUCTURE => match cdb[7] {
                    0x80 => {
                        if self.fault_on_vid_read {
                            return Err(crate::scsi::ScsiError {
                                status: crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                                sense: None,
                            });
                        }
                        let bus = self.bus_key.expect("bus key derived at step 8");
                        let mut mac = aes_cmac_16(&self.vid, &bus);
                        if self.bad_vid_mac {
                            mac[0] ^= 0xFF; // corrupt the MAC → Error::AacsVidMac
                        }
                        let mut r = vec![0u8; 36];
                        r[4..20].copy_from_slice(&self.vid);
                        r[20..36].copy_from_slice(&mac);
                        ok(r, data)
                    }
                    // format 0x84 read-data-keys: the bus dies here, unless
                    // the test opted into a full success path.
                    _ => {
                        if self.serve_zero_data_keys {
                            // GOOD status, all-zero block: read_data_keys rejects
                            // it (AacsDataKey, non-transport) → Ok with no bus key.
                            ok(vec![0u8; 36], data)
                        } else if self.serve_data_keys {
                            let mut r = vec![0u8; 36];
                            r[4..20].copy_from_slice(&[0x7Bu8; 16]); // enc read data key
                            r[20..36].copy_from_slice(&[0x7Cu8; 16]); // enc write data key
                            ok(r, data)
                        } else {
                            Err(crate::scsi::ScsiError {
                                status: crate::scsi::SCSI_STATUS_TRANSPORT_FAILURE,
                                sense: None,
                            })
                        }
                    }
                },
                _ => ok(vec![0u8; 2], data),
            }
        }
    }

    // Defect-D5: auth + VID SUCCEED, then the bus dies on read-data-keys.
    // That arm must classify `is_scsi_transport_failure()` like its VID-read
    // sibling, or a dead bus renders as a successful-looking unlock.
    #[test]
    fn transport_fault_reading_data_keys_is_transport_not_success() {
        let mut t = DriveEmu::new();
        let err = run_handshake_v1(&mut t, &[dummy_cert()])
            .expect_err("dead bus on the read-data-keys command");
        assert_eq!(err, crate::UnlockError::Transport);
    }

    /// Constant-time compare must still be a CORRECT compare.
    #[test]
    fn ct_eq_16_matches_ordinary_equality() {
        let a = [0x11u8; 16];
        assert!(ct_eq_16(&a, &a));
        for i in 0..16 {
            let mut b = a;
            b[i] ^= 0x80;
            assert!(!ct_eq_16(&a, &b), "differs at byte {i}");
        }
    }

    #[test]
    fn handshake_err_preserves_transport_failure() {
        use crate::scsi::{SCSI_STATUS_CHECK_CONDITION, SCSI_STATUS_TRANSPORT_FAILURE};

        // A transport wedge mid-handshake must NOT be reported as a cert/key
        // rejection — the operator needs to see the real (replug) cause, not
        // be sent down a keydb/host-cert rabbit hole.
        let transport = Error::Scsi {
            opcode: 0xA3, // SEND KEY
            status: SCSI_STATUS_TRANSPORT_FAILURE,
            sense: None,
        };
        let mapped = handshake_err(transport, Error::AacsCertRejected);
        assert!(
            mapped.is_scsi_transport_failure(),
            "transport failure must be preserved, not collapsed to a cert code"
        );

        // A genuine SCSI rejection (CHECK CONDITION) IS the drive saying no, so
        // it maps to the handshake-specific code as before.
        let rejected = Error::Scsi {
            opcode: 0xA3,
            status: SCSI_STATUS_CHECK_CONDITION,
            sense: Some(crate::scsi::ScsiSense {
                sense_key: 0x05, // ILLEGAL REQUEST
                asc: 0x24,
                ascq: 0x00,
            }),
        };
        let mapped = handshake_err(rejected, Error::AacsCertRejected);
        assert!(matches!(mapped, Error::AacsCertRejected));
        assert!(!mapped.is_scsi_transport_failure());
    }

    #[test]
    fn test_ec_curve_generator_on_curve() {
        // Verify G is on the curve: y² = x³ + ax + b (mod p)
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let b = BigUint::from_bytes_be(&EC_B);
        let gx = BigUint::from_bytes_be(&EC_GX);
        let gy = BigUint::from_bytes_be(&EC_GY);

        let lhs = (&gy * &gy) % &p;
        let rhs = (&gx * &gx * &gx + &a * &gx + &b) % &p;
        assert_eq!(lhs, rhs, "Generator point is not on the curve");
    }

    #[test]
    fn test_ec_mul_identity() {
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let g = EcPoint::from_bytes(&EC_GX, &EC_GY);

        // 1 × G = G
        let result = ec_mul(&BigUint::one(), &g, &a, &p);
        assert_eq!(result.x, g.x);
        assert_eq!(result.y, g.y);
    }

    #[test]
    fn test_ec_mul_order() {
        // n × G = O (point at infinity)
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let n = BigUint::from_bytes_be(&EC_N);
        let g = EcPoint::from_bytes(&EC_GX, &EC_GY);

        let result = ec_mul(&n, &g, &a, &p);
        assert!(result.infinity, "n × G should be point at infinity");
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        // Generate a key pair and test sign/verify
        let (priv_key, pub_x, pub_y) = generate_host_key_pair();
        let data = b"test data for AACS ECDSA";

        let (sig_r, sig_s) = ecdsa_sign(&priv_key, data);
        assert!(
            ecdsa_verify(&pub_x, &pub_y, &sig_r, &sig_s, data),
            "ECDSA signature should verify"
        );

        // Verify with wrong data fails
        assert!(
            !ecdsa_verify(&pub_x, &pub_y, &sig_r, &sig_s, b"wrong data"),
            "ECDSA should fail with wrong data"
        );
    }

    #[test]
    fn test_ecdh_shared_secret() {
        // Two parties should derive the same shared point
        let _p = BigUint::from_bytes_be(&EC_P);
        let _a = BigUint::from_bytes_be(&EC_A);
        let _g = EcPoint::from_bytes(&EC_GX, &EC_GY);

        let (priv_a, pub_ax, pub_ay) = generate_host_key_pair();
        let (priv_b, pub_bx, pub_by) = generate_host_key_pair();

        // A computes: priv_a × pub_B
        let shared_a = compute_bus_key(&priv_a, &pub_bx, &pub_by)
            .expect("on-curve generated point must be accepted");
        // B computes: priv_b × pub_A
        let shared_b = compute_bus_key(&priv_b, &pub_ax, &pub_ay)
            .expect("on-curve generated point must be accepted");

        assert_eq!(shared_a, shared_b, "ECDH shared secrets should match");
    }

    #[test]
    fn test_p256_generator_on_curve() {
        let p = BigUint::from_bytes_be(&P256_P);
        let a = BigUint::from_bytes_be(&P256_A);
        let b = BigUint::from_bytes_be(&P256_B);
        let gx = BigUint::from_bytes_be(&P256_GX);
        let gy = BigUint::from_bytes_be(&P256_GY);

        let lhs = (&gy * &gy) % &p;
        let rhs = (&gx * &gx * &gx + &a * &gx + &b) % &p;
        assert_eq!(lhs, rhs, "P-256 generator not on curve");
    }

    #[test]
    fn test_p256_mul_order() {
        let p = BigUint::from_bytes_be(&P256_P);
        let a = BigUint::from_bytes_be(&P256_A);
        let n = BigUint::from_bytes_be(&P256_N);
        let g = EcPoint::from_bytes(&P256_GX, &P256_GY);

        let result = ec_mul(&n, &g, &a, &p);
        assert!(
            result.infinity,
            "n × G should be point at infinity on P-256"
        );
    }

    #[test]
    fn test_p256_ecdsa_sign_verify() {
        let p = BigUint::from_bytes_be(&P256_P);
        let a = BigUint::from_bytes_be(&P256_A);
        let n = BigUint::from_bytes_be(&P256_N);
        let g = EcPoint::from_bytes(&P256_GX, &P256_GY);

        // Generate random P-256 key pair
        let mut priv_bytes = [0u8; 32];
        use rand::Rng;
        rand::rng().fill_bytes(&mut priv_bytes);
        let d = BigUint::from_bytes_be(&priv_bytes) % &n;
        let priv_key: [u8; 32] = to_bytes_be_padded(&d, 32).try_into().unwrap();

        let pub_point = ec_mul(&d, &g, &a, &p);
        let pub_x: Vec<u8> = to_bytes_be_padded(&pub_point.x, 32);
        let pub_y: Vec<u8> = to_bytes_be_padded(&pub_point.y, 32);

        let data = b"AACS 2.0 P-256 ECDSA test";
        let (sig_r, sig_s) = ecdsa_sign_p256(&priv_key, data);
        assert!(ecdsa_verify_p256(&pub_x, &pub_y, &sig_r, &sig_s, data));
        assert!(!ecdsa_verify_p256(&pub_x, &pub_y, &sig_r, &sig_s, b"wrong"));
    }

    #[test]
    fn test_p256_ecdh() {
        let p = BigUint::from_bytes_be(&P256_P);
        let a = BigUint::from_bytes_be(&P256_A);
        let n = BigUint::from_bytes_be(&P256_N);
        let g = EcPoint::from_bytes(&P256_GX, &P256_GY);

        let mut pa = [0u8; 32];
        let mut pb = [0u8; 32];
        use rand::Rng;
        rand::rng().fill_bytes(&mut pa);
        rand::rng().fill_bytes(&mut pb);
        let da = BigUint::from_bytes_be(&pa) % &n;
        let db = BigUint::from_bytes_be(&pb) % &n;
        let priv_a: [u8; 32] = to_bytes_be_padded(&da, 32).try_into().unwrap();
        let priv_b: [u8; 32] = to_bytes_be_padded(&db, 32).try_into().unwrap();

        let pub_a = ec_mul(&da, &g, &a, &p);
        let pub_b = ec_mul(&db, &g, &a, &p);

        let key_a = compute_bus_key_p256(
            &priv_a,
            &to_bytes_be_padded(&pub_b.x, 32),
            &to_bytes_be_padded(&pub_b.y, 32),
        )
        .expect("on-curve generated point must be accepted");
        let key_b = compute_bus_key_p256(
            &priv_b,
            &to_bytes_be_padded(&pub_a.x, 32),
            &to_bytes_be_padded(&pub_a.y, 32),
        )
        .expect("on-curve generated point must be accepted");

        assert_eq!(key_a, key_b, "P-256 ECDH shared secrets should match");
    }

    #[test]
    fn test_aes_cmac_deterministic() {
        // Same (data, key) must always produce the same MAC.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = [0u8; 16];
        let mac1 = aes_cmac_16(&data, &key);
        let mac2 = aes_cmac_16(&data, &key);
        assert_eq!(mac1, mac2);
        assert_ne!(mac1, [0u8; 16]); // shouldn't be all zeros
    }

    #[test]
    fn test_aes_cmac_nist_kat_full_block() {
        // NIST SP 800-38B Appendix D.1, Example 2 (Mlen = 128).
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        let mac = aes_cmac_16(&data, &key);
        assert_eq!(mac, expected, "AES-CMAC-128 must match NIST SP 800-38B KAT");
    }

    #[test]
    fn test_vid_mac_verify_roundtrip() {
        // Simulate the drive-side MAC, verify the host-side check accepts it,
        // then mutate VID and MAC in turn and confirm each causes a mismatch
        // (the path that yields Error::AacsVidMac in read_volume_id).
        let bus_key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let vid = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];

        // Drive returns vid + mac where mac == AES-CMAC-128(bus_key, vid).
        let drive_mac = aes_cmac_16(&vid, &bus_key);
        let calc_mac = aes_cmac_16(&vid, &bus_key);
        assert_eq!(calc_mac, drive_mac, "honest drive: MACs must match");

        // Mutate the MAC: a malicious drive that swapped VID but returned its
        // original MAC would produce a mismatch here.
        let mut bad_mac = drive_mac;
        bad_mac[0] ^= 0x01;
        assert_ne!(calc_mac, bad_mac, "mutated MAC must be rejected");

        // Mutate the VID: even one bit of VID drift produces a wildly different
        // CMAC (this is what catches a substituted VID with a stale MAC).
        let mut bad_vid = vid;
        bad_vid[15] ^= 0x01;
        let calc_for_bad_vid = aes_cmac_16(&bad_vid, &bus_key);
        assert_ne!(
            calc_for_bad_vid, drive_mac,
            "MAC over mutated VID must not match original MAC"
        );

        // Wrong bus key (e.g. handshake replayed against the wrong session)
        // also produces a different MAC over the same VID.
        let mut wrong_key = bus_key;
        wrong_key[0] ^= 0xff;
        let calc_with_wrong_key = aes_cmac_16(&vid, &wrong_key);
        assert_ne!(
            calc_with_wrong_key, drive_mac,
            "MAC under wrong bus key must not match"
        );
    }

    #[test]
    fn test_vid_mac_all_zero_mac_rejected() {
        // Defensive: a buggy/hostile drive returning an all-zero MAC must be
        // rejected — the real MAC over any non-trivial VID is nearly never 0.
        let bus_key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let vid = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let calc_mac = aes_cmac_16(&vid, &bus_key);
        assert_ne!(calc_mac, [0u8; 16], "real CMAC must not be all zeros");
    }

    #[test]
    fn test_verify_cert_p256_short_cert_no_panic() {
        // verify_cert_p256 slices cert[68..100]/[100..132]/[..68]; a cert
        // shorter than 132 must return false, never panic. Sweep the boundary.
        for len in [0usize, 67, 68, 99, 100, 131] {
            let cert = vec![0x11u8; len];
            assert!(
                !verify_cert_p256(&cert, &AACS2_LA_PUB_X, &AACS2_LA_PUB_Y),
                "len {len} must not panic"
            );
        }
        // A 132-byte all-0x11 cert reaches verification and is rejected on its
        // (invalid) signature — still false, still no panic.
        assert!(
            !verify_cert_p256(&[0x11u8; 132], &AACS2_LA_PUB_X, &AACS2_LA_PUB_Y),
            "132-byte cert with a bogus signature must verify-false, not panic"
        );
    }

    #[test]
    fn test_compute_bus_key_rejects_off_curve_point() {
        // An off-curve drive point must be rejected (invalid-curve guard),
        // while an on-curve point (here the generator G) is accepted.
        let (host_priv, _, _) = generate_host_key_pair();

        // On-curve: G itself.
        assert!(
            compute_bus_key(&host_priv, &EC_GX, &EC_GY).is_some(),
            "on-curve point must be accepted"
        );

        // Off-curve: G with y flipped by one bit almost never stays on the curve.
        let mut bad_y = EC_GY;
        bad_y[19] ^= 0x01;
        assert!(
            compute_bus_key(&host_priv, &EC_GX, &bad_y).is_none(),
            "off-curve point must be rejected"
        );
    }

    #[test]
    fn test_compute_bus_key_p256_rejects_off_curve_point() {
        let (host_priv, _, _) = generate_host_key_pair_p256();

        assert!(
            compute_bus_key_p256(&host_priv, &P256_GX, &P256_GY).is_some(),
            "on-curve P-256 point must be accepted"
        );

        let mut bad_y = P256_GY;
        bad_y[31] ^= 0x01;
        assert!(
            compute_bus_key_p256(&host_priv, &P256_GX, &bad_y).is_none(),
            "off-curve P-256 point must be rejected"
        );
    }

    // Fix 6: a shared point at infinity must never be reduced to a bus key. With
    // host_priv == n (the group order), n·G == O, so the ECDH result is the point
    // at infinity — the on-curve guard passes (G is on-curve) but the infinity
    // guard must return None rather than derive an all-zero-ish key.
    #[test]
    fn compute_bus_key_rejects_a_shared_point_at_infinity() {
        assert!(
            compute_bus_key(&EC_N, &EC_GX, &EC_GY).is_none(),
            "n·G is the point at infinity and must yield no bus key (AACS 1.0)"
        );
        assert!(
            compute_bus_key_p256(&P256_N, &P256_GX, &P256_GY).is_none(),
            "n·G is the point at infinity and must yield no bus key (P-256)"
        );
    }

    // Fix 8: when NO host cert reaches the drive (empty list, or every cert
    // skipped as a dead pairing), the outcome is NoUsableHostCert — a keydb/
    // host-cert problem — not the HandshakeRejected a drive would have to issue.
    #[test]
    fn no_usable_host_cert_when_no_cert_reaches_the_drive() {
        // Empty list: never touches the drive.
        let mut t = MockTransport::always(Reply::TransportFault);
        let err = run_cert_handshake(&mut t, &[]).expect_err("no certs at all");
        assert_eq!(err, crate::UnlockError::NoUsableHostCert);
        assert_eq!(t.calls(), 0, "an empty cert list issues no SCSI command");

        // A list of only dead pairings is likewise NoUsableHostCert (all skipped
        // host-side, no drive round-trip).
        let mut t2 = MockTransport::always(Reply::illegal_request());
        let err2 = run_cert_handshake(&mut t2, &[mispaired_host_cert(), mispaired_host_cert()])
            .expect_err("only dead pairings");
        assert_eq!(err2, crate::UnlockError::NoUsableHostCert);
        assert_eq!(t2.calls(), 0, "dead pairings issue no SCSI command");
    }

    // `test_verify_host_cert_from_keydb` was removed (env-gated, inert, asserted
    // nothing); its property is now pinned by `la_anchor_keys_are_on_curve`.
    // ── Hardening additions: EC curve invariants (4a³+27b² != 0) ──

    #[test]
    fn aacs1_curve_is_nonsingular() {
        // A valid Weierstrass curve requires discriminant 4a³ + 27b² ≠ 0
        // (mod p). A typo in EC_A or EC_B that singularised the curve would be
        // caught here.
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let b = BigUint::from_bytes_be(&EC_B);
        let four = BigUint::from(4u32);
        let twenty_seven = BigUint::from(27u32);
        let disc = (&four * &a % &p * &a % &p * &a % &p + &twenty_seven * &b % &p * &b % &p) % &p;
        assert!(!disc.is_zero(), "AACS 1.0 curve must be nonsingular");
    }

    #[test]
    fn p256_curve_is_nonsingular() {
        let p = BigUint::from_bytes_be(&P256_P);
        let a = BigUint::from_bytes_be(&P256_A);
        let b = BigUint::from_bytes_be(&P256_B);
        let four = BigUint::from(4u32);
        let twenty_seven = BigUint::from(27u32);
        let disc = (&four * &a % &p * &a % &p * &a % &p + &twenty_seven * &b % &p * &b % &p) % &p;
        assert!(!disc.is_zero(), "P-256 curve must be nonsingular");
    }

    // ── mod_inv ────────────────────────────────────────────────────────────

    #[test]
    fn mod_inv_round_trips() {
        // a * a⁻¹ ≡ 1 (mod m). Pin against the AACS prime.
        let m = BigUint::from_bytes_be(&EC_N);
        let a = BigUint::from(123456789u64);
        let inv = mod_inv(&a, &m).expect("inverse exists for a coprime to prime n");
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }

    #[test]
    fn mod_inv_of_one_is_one() {
        let m = BigUint::from(97u32);
        assert_eq!(mod_inv(&BigUint::one(), &m), Some(BigUint::one()));
    }

    // ── to_bytes_be_padded ─────────────────────────────────────────────────

    #[test]
    fn to_bytes_be_padded_left_pads_short_values() {
        // A small number must be left-zero-padded to the fixed width (keys are
        // fixed-size big-endian; a short value left unpadded would shift bytes).
        let n = BigUint::from(0x1234u32);
        assert_eq!(to_bytes_be_padded(&n, 20), {
            let mut v = vec![0u8; 18];
            v.extend_from_slice(&[0x12, 0x34]);
            v
        });
    }

    #[test]
    fn to_bytes_be_padded_truncates_to_low_bytes_when_longer() {
        // When the encoding is longer than len, the low `len` bytes are kept
        // (the function slices the tail) — this is how the 256-bit ECDH x is
        // reduced to the low 128 bits for the bus key.
        let n = BigUint::from(0x0102030405u64); // 5 bytes
        assert_eq!(to_bytes_be_padded(&n, 2), vec![0x04, 0x05]);
    }

    // ── point_on_curve (via compute_bus_key acceptance) ────────────────────
    // point_on_curve is private; exercise it through compute_bus_key, which
    // calls it as the invalid-curve guard.

    #[test]
    fn off_curve_x_out_of_field_is_rejected() {
        // A coordinate >= p is outside the field and must be rejected before
        // the multiply (the `x >= p || y >= p` guard). Use x = p (== modulus).
        let (host_priv, _, _) = generate_host_key_pair();
        // EC_P itself as the x coordinate → x == p → out of field.
        assert!(
            compute_bus_key(&host_priv, &EC_P, &EC_GY).is_none(),
            "x == p is out of field and must be rejected"
        );
    }

    // ── CDB builders: REPORT KEY / SEND KEY / REPORT DISC STRUCTURE ────────

    #[test]
    fn cdb_report_key_layout() {
        // 0xA4 opcode; AACS key class at byte 7; BE16 length at 8/9;
        // (agid<<6)|format at byte 10. Pin the exact bit packing.
        let cdb = cdb_report_key(0b10, 0x02, 0x0054);
        assert_eq!(cdb[0], crate::scsi::SCSI_REPORT_KEY);
        assert_eq!(cdb[7], crate::scsi::AACS_KEY_CLASS);
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 0x54);
        // agid=2 → bits 7:6 = 10b = 0x80; format 0x02 in low 6 bits.
        assert_eq!(cdb[10], 0x80 | 0x02);
    }

    #[test]
    fn cdb_report_key_format_masked_to_6_bits() {
        // The format field is `format & 0x3F`; a value with bits 6/7 set must
        // not bleed into the AGID field. 0xFF & 0x3F == 0x3F.
        let cdb = cdb_report_key(0, 0xFF, 2);
        assert_eq!(cdb[10], 0x3F, "format must be masked to its low 6 bits");
    }

    #[test]
    fn cdb_send_key_layout() {
        let cdb = cdb_send_key(0b11, 0x01, 116);
        assert_eq!(cdb[0], crate::scsi::SCSI_SEND_KEY);
        assert_eq!(cdb[7], crate::scsi::AACS_KEY_CLASS);
        assert_eq!(cdb[8], (116u16 >> 8) as u8);
        assert_eq!(cdb[9], (116u16 & 0xFF) as u8);
        assert_eq!(cdb[10], (0b11 << 6) | 0x01);
    }

    #[test]
    fn cdb_report_disc_structure_layout() {
        // 0xAD opcode; byte 1 = 0x01 (Blu-ray); format at byte 7; BE16 length;
        // agid<<6 at byte 10 (no format bits here).
        let cdb = cdb_report_disc_structure(0b01, 0x80, 36);
        assert_eq!(cdb[0], crate::scsi::SCSI_READ_DISC_STRUCTURE);
        assert_eq!(cdb[1], 0x01);
        assert_eq!(cdb[7], 0x80);
        assert_eq!(cdb[8], 0x00);
        assert_eq!(cdb[9], 36);
        assert_eq!(cdb[10], 0b01 << 6);
    }

    // ── verify_cert (AACS 1.0): length guard ───────────────────────────────

    #[test]
    fn verify_cert_v1_rejects_short_cert_no_panic() {
        // < 92 bytes → false (the sig slices cert[52..72]/[72..92] would
        // otherwise panic). Sweep the boundary.
        for len in [0usize, 51, 52, 71, 72, 91] {
            assert!(!verify_cert(&vec![0u8; len]), "len {len} must not panic");
        }
    }

    #[test]
    fn cert_pub_key_v1_zeroes_when_too_short() {
        // < 52 bytes → zeroed (x,y) rather than an OOB slice on cert[12..52].
        let (x, y) = cert_pub_key(&[0u8; 40]);
        assert_eq!(x, [0u8; 20]);
        assert_eq!(y, [0u8; 20]);
    }

    #[test]
    fn cert_pub_key_v1_extracts_offsets_12_32_52() {
        // pub_x at [12..32], pub_y at [32..52]. Build a 92-byte cert with
        // distinct x/y regions.
        let mut cert = vec![0u8; 92];
        for b in &mut cert[12..32] {
            *b = 0xA1;
        }
        for b in &mut cert[32..52] {
            *b = 0xB2;
        }
        let (x, y) = cert_pub_key(&cert);
        assert_eq!(x, [0xA1u8; 20]);
        assert_eq!(y, [0xB2u8; 20]);
    }

    #[test]
    fn cert_pub_key_p256_extracts_offsets_4_36_68() {
        // AACS 2.0 (132-byte cert): pub_x@[4..36], pub_y@[36..68]. Catches
        // regressing to the old 10-byte-header [10..42]/[42..74] offsets.
        let mut cert = vec![0u8; 132];
        for b in &mut cert[4..36] {
            *b = 0xC3;
        }
        for b in &mut cert[36..68] {
            *b = 0xD4;
        }
        let (x, y) = cert_pub_key_p256(&cert);
        assert_eq!(x, [0xC3u8; 32]);
        assert_eq!(y, [0xD4u8; 32]);
    }

    #[test]
    fn cert_pub_key_p256_zeroes_when_too_short() {
        // < 68 bytes → zeroed, matching the verify_cert_p256 >= 132 guard's
        // safety contract (no OOB on cert[4..68]).
        let (x, y) = cert_pub_key_p256(&[0u8; 67]);
        assert_eq!(x, [0u8; 32]);
        assert_eq!(y, [0u8; 32]);
    }

    // ── ECDSA sign produces 20/32-byte fixed-width outputs ─────────────────

    #[test]
    fn ecdsa_sign_outputs_are_fixed_width_and_verify() {
        // Sign/verify already covered; assert (r,s) are full-width and
        // non-trivial, and round-trip through verify.
        let (priv_key, px, py) = generate_host_key_pair();
        let (r, s) = ecdsa_sign(&priv_key, b"payload");
        assert_ne!(r, [0u8; 20]);
        assert_ne!(s, [0u8; 20]);
        assert!(ecdsa_verify(&px, &py, &r, &s, b"payload"));
    }

    #[test]
    fn ecdsa_verify_rejects_out_of_range_signature_components() {
        // r or s == 0, or >= n, must be rejected up front (standard ECDSA
        // range check). Use r = 0.
        let (_priv, px, py) = generate_host_key_pair();
        let zero = [0u8; 20];
        let some = [0x01u8; 20];
        assert!(
            !ecdsa_verify(&px, &py, &zero, &some, b"d"),
            "r == 0 must be rejected"
        );
        assert!(
            !ecdsa_verify(&px, &py, &some, &zero, b"d"),
            "s == 0 must be rejected"
        );
        // r == n must be rejected (>= n).
        assert!(!ecdsa_verify(&px, &py, &EC_N, &some, b"d"));
    }

    // ── ec_add / ec_double identities ──────────────────────────────────────

    #[test]
    fn ec_add_with_infinity_is_identity() {
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
        let inf = EcPoint::infinity();
        let r1 = ec_add(&g, &inf, &a, &p);
        let r2 = ec_add(&inf, &g, &a, &p);
        assert_eq!((r1.x, r1.y), (g.x.clone(), g.y.clone()));
        assert_eq!((r2.x, r2.y), (g.x, g.y));
    }

    #[test]
    fn ec_add_point_and_its_negation_is_infinity() {
        // P + (-P) = O. -P has y' = p - y. Same x, different y → infinity.
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
        let neg_y = (&p - &g.y) % &p;
        let neg_g = EcPoint::new(g.x.clone(), neg_y);
        let sum = ec_add(&g, &neg_g, &a, &p);
        assert!(sum.infinity, "P + (-P) must be the point at infinity");
    }

    #[test]
    fn ec_mul_two_g_equals_g_plus_g() {
        // 2·G via scalar mul equals ec_double(G) and ec_add(G,G).
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
        let two = BigUint::from(2u32);
        let mul2 = ec_mul(&two, &g, &a, &p);
        let dbl = ec_double(&g, &a, &p);
        let add = ec_add(&g, &g, &a, &p);
        assert_eq!((mul2.x.clone(), mul2.y.clone()), (dbl.x, dbl.y));
        assert_eq!((mul2.x, mul2.y), (add.x, add.y));
    }

    // ── AES-CMAC subkey: K1 doubling with Rb=0x87 ──────────────────────────

    #[test]
    fn aes_cmac_full_block_changes_with_one_input_bit() {
        // A single-bit flip in the message must change the MAC (the K1 XOR +
        // encrypt is sensitive to all input bits). Pairs with the NIST KAT.
        let key = [0x2bu8; 16];
        let m1 = [0x00u8; 16];
        let mut m2 = m1;
        m2[7] ^= 0x01;
        assert_ne!(aes_cmac_16(&m1, &key), aes_cmac_16(&m2, &key));
    }

    // ── verify_cert_p256 boundary at exactly 132 ───────────────────────────

    #[test]
    fn verify_cert_p256_accepts_132_byte_length_without_panic() {
        // 132 bytes is the real cert length; slices are in-bounds, sig won't
        // verify but must NOT panic. Catches regressing the guard to 138.
        let cert = vec![0x00u8; 132];
        assert!(!verify_cert_p256(&cert, &AACS2_LA_PUB_X, &AACS2_LA_PUB_Y));
    }

    // On-curve guard for the LA anchors: both must satisfy y² ≡ x³+ax+b (mod
    // p) and lie in the prime-order subgroup, or `point_on_curve(Q)` rejects
    // every cert they sign. Reverting to the OFF-CURVE value fails this.
    #[test]
    fn la_anchor_keys_are_on_curve() {
        // AACS 1.0 LA key on the 160-bit curve.
        {
            let p = BigUint::from_bytes_be(&EC_P);
            let a = BigUint::from_bytes_be(&EC_A);
            let b = BigUint::from_bytes_be(&EC_B);
            let n = BigUint::from_bytes_be(&EC_N);
            let qx = BigUint::from_bytes_be(&AACS_LA_PUB_X);
            let qy = BigUint::from_bytes_be(&AACS_LA_PUB_Y);
            assert!(
                point_on_curve(&qx, &qy, &a, &b, &p),
                "AACS 1.0 LA public key is not on the curve"
            );
            let q = EcPoint::from_bytes(&AACS_LA_PUB_X, &AACS_LA_PUB_Y);
            assert!(
                ec_mul(&n, &q, &a, &p).infinity,
                "AACS 1.0 LA public key is not in the prime-order subgroup (n·Q != O)"
            );
        }
        // AACS 2.0 LA key on P-256.
        {
            let p = BigUint::from_bytes_be(&P256_P);
            let a = BigUint::from_bytes_be(&P256_A);
            let b = BigUint::from_bytes_be(&P256_B);
            let n = BigUint::from_bytes_be(&P256_N);
            let qx = BigUint::from_bytes_be(&AACS2_LA_PUB_X);
            let qy = BigUint::from_bytes_be(&AACS2_LA_PUB_Y);
            assert!(
                point_on_curve(&qx, &qy, &a, &b, &p),
                "AACS 2.0 LA public key is not on the curve"
            );
            let q = EcPoint::from_bytes(&AACS2_LA_PUB_X, &AACS2_LA_PUB_Y);
            assert!(
                ec_mul(&n, &q, &a, &p).infinity,
                "AACS 2.0 LA public key is not in the prime-order subgroup (n·Q != O)"
            );
        }
    }

    // End-to-end proof the landed AACS 1.0 LA anchor verifies a GENUINE
    // LA-signed cert. Fixture is a real, revoked 92-byte host cert (public
    // key only — safe to embed). Reverting the anchor to OFF-CURVE fails this.
    #[test]
    fn verify_cert_accepts_a_genuine_la_signed_host_cert() {
        // Raw hex of the 92-byte genuine host certificate.
        const CERT_HEX: &str = concat!(
            "0201005cffff80000210000068799afa84876ecf28c10d35",
            "1677898609004e1e17ccda763b16ccab290fde01acb9b8e3",
            "6ef3b58916e1f55b983eeee66ada9eeaa0645f7d7a3eb5ff",
            "3f8afa32184b173b9fc177f398257cdedf2c7617"
        );
        let cert: Vec<u8> = (0..CERT_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&CERT_HEX[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(cert.len(), 92, "fixture must be a full 92-byte cert");
        assert!(
            verify_cert(&cert),
            "the landed AACS 1.0 LA anchor must verify a genuine LA-signed cert"
        );
    }

    // AACS 2.0 (P-256) host-cert handshake — live-path proofs under a
    // self-generated test LA keypair (no genuine 2.0 cert exists to sign
    // with). See docs/aacs-handshake.md for the framing detail.

    /// Build a synthetic 132-byte AACS 2.0 drive certificate carrying
    /// `(pub_x,pub_y)`, signed by the test LA private key over cert[..68]
    /// (SHA-256), with `type_byte` at offset 0.
    fn p256_synth_cert(
        type_byte: u8,
        pub_x: &[u8; 32],
        pub_y: &[u8; 32],
        la_priv: &[u8; 32],
    ) -> Vec<u8> {
        let mut cert = vec![0u8; 132];
        cert[0] = type_byte;
        cert[1] = 0x00; // version
        cert[4..36].copy_from_slice(pub_x);
        cert[36..68].copy_from_slice(pub_y);
        let (r, s) = ecdsa_sign_p256(la_priv, &cert[..68]);
        cert[68..100].copy_from_slice(&r);
        cert[100..132].copy_from_slice(&s);
        cert
    }

    // A validly-signed synthetic 2.0 cert VERIFIES under its test LA anchor,
    // its pubkey extracts, and a matching-key signature round-trips. A
    // one-bit flip in the LA signature makes verification FALSE.
    #[test]
    fn p256_synthetic_la_signed_cert_verifies_and_extracts() {
        let (la_priv, la_x, la_y) = generate_host_key_pair_p256();
        let (drive_priv, drive_x, drive_y) = generate_host_key_pair_p256();
        let cert = p256_synth_cert(0x11, &drive_x, &drive_y, &la_priv);

        // (a) accepted under the LA anchor that signed it.
        assert!(
            verify_cert_p256(&cert, &la_x, &la_y),
            "a genuine LA-signed 2.0 cert must verify"
        );
        // Extracted pub key is the one we embedded.
        let (px, py) = cert_pub_key_p256(&cert);
        assert_eq!(px, drive_x);
        assert_eq!(py, drive_y);
        // The embedded key really signs (drive-key-message shape).
        let msg = b"host_nonce||drive_key_point";
        let (r, s) = ecdsa_sign_p256(&drive_priv, msg);
        assert!(ecdsa_verify_p256(&px, &py, &r, &s, msg));

        // (b) a corrupted LA signature verifies FALSE.
        let mut bad = cert.clone();
        bad[100] ^= 0x01; // flip a sig_s byte
        assert!(
            !verify_cert_p256(&bad, &la_x, &la_y),
            "a bad-signature 2.0 cert must be rejected"
        );
        // …and under the WRONG anchor even the genuine cert is rejected.
        let (_wrong_priv, wx, wy) = generate_host_key_pair_p256();
        assert!(
            !verify_cert_p256(&cert, &wx, &wy),
            "wrong anchor must reject"
        );
    }

    // Plays the DRIVE side of the native AACS 2.0 AKE well enough for
    // `aacs2_authenticate_p256_with_anchor` to complete and derive a bus key,
    // mirroring the 1.0 `DriveEmu` (same bus key on both sides, ECDH symmetric).
    struct DriveEmuP256 {
        lt_priv: [u8; 32],
        eph_priv: [u8; 32],
        eph_x: [u8; 32],
        eph_y: [u8; 32],
        cert: Vec<u8>,
        /// When set, step 6 serves an OFF-CURVE key point (identity-ish) so the
        /// host's `compute_bus_key_p256` invalid-curve guard must reject it.
        off_curve_point: bool,
        /// When set, step 6's key-point signature is corrupted AFTER signing
        /// (so the signed message is genuine but the wire bytes are not) — the
        /// host's `ecdsa_verify_p256` at step 6 must reject it.
        bad_step6_sig: bool,
        host_nonce: [u8; 20],
        bus_key: Option<[u8; 16]>,
    }

    impl DriveEmuP256 {
        /// `cert` must embed the public half of `lt_priv` for the step-6
        /// signature to verify (the accept path); the bad-sig / wrong-type
        /// tests fail at step 5 before step 6, so the match is irrelevant there.
        fn new(lt_priv: [u8; 32], cert: Vec<u8>) -> Self {
            let (eph_priv, eph_x, eph_y) = generate_host_key_pair_p256();
            DriveEmuP256 {
                lt_priv,
                eph_priv,
                eph_x,
                eph_y,
                cert,
                off_curve_point: false,
                bad_step6_sig: false,
                host_nonce: [0u8; 20],
                bus_key: None,
            }
        }
    }

    impl ScsiTransport for DriveEmuP256 {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            let ok = |payload: Vec<u8>, data: &mut [u8]| {
                let n = payload.len().min(data.len());
                data[..n].copy_from_slice(&payload[..n]);
                Ok(crate::scsi::ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0u8; 32],
                })
            };
            match cdb[0] {
                crate::scsi::SCSI_REPORT_KEY => match cdb[10] & 0x3F {
                    0x3F => ok(vec![0u8; 2], data),
                    0x00 => ok(vec![0u8; 8], data),
                    0x01 => {
                        // drive cert + nonce (156 bytes: 4 hdr + 20 nonce + 132 cert)
                        let mut r = vec![0u8; 156];
                        r[4..24].copy_from_slice(&[0x5Au8; 20]); // drive nonce
                        r[24..156].copy_from_slice(&self.cert);
                        ok(r, data)
                    }
                    0x02 => {
                        // drive key point + signature over host_nonce||x||y,
                        // signed by the LONG-TERM cert key.
                        let (mut px, mut py) = (self.eph_x, self.eph_y);
                        if self.off_curve_point {
                            py[31] ^= 0x01; // almost never still on the curve
                        }
                        let mut signed = Vec::with_capacity(84);
                        signed.extend_from_slice(&self.host_nonce);
                        signed.extend_from_slice(&px);
                        signed.extend_from_slice(&py);
                        let (sr, mut ss) = ecdsa_sign_p256(&self.lt_priv, &signed);
                        if self.bad_step6_sig {
                            ss[31] ^= 0xFF; // corrupt the wire signature, not the signed message
                        }
                        let mut r = vec![0u8; 132];
                        r[4..36].copy_from_slice(&px);
                        r[36..68].copy_from_slice(&py);
                        r[68..100].copy_from_slice(&sr);
                        r[100..132].copy_from_slice(&ss);
                        // silence unused-mut when off_curve_point is false
                        let _ = (&mut px, &mut py);
                        ok(r, data)
                    }
                    _ => ok(vec![0u8; 2], data),
                },
                crate::scsi::SCSI_SEND_KEY => {
                    match cdb[10] & 0x3F {
                        0x01 => {
                            // host cert + nonce arrives; capture the host nonce.
                            self.host_nonce.copy_from_slice(&data[4..24]);
                        }
                        0x02 => {
                            // host ephemeral key point arrives; derive the shared
                            // bus key from the drive side (eph_priv × host_point).
                            let mut hx = [0u8; 32];
                            let mut hy = [0u8; 32];
                            hx.copy_from_slice(&data[4..36]);
                            hy.copy_from_slice(&data[36..68]);
                            self.bus_key = compute_bus_key_p256(&self.eph_priv, &hx, &hy);
                        }
                        _ => {}
                    }
                    ok(vec![], data)
                }
                _ => ok(vec![0u8; 2], data),
            }
        }
    }

    /// THE positive live-path proof (a): a validly-signed type-0x11 drive cert
    /// is ACCEPTED and the native P-256 AKE runs to completion, deriving the
    /// SAME bus key on both sides.
    #[test]
    fn p256_ake_accepts_valid_cert_and_derives_bus_key() {
        let (la_priv, la_x, la_y) = generate_host_key_pair_p256();
        let (drive_lt_priv, drive_lt_x, drive_lt_y) = generate_host_key_pair_p256();
        let cert = p256_synth_cert(0x11, &drive_lt_x, &drive_lt_y, &la_priv);
        let (host_priv, host_x, host_y) = generate_host_key_pair_p256();
        // The host cert must embed the host's own public key so the step-7
        // self-verify guard passes (the drive emulator ignores the host cert's
        // signature, so any LA key is fine to sign it).
        let host_cert = p256_synth_cert(0x11, &host_x, &host_y, &la_priv);

        let mut emu = DriveEmuP256::new(drive_lt_priv, cert);
        let auth =
            aacs2_authenticate_p256_with_anchor(&mut emu, &host_priv, &host_cert, &la_x, &la_y)
                .expect("a genuine LA-signed 2.0 cert must complete the AKE");
        assert_ne!(auth.bus_key, [0u8; 16], "a bus key must be derived");
        assert_eq!(
            Some(auth.bus_key),
            emu.bus_key,
            "host and drive must derive the SAME P-256 ECDH bus key"
        );
    }

    // Fatal-verify proof (b): a type-0x11 cert with a corrupt LA signature
    // must ABORT, not log-and-continue. Reverting the `if !verify_cert_p256
    // { return Err }` to the old non-fatal debug! lets this return Ok.
    #[test]
    fn p256_ake_bad_cert_signature_is_fatal() {
        let (la_priv, la_x, la_y) = generate_host_key_pair_p256();
        let (drive_lt_priv, drive_lt_x, drive_lt_y) = generate_host_key_pair_p256();
        let mut cert = p256_synth_cert(0x11, &drive_lt_x, &drive_lt_y, &la_priv);
        cert[120] ^= 0xFF; // corrupt the LA signature (in sig_s)
        let (host_priv, _hx, _hy) = generate_host_key_pair_p256();

        let mut emu = DriveEmuP256::new(drive_lt_priv, cert);
        let err =
            aacs2_authenticate_p256_with_anchor(&mut emu, &host_priv, &[0x11u8; 132], &la_x, &la_y)
                .expect_err("a bad-signature cert must abort, never proceed");
        assert!(
            matches!(err, Error::AacsCertVerify),
            "rejection must fire at the cert-verify gate (AacsCertVerify); got {err:?}"
        );
    }

    // Type-gate proof (c): a cert type byte != 0x11 must be REJECTED even
    // with an otherwise-valid LA signature. Removing the `!= 0x11` gate lets
    // it reach step 6 and derive an attacker-choosable bus key.
    #[test]
    fn p256_ake_unknown_cert_type_is_rejected() {
        let (la_priv, la_x, la_y) = generate_host_key_pair_p256();
        let (drive_lt_priv, drive_lt_x, drive_lt_y) = generate_host_key_pair_p256();
        // Type 0x10, but a genuinely LA-signed cert (so only the TYPE is wrong).
        let cert = p256_synth_cert(0x10, &drive_lt_x, &drive_lt_y, &la_priv);
        let (host_priv, _hx, _hy) = generate_host_key_pair_p256();

        let mut emu = DriveEmuP256::new(drive_lt_priv, cert);
        let err =
            aacs2_authenticate_p256_with_anchor(&mut emu, &host_priv, &[0x11u8; 132], &la_x, &la_y)
                .expect_err("an unexpected cert type must be rejected before any key is trusted");
        assert!(
            matches!(err, Error::AacsCertVerify),
            "rejection must fire at the cert-type gate (AacsCertVerify); got {err:?}"
        );
    }

    // Off-curve proof (d), AKE level: a valid cert followed by an OFF-CURVE
    // drive key point at step 6 must abort at bus-key derivation
    // (`compute_bus_key_p256`'s invalid-curve guard), not multiply onto a weak curve.
    #[test]
    fn p256_ake_off_curve_drive_point_is_rejected() {
        let (la_priv, la_x, la_y) = generate_host_key_pair_p256();
        let (drive_lt_priv, drive_lt_x, drive_lt_y) = generate_host_key_pair_p256();
        let cert = p256_synth_cert(0x11, &drive_lt_x, &drive_lt_y, &la_priv);
        let (host_priv, host_x, host_y) = generate_host_key_pair_p256();
        // Host cert embeds the host pubkey so the step-7 self-verify guard
        // passes and the AKE reaches the step-9 off-curve rejection under test.
        let host_cert = p256_synth_cert(0x11, &host_x, &host_y, &la_priv);

        let mut emu = DriveEmuP256::new(drive_lt_priv, cert);
        emu.off_curve_point = true;
        let err =
            aacs2_authenticate_p256_with_anchor(&mut emu, &host_priv, &host_cert, &la_x, &la_y)
                .expect_err("an off-curve drive key point must abort the ECDH");
        assert!(
            matches!(err, Error::AacsKeyVerify),
            "off-curve point must be rejected at bus-key derivation; got {err:?}"
        );
    }

    // ECDSA-P256 pubkey validation proof, primitive level: Q=(0,0) collapses
    // `u2·Q` and forges a signature with NO private key. `point_on_curve(Q)`
    // stops it; the forged (r, s=1) below VERIFIES if that guard is absent.
    #[test]
    fn ecdsa_verify_p256_rejects_identity_key_forgery() {
        let p = BigUint::from_bytes_be(&P256_P);
        let a = BigUint::from_bytes_be(&P256_A);
        let n = BigUint::from_bytes_be(&P256_N);
        let g = EcPoint::from_bytes(&P256_GX, &P256_GY);
        use sha2::{Digest as _, Sha256};

        // Find data whose forged r (= x(u1·G) mod n, u1 = z with s=1) is EVEN, so
        // that this impl's u2·(0,0) reduces to the point at infinity and the
        // check collapses to r == x(z·G) — the exact identity-key forgery.
        let (data, r) = (0u32..100_000)
            .find_map(|ctr| {
                let d = ctr.to_le_bytes();
                let z = BigUint::from_bytes_be(&Sha256::digest(d));
                let u1 = &z % &n;
                let rr = ec_mul(&u1, &g, &a, &p).x % &n;
                (!rr.is_zero() && !rr.bit(0)).then(|| (d.to_vec(), rr))
            })
            .expect("an even forged r exists within the search bound");
        let sig_r: [u8; 32] = to_bytes_be_padded(&r, 32).try_into().unwrap();
        let mut sig_s = [0u8; 32];
        sig_s[31] = 1; // s = 1

        // Q = the identity point (0,0): with the guard it is rejected outright.
        let zero = [0u8; 32];
        assert!(
            !ecdsa_verify_p256(&zero, &zero, &sig_r, &sig_s, &data),
            "identity-key forgery must be rejected by point_on_curve(Q)"
        );

        // An off-curve Q (a real key with y flipped) is likewise rejected.
        let (_priv, mut ox, oy) = generate_host_key_pair_p256();
        ox[31] ^= 0x01;
        assert!(
            !ecdsa_verify_p256(&ox, &oy, &sig_r, &sig_s, &data),
            "off-curve Q must be rejected"
        );
    }

    // SANITY: `ecdsa_verify_p256` + P-256 constants + SHA-256 verify against
    // GENUINE AACS 2.0 material (a real Content Cert, since no AKE cert
    // exists locally). See docs/aacs-handshake.md for the full rationale.
    #[test]
    fn ecdsa_verify_p256_verifies_a_genuine_aacs2_content_cert() {
        fn hx(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        // The published AACS 2.0 Content Certificate public key (P-256).
        let cc_x: [u8; 32] = hx("E70D49D26F45EAA736939D72882ED8FBA1607026963949970496C910EA5C9DC2")
            .try_into()
            .unwrap();
        let cc_y: [u8; 32] = hx("D1F5897CECB844014E0FB08CC76E20E8545ECC271EE46C4AEF81D9169BF84172")
            .try_into()
            .unwrap();
        // The signed region (first 168 bytes of CivilWar/Content000.cer) and the
        // 64-byte trailing signature (r‖s).
        let signed = hx(
            "108000069300030000022e5400010728800bab0300000000008600000000000000000000000000000000000000000000000000000000000000000000fb8a18a7d858edd8055017446a0e9b050e9967d612518662f4fd181cf5634951000000000000000000000000000000000000000000000000000000000000000000000001d582de9f77bd30467c56ea69e64f22859dccff826f47c0fdc69a4d1db107b6351248ba32d4c73d2e",
        );
        assert_eq!(signed.len(), 168, "signed region must be 168 bytes");
        let sig_r = hx("dd4952997dbc3948f094ed79d85db91c018fb141da4988e99db1645f68b0b1a7");
        let sig_s = hx("cb4fa07f25b6fe35685adecac25bfc9a1f1614325c2764fc14ae5984b7f65be9");
        assert!(
            ecdsa_verify_p256(&cc_x, &cc_y, &sig_r, &sig_s, &signed),
            "the P-256/SHA-256 primitive must verify a genuine AACS 2.0 content cert"
        );
        // Negative control: one flipped byte in the signed region breaks it.
        let mut tampered = signed.clone();
        tampered[0] ^= 0x01;
        assert!(
            !ecdsa_verify_p256(&cc_x, &cc_y, &sig_r, &sig_s, &tampered),
            "a tampered signed region must not verify"
        );
    }

    // ── Round-2 coverage: EC math edge cases ── `mod_inv` returns `None`
    // when `gcd(a, m) != 1`; called directly with a non-coprime pair since
    // production always passes a prime curve modulus.
    #[test]
    fn mod_inv_returns_none_for_non_coprime_inputs() {
        let a = BigUint::from(4u32);
        let m = BigUint::from(8u32); // gcd(4, 8) = 4, no inverse exists
        assert!(mod_inv(&a, &m).is_none());
    }

    // `ec_add`'s `dx_inv` guard: a non-invertible x-difference must yield
    // infinity, not panic or a bogus point. Only reachable with a non-prime
    // modulus (real curves here use prime `p`) — a direct exercise of it.
    #[test]
    fn ec_add_returns_infinity_when_dx_not_invertible() {
        let a = BigUint::from(1u32);
        let p = BigUint::from(8u32); // composite modulus
        let p1 = EcPoint::new(BigUint::from(0u32), BigUint::from(1u32));
        let p2 = EcPoint::new(BigUint::from(4u32), BigUint::from(3u32)); // dx = 4, gcd(4,8)=4
        let r = ec_add(&p1, &p2, &a, &p);
        assert!(
            r.infinity,
            "a non-invertible dx must yield infinity, not a bogus point"
        );
    }

    /// `ec_double`'s `denom_inv` guard: same shape as above, for the
    /// doubling denominator `2y`.
    #[test]
    fn ec_double_returns_infinity_when_denominator_not_invertible() {
        let a = BigUint::from(1u32);
        let p = BigUint::from(8u32); // composite modulus
        let pt = EcPoint::new(BigUint::from(1u32), BigUint::from(4u32)); // 2y = 8, gcd(8,8)=8
        let r = ec_double(&pt, &a, &p);
        assert!(
            r.infinity,
            "a non-invertible denominator must yield infinity"
        );
    }

    /// `ec_mul` with a zero scalar is the point at infinity by definition —
    /// the double-and-add loop must short-circuit rather than run.
    #[test]
    fn ec_mul_zero_scalar_returns_infinity() {
        let a = BigUint::from_bytes_be(&EC_A);
        let p = BigUint::from_bytes_be(&EC_P);
        let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
        let r = ec_mul(&BigUint::zero(), &g, &a, &p);
        assert!(r.infinity);
    }

    // `ecdsa_verify` (AACS 1.0) rejects an off-curve public key up front,
    // the same invalid-curve defence the P-256 primitive has its own test
    // for, but the 1.0 primitive had none.
    #[test]
    fn ecdsa_verify_rejects_off_curve_public_key() {
        let (priv_key, px, py) = generate_host_key_pair();
        let (r, s) = ecdsa_sign(&priv_key, b"payload");
        // A genuinely off-curve point: flip a low byte of py.
        let mut bad_py = py;
        bad_py[19] ^= 0x01;
        assert!(
            !ecdsa_verify(&px, &bad_py, &r, &s, b"payload"),
            "an off-curve public key must be rejected before any range/pairing check"
        );
    }

    // ── Round-2 coverage: Debug redaction ───────────────────────────────────

    /// `AacsAuth`'s hand-written `Debug` must redact `bus_key` / `volume_id` /
    /// `read_data_key` (key material) while still showing whether each is
    /// present, and must NOT panic on a populated instance.
    #[test]
    fn aacs_auth_debug_redacts_key_material() {
        let auth = AacsAuth {
            bus_key: [0x11u8; 16],
            agid: 2,
            volume_id: Some([0x22u8; 16]),
            read_data_key: Some([0x33u8; 16]),
        };
        let s = format!("{auth:?}");
        assert!(
            s.contains("[redacted]"),
            "key material must be redacted: {s}"
        );
        assert!(!s.contains("17"), "no raw key byte (0x11=17) may leak: {s}");
        assert!(
            s.contains("agid"),
            "non-secret fields must still print: {s}"
        );
    }

    /// `CertHandshake`'s hand-written `Debug` likewise redacts `read_data_key`
    /// and `volume_id`, and does not panic on `None`.
    #[test]
    fn cert_handshake_debug_redacts_key_material() {
        let ch = CertHandshake {
            volume_id: [0x44u8; 16],
            read_data_key: Some([0x55u8; 16]),
            read_data_key_err: None,
        };
        let s = format!("{ch:?}");
        assert!(
            s.contains("[redacted]"),
            "key material must be redacted: {s}"
        );

        let ch_none = CertHandshake {
            volume_id: [0u8; 16],
            read_data_key: None,
            read_data_key_err: Some(7006),
        };
        let s2 = format!("{ch_none:?}");
        assert!(s2.contains("[redacted]"));
    }

    // ── Round-2 coverage: AACS 1.0 cert-verify gate ─────────────────────────

    /// `aacs_authenticate` rejects a host cert shorter than 92 bytes before
    /// issuing a single SCSI command.
    #[test]
    fn aacs_authenticate_v1_rejects_short_host_cert() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let priv_key = [0u8; 20];
        let err = aacs_authenticate(&mut t, &priv_key, &[0u8; 91])
            .expect_err("a 91-byte cert is too short");
        assert!(matches!(err, Error::AacsCertShort));
        assert_eq!(t.calls(), 0, "must reject before touching the transport");
    }

    // A type-0x01 drive cert with a bad LA signature must be rejected at the
    // cert-verify gate (`AacsCertVerify` via `verify_cert`) — the type-0x01
    // sibling of the type-0x11/0x02 gate tests, exercising a different branch.
    #[test]
    fn aacs_authenticate_v1_type01_bad_signature_is_rejected() {
        let mut cert_resp = vec![0u8; 116];
        cert_resp[24] = 0x01; // type 0x01, but the rest is all zeros: sig r=s=0
        let script = vec![
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 2]),
            Reply::good(vec![0u8; 8]), // AGID alloc
            Reply::good(vec![]),       // SEND KEY host cert
            Reply::good(cert_resp),    // REPORT KEY drive cert (type 0x01, unsigned)
        ];
        let mut t = MockTransport::scripted(script, Reply::good(vec![0u8; 2]));
        let hc = dummy_cert();
        let err = aacs_authenticate(&mut t, &hc.private_key, &hc.certificate)
            .expect_err("an unsigned type-0x01 cert must fail LA verification");
        assert!(matches!(err, Error::AacsCertVerify));
    }

    // ── Round-2 coverage: AACS 2.0 (P-256) wiring ── the native AKE entry
    // must forward a dead bus on the first step unchanged (so the orchestrator
    // can classify it as a transport abort rather than a cert rejection).
    #[test]
    fn aacs2_authenticate_p256_wrapper_propagates_transport_fault() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let (host_priv, _hx, _hy) = generate_host_key_pair_p256();
        let err = aacs2_authenticate_p256_with_anchor(
            &mut t,
            &host_priv,
            &[0x11u8; 132],
            &AACS2_LA_PUB_X,
            &AACS2_LA_PUB_Y,
        )
        .expect_err("dead bus");
        assert!(err.is_scsi_transport_failure());
    }

    // Fix 3: the production P-256 (AACS 2.0) path is gated OFF while its cert
    // offsets are provisional, so it can't silently mis-verify a real disc.
    // Pin the gate constant; flipping it on requires a captured 2.0 test vector.
    #[test]
    fn aacs2_p256_is_experimental_and_disabled_in_production() {
        // black_box so clippy doesn't fold the const into a constant assertion:
        // this is a deliberate regression guard on the production default.
        let enabled = std::hint::black_box(AACS2_P256_EXPERIMENTAL);
        assert!(
            !enabled,
            "the native AACS 2.0 P-256 path must stay disabled until a captured \
             cert vector confirms the provisional offsets"
        );
    }

    /// `aacs2_authenticate_p256_with_anchor` rejects a host cert shorter than
    /// 132 bytes before issuing a single SCSI command.
    #[test]
    fn aacs2_authenticate_p256_with_anchor_rejects_short_host_cert() {
        let mut t = MockTransport::always(Reply::TransportFault);
        let (host_priv, _hx, _hy) = generate_host_key_pair_p256();
        let (_la_priv, la_x, la_y) = generate_host_key_pair_p256();
        let err =
            aacs2_authenticate_p256_with_anchor(&mut t, &host_priv, &[0u8; 131], &la_x, &la_y)
                .expect_err("a 131-byte cert is too short");
        assert!(matches!(err, Error::AacsCertShort));
        assert_eq!(t.calls(), 0, "must reject before touching the transport");
    }

    // Step-6 signature proof, P-256 AKE: a valid cert but a corrupted
    // drive key-point signature at step 6 must abort at `ecdsa_verify_p256`
    // (`AacsKeyVerify`) — distinct from the cert-verify and off-curve tests.
    #[test]
    fn p256_ake_bad_step6_signature_is_rejected() {
        let (la_priv, la_x, la_y) = generate_host_key_pair_p256();
        let (drive_lt_priv, drive_lt_x, drive_lt_y) = generate_host_key_pair_p256();
        let cert = p256_synth_cert(0x11, &drive_lt_x, &drive_lt_y, &la_priv);
        let (host_priv, _hx, _hy) = generate_host_key_pair_p256();

        let mut emu = DriveEmuP256::new(drive_lt_priv, cert);
        emu.bad_step6_sig = true;
        let err =
            aacs2_authenticate_p256_with_anchor(&mut emu, &host_priv, &[0x11u8; 132], &la_x, &la_y)
                .expect_err("a corrupted step-6 signature must abort the AKE");
        assert!(
            matches!(err, Error::AacsKeyVerify),
            "rejection must fire at the step-6 signature check; got {err:?}"
        );
    }

    // ── Round-2 coverage: run_cert_handshake full success ── auth, VID read,
    // AND read-data-keys all succeed here; every other test above stops
    // short — this is the only one reaching the final `Ok(CertHandshake)`.
    #[test]
    fn run_cert_handshake_succeeds_end_to_end() {
        let mut t = DriveEmu::new();
        t.serve_data_keys = true;
        let ch = run_handshake_v1(&mut t, &[dummy_cert()])
            .expect("auth + VID + data-key reads all succeed");
        assert_eq!(ch.volume_id, [0x5Au8; 16]);
        assert!(
            ch.read_data_key.is_some(),
            "a served data-key block must decrypt"
        );
        assert!(ch.read_data_key_err.is_none());

        // Fix 4: the AGID must be released on the fully-SUCCESSFUL path too (it
        // used to leak, slowly draining the drive's 4-AGID pool across discs).
        // The last CDB is a REPORT KEY (0xA4) with format 0x3F in byte 10.
        let last = t.cdbs.last().expect("commands were issued");
        assert_eq!(last[0], crate::scsi::SCSI_REPORT_KEY);
        assert_eq!(
            last[10] & 0x3F,
            0x3F,
            "AGID must be released after the final data-key read"
        );
    }

    // Plays a backward-compat 2.0 drive that ALSO speaks the AACS 1.0 AKE: it
    // completes the 1.0 handshake (genuine type-0x01 cert, signed step 6) but its
    // 1.0-derived bus key CANNOT authenticate the VID (bad MAC), then serves a
    // full native P-256 (AACS 2.0) AKE. Phase is keyed off the SCSI payload
    // length (v1 = 116/84, v2 = 156/132). Proves fix 2: a post-auth 1.0 VID/MAC
    // failure with v2 creds present falls through to the P-256 path.
    struct HybridDrive {
        // AACS 1.0 material.
        la1_x: [u8; 20],
        la1_y: [u8; 20],
        lt1_priv: [u8; 20],
        cert1: Vec<u8>,
        eph1_priv: [u8; 20],
        eph1_x: [u8; 20],
        eph1_y: [u8; 20],
        host_nonce1: [u8; 20],
        bus1: Option<[u8; 16]>,
        // AACS 2.0 (P-256) material.
        la2_x: [u8; 32],
        la2_y: [u8; 32],
        lt2_priv: [u8; 32],
        cert2: Vec<u8>,
        eph2_priv: [u8; 32],
        eph2_x: [u8; 32],
        eph2_y: [u8; 32],
        host_nonce2: [u8; 20],
        bus2: Option<[u8; 16]>,
        drive_nonce: [u8; 20],
        vid: [u8; 16],
        /// Set once the host begins the native P-256 AKE (a 156-byte host cert
        /// send arrives) — the assertion that the fallback was actually reached.
        reached_p256: bool,
    }

    impl HybridDrive {
        fn new() -> Self {
            let (la1_priv, la1_x, la1_y) = generate_host_key_pair();
            let (lt1_priv, lt1_x, lt1_y) = generate_host_key_pair();
            let (eph1_priv, eph1_x, eph1_y) = generate_host_key_pair();
            let cert1 = v1_synth_cert(0x01, &lt1_x, &lt1_y, &la1_priv);

            let (la2_priv, la2_x, la2_y) = generate_host_key_pair_p256();
            let (lt2_priv, lt2_x, lt2_y) = generate_host_key_pair_p256();
            let (eph2_priv, eph2_x, eph2_y) = generate_host_key_pair_p256();
            let cert2 = p256_synth_cert(0x11, &lt2_x, &lt2_y, &la2_priv);

            let mut drive_nonce = [0u8; 20];
            use rand::Rng;
            rand::rng().fill_bytes(&mut drive_nonce);
            HybridDrive {
                la1_x,
                la1_y,
                lt1_priv,
                cert1,
                eph1_priv,
                eph1_x,
                eph1_y,
                host_nonce1: [0u8; 20],
                bus1: None,
                la2_x,
                la2_y,
                lt2_priv,
                cert2,
                eph2_priv,
                eph2_x,
                eph2_y,
                host_nonce2: [0u8; 20],
                bus2: None,
                drive_nonce,
                vid: [0x5Au8; 16],
                reached_p256: false,
            }
        }
    }

    impl ScsiTransport for HybridDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            let ok = |payload: Vec<u8>, data: &mut [u8]| {
                let n = payload.len().min(data.len());
                data[..n].copy_from_slice(&payload[..n]);
                Ok(crate::scsi::ScsiResult {
                    status: 0,
                    bytes_transferred: n,
                    sense: [0u8; 32],
                })
            };
            let len = ((cdb[8] as usize) << 8) | cdb[9] as usize;
            match cdb[0] {
                crate::scsi::SCSI_REPORT_KEY => match cdb[10] & 0x3F {
                    0x3F => ok(vec![0u8; 2], data),
                    0x00 => ok(vec![0u8; 8], data),
                    0x01 if len >= 156 => {
                        // v2 drive cert (156): 4 hdr + 20 nonce + 132 cert.
                        let mut r = vec![0u8; 156];
                        r[4..24].copy_from_slice(&self.drive_nonce);
                        r[24..156].copy_from_slice(&self.cert2);
                        ok(r, data)
                    }
                    0x01 => {
                        // v1 drive cert (116).
                        let mut r = vec![0u8; 116];
                        r[4..24].copy_from_slice(&self.drive_nonce);
                        r[24..116].copy_from_slice(&self.cert1);
                        ok(r, data)
                    }
                    0x02 if len >= 132 => {
                        // v2 drive key point + P-256 signature by lt2.
                        let mut signed = Vec::with_capacity(84);
                        signed.extend_from_slice(&self.host_nonce2);
                        signed.extend_from_slice(&self.eph2_x);
                        signed.extend_from_slice(&self.eph2_y);
                        let (sr, ss) = ecdsa_sign_p256(&self.lt2_priv, &signed);
                        let mut r = vec![0u8; 132];
                        r[4..36].copy_from_slice(&self.eph2_x);
                        r[36..68].copy_from_slice(&self.eph2_y);
                        r[68..100].copy_from_slice(&sr);
                        r[100..132].copy_from_slice(&ss);
                        ok(r, data)
                    }
                    0x02 => {
                        // v1 drive key point + signature by lt1.
                        let mut signed = [0u8; 60];
                        signed[..20].copy_from_slice(&self.host_nonce1);
                        signed[20..40].copy_from_slice(&self.eph1_x);
                        signed[40..60].copy_from_slice(&self.eph1_y);
                        let (sr, ss) = ecdsa_sign(&self.lt1_priv, &signed);
                        let mut r = vec![0u8; 84];
                        r[4..24].copy_from_slice(&self.eph1_x);
                        r[24..44].copy_from_slice(&self.eph1_y);
                        r[44..64].copy_from_slice(&sr);
                        r[64..84].copy_from_slice(&ss);
                        ok(r, data)
                    }
                    _ => ok(vec![0u8; 2], data),
                },
                crate::scsi::SCSI_SEND_KEY => {
                    match cdb[10] & 0x3F {
                        0x01 if len >= 156 => {
                            self.reached_p256 = true;
                            self.host_nonce2.copy_from_slice(&data[4..24]);
                        }
                        0x01 => self.host_nonce1.copy_from_slice(&data[4..24]),
                        0x02 if len >= 132 => {
                            let mut hx = [0u8; 32];
                            let mut hy = [0u8; 32];
                            hx.copy_from_slice(&data[4..36]);
                            hy.copy_from_slice(&data[36..68]);
                            self.bus2 = compute_bus_key_p256(&self.eph2_priv, &hx, &hy);
                        }
                        0x02 => {
                            let mut hx = [0u8; 20];
                            let mut hy = [0u8; 20];
                            hx.copy_from_slice(&data[4..24]);
                            hy.copy_from_slice(&data[24..44]);
                            self.bus1 = compute_bus_key(&self.eph1_priv, &hx, &hy);
                        }
                        _ => {}
                    }
                    ok(vec![], data)
                }
                crate::scsi::SCSI_READ_DISC_STRUCTURE => match cdb[7] {
                    0x80 => {
                        // v2 VID authenticates (good MAC under bus2); the v1 VID
                        // does NOT (corrupted MAC under bus1) → the fallback.
                        let (bus, good) = match self.bus2 {
                            Some(b) => (b, true),
                            None => (self.bus1.expect("v1 bus key derived"), false),
                        };
                        let mut mac = aes_cmac_16(&self.vid, &bus);
                        if !good {
                            mac[0] ^= 0xFF;
                        }
                        let mut r = vec![0u8; 36];
                        r[4..20].copy_from_slice(&self.vid);
                        r[20..36].copy_from_slice(&mac);
                        ok(r, data)
                    }
                    _ => {
                        let mut r = vec![0u8; 36];
                        r[4..20].copy_from_slice(&[0x7Bu8; 16]);
                        r[20..36].copy_from_slice(&[0x7Cu8; 16]);
                        ok(r, data)
                    }
                },
                _ => ok(vec![0u8; 2], data),
            }
        }
    }

    // Fix 2: a backward-compat 2.0 drive completes the AACS 1.0 AKE but its
    // 1.0 VID MAC fails; with v2 creds present, the handshake must fall through
    // to the native P-256 AKE (not terminate with VidUnavailable) and complete.
    #[test]
    fn vid_mac_failure_on_the_1_0_path_falls_through_to_p256() {
        let mut drive = HybridDrive::new();
        let (l1x, l1y) = (drive.la1_x, drive.la1_y);
        let (l2x, l2y) = (drive.la2_x, drive.la2_y);

        // Host cert: a self-consistent v1 pair PLUS v2 creds (a 0x11 host cert
        // embedding the host's own P-256 pubkey so the step-7 self-verify passes;
        // its LA signer is irrelevant — neither side checks the host cert sig).
        let v1 = dummy_cert();
        let (hv2_priv, hv2_x, hv2_y) = generate_host_key_pair_p256();
        let (throwaway_la, _, _) = generate_host_key_pair_p256();
        let host_cert = crate::HostCert {
            private_key: v1.private_key,
            certificate: v1.certificate.clone(),
            private_key_v2: Some(hv2_priv),
            certificate_v2: Some(p256_synth_cert(0x11, &hv2_x, &hv2_y, &throwaway_la)),
        };

        let ch = run_cert_handshake_with_anchors(
            &mut drive,
            std::slice::from_ref(&host_cert),
            (&l1x, &l1y),
            (&l2x, &l2y),
            true, // P-256 enabled (the test seam; production keeps it gated)
        )
        .expect("the 1.0 VID MAC fails, so the native P-256 AKE must complete");
        assert_eq!(ch.volume_id, [0x5Au8; 16], "the P-256 VID must be returned");
        assert!(
            ch.read_data_key.is_some(),
            "the P-256 path served a bus key"
        );
        assert!(
            drive.reached_p256,
            "the native P-256 AKE must have been reached after the 1.0 VID MAC failure"
        );
    }

    // SLOT for a REAL AACS 2.0 host certificate (a side agent is sourcing
    // one): when it lands, drop the fixture + real LA anchor here and remove
    // `#[ignore]`. Until then this documents the missing fixture without failing CI.
    #[test]
    #[ignore = "pending a genuine AACS 2.0 host/drive certificate fixture"]
    fn real_aacs2_cert_verifies_under_the_published_la_anchor() {
        // const REAL_2_0_DRIVE_CERT_HEX: &str = "…132 bytes…";
        // let cert = hex_to_bytes(REAL_2_0_DRIVE_CERT_HEX);
        // assert!(verify_cert_p256(&cert, &AACS2_LA_PUB_X, &AACS2_LA_PUB_Y));
        unimplemented!("drop a genuine 2.0 cert fixture here");
    }

    // ── Host-signing self-verify: the class of bug the priv·G check exposes ──
    // Targets the AKE host-signing surface (step 7). Pre-existing tests
    // round-trip a FRESH keypair (self-consistent), so can't catch a mispairing.

    /// A helper that returns `(priv·G).x‖.y` as the AACS-1.0 20-byte pair, so
    /// tests can assert the base-point plumbing (`ec_mul` over `EC_G`) against
    /// an independently-extracted cert public key. Cross-checks libaacs, which
    /// derives the host public key the same way (`crypto_create_host_key_pair`).
    fn priv_times_g_v1(priv_key: &[u8; 20]) -> ([u8; 20], [u8; 20]) {
        let p = BigUint::from_bytes_be(&EC_P);
        let a = BigUint::from_bytes_be(&EC_A);
        let g = EcPoint::from_bytes(&EC_GX, &EC_GY);
        let d = BigUint::from_bytes_be(priv_key);
        let q = ec_mul(&d, &g, &a, &p);
        let mut x = [0u8; 20];
        let mut y = [0u8; 20];
        x.copy_from_slice(&to_bytes_be_padded(&q.x, 20));
        y.copy_from_slice(&to_bytes_be_padded(&q.y, 20));
        (x, y)
    }

    /// For an internally-consistent host cert (`dummy_cert`), `priv·G` MUST
    /// equal the public key extracted at the AACS-1.0 offsets 12/32 — the exact
    /// check that separates "cert_pub_key offset wrong / wrong base point" from
    /// "signing algorithm wrong". Synthetic twin of the real-cert check in
    /// `real_host_certs_priv_times_g_and_self_verify`.
    #[test]
    fn priv_times_g_equals_cert_pub_key_for_a_consistent_cert() {
        let hc = dummy_cert();
        let priv_key = hc.private_key;
        let (qx, qy) = priv_times_g_v1(&priv_key);
        let (cx, cy) = cert_pub_key(&hc.certificate);
        assert_eq!(qx, cx, "priv·G x must equal cert pub_x at offset 12");
        assert_eq!(qy, cy, "priv·G y must equal cert pub_y at offset 32");
    }

    /// The FIX-TARGET property in primitive form: a signature made with a host
    /// cert's private key MUST verify against the SAME cert's public key over
    /// arbitrary 60-byte step-7 data — the exact "sign with cert priv, verify
    /// with cert_pub_key(cert)" path that hardware exercises.
    #[test]
    fn ecdsa_sign_self_verifies_against_own_cert_pubkey_60_bytes() {
        let hc = dummy_cert();
        let (cx, cy) = cert_pub_key(&hc.certificate);
        let data = [0xA5u8; 60];
        let (r, s) = ecdsa_sign(&hc.private_key, &data);
        assert!(
            ecdsa_verify(&cx, &cy, &r, &s, &data),
            "a signature by the cert's private key must self-verify against its pubkey"
        );
    }

    /// The REPRODUCTION (no hardware, no secrets): a signature by a private key
    /// that does NOT match the certificate's public key fails to self-verify —
    /// exactly the `ffff80000210` mispaired-keydb failure mode, which the step-7
    /// guard turns into a precise host-side error.
    #[test]
    fn ecdsa_sign_fails_to_self_verify_against_a_mismatched_cert_pubkey() {
        let hc = mispaired_host_cert();
        let (cx, cy) = cert_pub_key(&hc.certificate);
        let data = [0xA5u8; 60];
        let (r, s) = ecdsa_sign(&hc.private_key, &data);
        assert!(
            !ecdsa_verify(&cx, &cy, &r, &s, &data),
            "a signature by a mismatched private key must NOT verify against the cert pubkey"
        );
        // …and priv·G must NOT equal the cert's public key, either.
        let (qx, qy) = priv_times_g_v1(&hc.private_key);
        assert!(
            qx != cx || qy != cy,
            "a mispaired cert must have priv·G != cert pubkey"
        );
    }

    /// The step-7 self-verify GUARD, end-to-end over the 1.0 AKE: a mispaired
    /// host cert must abort with `AacsHostSignVerify` at step 7 — BEFORE the
    /// doomed signature is ever sent to the drive (SEND KEY format 0x02).
    #[test]
    fn host_sign_guard_rejects_a_mispaired_host_cert() {
        let mut emu = DriveEmu::new();
        let (lax, lay) = (emu.la_x, emu.la_y);
        let hc = mispaired_host_cert();
        let err =
            aacs_authenticate_with_anchor(&mut emu, &hc.private_key, &hc.certificate, &lax, &lay)
                .expect_err("a mispaired host cert must be rejected at the self-verify guard");
        assert!(
            matches!(err, Error::AacsHostSignVerify),
            "must fail at the step-7 self-verify guard; got {err:?}"
        );
        // The guard fires BEFORE step 8, so the drive never saw a key point:
        // the bus key was never derived on the drive side.
        assert!(
            emu.host_sig_ok.is_none() || emu.host_sig_ok == Some(false),
            "the doomed signature must not have been shipped"
        );
    }

    // ── Cert-selection fallback: skip dead pairings, roll down to a valid one ──

    /// Given `[mispaired, valid]`, the unlocker gates the mispaired cert out
    /// HOST-SIDE (its priv·G != cert pubkey) with no drive round-trip, then
    /// authenticates with the valid one. The mispaired cert must never have
    /// been shipped at SEND KEY format 0x01.
    #[test]
    fn fallback_skips_locally_mispaired_cert_and_auths_with_the_next_valid_one() {
        let mut emu = DriveEmu::new();
        emu.serve_data_keys = true;
        let good = dummy_cert();
        let certs = vec![mispaired_host_cert(), good.clone()];
        let ch = run_handshake_v1(&mut emu, &certs)
            .expect("the mispaired cert is skipped locally; the valid one authenticates");
        assert_eq!(ch.volume_id, [0x5Au8; 16]);
        assert!(ch.read_data_key.is_some());
        assert_eq!(
            emu.certs_sent.len(),
            1,
            "only the VALID cert may reach the drive; the mispaired one is gated out"
        );
        assert_eq!(&emu.certs_sent[0][..], &good.certificate[..92]);
    }

    /// Given `[valid_revoked_by_drive, valid_accepted]` where BOTH pass the
    /// host-side keypair gate, a drive-side 6F/00 (copy-protection key-exchange
    /// failure — the HRL-revocation shape) on the first cert-send must roll
    /// through to the second cert, which authenticates. Both certs are shipped:
    /// revocation is only discoverable via a drive round-trip.
    #[test]
    fn fallback_rolls_past_a_drive_revoked_cert_to_the_next_accepted_one() {
        let mut emu = DriveEmu::new();
        emu.serve_data_keys = true;
        emu.revoke_cert_sends = 1;
        let first = dummy_cert();
        let second = dummy_cert();
        assert!(aacs1_keypair_matches(
            &first.private_key,
            &first.certificate
        ));
        assert!(aacs1_keypair_matches(
            &second.private_key,
            &second.certificate
        ));
        let ch = run_handshake_v1(&mut emu, &[first.clone(), second.clone()])
            .expect("roll past the revoked cert and authenticate with the next");
        assert_eq!(ch.volume_id, [0x5Au8; 16]);
        assert_eq!(
            emu.certs_sent.len(),
            2,
            "the revoked cert IS shipped (a round-trip reveals revocation), then the next"
        );
        assert_eq!(&emu.certs_sent[0][..], &first.certificate[..92]);
        assert_eq!(&emu.certs_sent[1][..], &second.certificate[..92]);
    }

    /// A LONE mispaired cert must fail cleanly WITHOUT any drive round-trip —
    /// the host-side gate fires before a single CDB is issued. Because no cert
    /// ever reached the drive, the outcome is `NoUsableHostCert` (a keydb/
    /// host-cert problem), not the `HandshakeRejected` a drive would have to
    /// issue. Uses the mock transport so a wasted SEND KEY 0x01 would be caught.
    #[test]
    fn only_a_mispaired_cert_fails_without_any_drive_round_trip() {
        let mut t = MockTransport::always(Reply::illegal_request());
        let err = run_cert_handshake(&mut t, &[mispaired_host_cert()])
            .expect_err("a lone mispaired cert cannot authenticate");
        assert!(matches!(err, crate::UnlockError::NoUsableHostCert));
        assert_eq!(
            t.calls(),
            0,
            "no SCSI command may be issued for a locally-dead pairing"
        );
        assert!(
            t.cdbs.iter().all(|c| c[0] != crate::scsi::SCSI_SEND_KEY),
            "no SEND KEY cert-send round-trip for a locally-dead cert"
        );
    }

    /// The single-valid-cert happy path is unchanged: exactly one cert is
    /// shipped to the drive and the handshake succeeds (the up-front gate must
    /// not skip a genuinely-valid cert).
    #[test]
    fn single_valid_cert_still_ships_exactly_one_cert_and_succeeds() {
        let mut emu = DriveEmu::new();
        emu.serve_data_keys = true;
        let good = dummy_cert();
        let ch = run_handshake_v1(&mut emu, std::slice::from_ref(&good))
            .expect("a lone valid cert authenticates as before");
        assert_eq!(ch.volume_id, [0x5Au8; 16]);
        assert_eq!(emu.certs_sent.len(), 1);
        assert_eq!(&emu.certs_sent[0][..], &good.certificate[..92]);
    }

    /// A dead-v1 pairing that ALSO carries v2 creds must be skipped up front in
    /// production (`allow_p256 = false`) exactly like a plain dead pairing — the
    /// up-front `has_v2` gate must honor `allow_p256` the way `attempt_one_cert`
    /// does. Otherwise each such cert reaches the drive, fails the step-7
    /// self-verify, and burns a `MAX_CERT_ATTEMPTS` slot: `[dead+v2 ×3, valid]`
    /// exhausts the cap and the valid cert is never tried. With the gate fixed,
    /// none of the three dead certs ships a byte and the valid one authenticates.
    #[test]
    fn dead_v1_with_v2_creds_is_skipped_up_front_when_p256_disabled() {
        let mut emu = DriveEmu::new();
        emu.serve_data_keys = true;
        // A dead v1 pairing whose cert also advertises v2 creds. Under
        // `allow_p256 = false` the v2 path can never run, so this cert offers the
        // drive nothing and must be gated out host-side.
        let dead_with_v2 = || {
            let mut hc = mispaired_host_cert();
            hc.private_key_v2 = Some([0x11u8; 32]);
            hc.certificate_v2 = Some(vec![0x11u8; 92]);
            hc
        };
        let good = dummy_cert();
        let certs = vec![dead_with_v2(), dead_with_v2(), dead_with_v2(), good.clone()];
        let ch = run_handshake_v1(&mut emu, &certs)
            .expect("the dead+v2 certs are skipped up front; the valid one authenticates");
        assert_eq!(ch.volume_id, [0x5Au8; 16]);
        assert!(ch.read_data_key.is_some());
        assert_eq!(
            emu.certs_sent.len(),
            1,
            "only the VALID cert may reach the drive; the dead+v2 certs are gated \
             out up front and must not consume the MAX_CERT_ATTEMPTS cap"
        );
        assert_eq!(&emu.certs_sent[0][..], &good.certificate[..92]);
    }

    /// The positive counterpart, end-to-end: a consistent host cert passes the
    /// step-7 guard AND the drive, verifying the host signature the way real
    /// hardware does, confirms it against the EXACT step-7 layout
    /// (`drive_nonce || host_key_point_x || host_key_point_y`). Pins the
    /// production signed-data layout to libaacs's `crypto_aacs_sign` block.
    #[test]
    fn host_sign_guard_accepts_consistent_cert_and_drive_verifies_step7_layout() {
        let hc = dummy_cert();
        let (cx, cy) = cert_pub_key(&hc.certificate);
        let mut emu = DriveEmu::new();
        emu.host_cert_pub = Some((cx, cy));
        let (lax, lay) = (emu.la_x, emu.la_y);
        let auth =
            aacs_authenticate_with_anchor(&mut emu, &hc.private_key, &hc.certificate, &lax, &lay)
                .expect("a consistent host cert must complete the AKE through step 9");
        assert_ne!(auth.bus_key, [0u8; 16], "a bus key must be derived");
        assert_eq!(
            emu.host_sig_ok,
            Some(true),
            "the drive must verify the host signature over drive_nonce||host_x||host_y"
        );
    }

    /// Step-6 (DRIVE signature) verify, 1.0 primitive: the host verifies
    /// `sign(host_nonce || drive_key_point)` against the drive cert's public
    /// key. A valid signature verifies; tampering the data OR the signature
    /// rejects — the exact acceptance/rejection the step-6 check performs.
    #[test]
    fn step6_drive_key_signature_valid_and_invalid() {
        // Drive long-term keypair (stands in for the drive cert key).
        let (drive_priv, drive_x, drive_y) = generate_host_key_pair();
        // Ephemeral drive key point that gets signed.
        let (_eph_priv, kx, ky) = generate_host_key_pair();
        let host_nonce = [0x33u8; 20];

        let mut signed = [0u8; 60];
        signed[..20].copy_from_slice(&host_nonce);
        signed[20..40].copy_from_slice(&kx);
        signed[40..60].copy_from_slice(&ky);
        let (r, s) = ecdsa_sign(&drive_priv, &signed);

        assert!(
            ecdsa_verify(&drive_x, &drive_y, &r, &s, &signed),
            "a genuine drive key-point signature must verify"
        );
        // Tampered signed data → reject.
        let mut bad = signed;
        bad[59] ^= 0x01;
        assert!(
            !ecdsa_verify(&drive_x, &drive_y, &r, &s, &bad),
            "a tampered signed region must be rejected"
        );
        // Tampered signature → reject.
        let mut bad_s = s;
        bad_s[19] ^= 0x01;
        assert!(
            !ecdsa_verify(&drive_x, &drive_y, &r, &bad_s, &signed),
            "a tampered signature must be rejected"
        );
        // Wrong public key → reject.
        let (_p2, wx, wy) = generate_host_key_pair();
        assert!(
            !ecdsa_verify(&wx, &wy, &r, &s, &signed),
            "the wrong public key must be rejected"
        );
    }

    /// `read_volume_id` ACCEPTS a correct MAC and returns the VID; and REJECTS
    /// a wrong MAC with `AacsVidMac`. Exercises the function through the
    /// transport (existing MAC tests are primitive-level or via run_cert_handshake).
    #[test]
    fn read_volume_id_accepts_correct_mac_and_rejects_wrong_mac() {
        let bus_key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let vid = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let mac = aes_cmac_16(&vid, &bus_key);

        // Accept path.
        let mut good = vec![0u8; 36];
        good[4..20].copy_from_slice(&vid);
        good[20..36].copy_from_slice(&mac);
        let mut t = MockTransport::always(Reply::good(good));
        let mut auth = AacsAuth {
            bus_key,
            agid: 0,
            volume_id: None,
            read_data_key: None,
        };
        let got = read_volume_id(&mut t, &mut auth).expect("a correct MAC must be accepted");
        assert_eq!(got, vid, "the VID must be returned verbatim");
        assert_eq!(auth.volume_id, Some(vid), "the VID must be recorded");

        // Reject path: a wrong MAC.
        let mut bad = vec![0u8; 36];
        bad[4..20].copy_from_slice(&vid);
        bad[20..36].copy_from_slice(&mac);
        bad[20] ^= 0x01; // corrupt one MAC byte
        let mut t2 = MockTransport::always(Reply::good(bad));
        let mut auth2 = AacsAuth {
            bus_key,
            agid: 0,
            volume_id: None,
            read_data_key: None,
        };
        let e = read_volume_id(&mut t2, &mut auth2).expect_err("a wrong MAC must be rejected");
        assert!(matches!(e, Error::AacsVidMac), "got {e:?}");
        assert!(
            auth2.volume_id.is_none(),
            "no VID may be recorded on MAC failure"
        );
    }

    // ── Real-keydb-driven suite (the priv·G check that root-caused the bug) ──

    /// Load the real host certs from the local keydb JSON, or `None` when it is
    /// absent (so these tests SKIP cleanly in CI). Private keys must NEVER be
    /// committed to this repo (public github origin; the maintainers embed cert
    /// PUBLIC keys only and precommit runs a secret-leak scanner), so the certs
    /// are read at runtime from `$FREEMKV_KEYDB_JSON` (else `$HOME/Downloads`).
    fn load_keydb_host_certs() -> Option<Vec<(Vec<u8>, [u8; 20])>> {
        // Honour an override, else the canonical local path (built from $HOME
        // at runtime so no developer path is hard-coded into the source).
        let path = std::env::var("FREEMKV_KEYDB_JSON").ok().or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| format!("{h}/Downloads/keys.json"))
        })?;
        let raw = std::fs::read_to_string(&path).ok()?;
        let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let arr = json.get("host_certs")?.as_array()?;
        let hexb = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let mut out = Vec::new();
        for c in arr {
            let hc = hexb(c.get("hc")?.as_str()?);
            let pk = hexb(c.get("pk")?.as_str()?);
            if hc.len() == 92 && pk.len() == 20 {
                let mut priv_key = [0u8; 20];
                priv_key.copy_from_slice(&pk);
                out.push((hc, priv_key));
            }
        }
        Some(out)
    }

    /// For EVERY real host cert: it is a genuine LA-signed cert, and — for the
    /// internally-consistent ones — `priv·G == cert_pub_key(cert)` AND a
    /// signature by its private key self-verifies against its cert pubkey. Any
    /// mispaired entry (priv·G != pubkey) is REPORTED, not silently tolerated.
    #[test]
    fn real_host_certs_priv_times_g_and_self_verify() {
        let Some(certs) = load_keydb_host_certs() else {
            eprintln!("skip: local keydb JSON not present (set FREEMKV_KEYDB_JSON to run)");
            return;
        };
        assert!(!certs.is_empty(), "keydb must carry at least one host cert");

        let mut consistent = 0usize;
        let mut mispaired: Vec<String> = Vec::new();
        for (i, (hc, priv_key)) in certs.iter().enumerate() {
            // Every entry's certificate must carry a genuine LA signature.
            assert!(verify_cert(hc), "cert {i}: LA signature must verify");

            let (cx, cy) = cert_pub_key(hc);
            let (qx, qy) = priv_times_g_v1(priv_key);
            if qx == cx && qy == cy {
                consistent += 1;
                // The fix-target property: sign→self-verify MUST pass.
                let data = [0x5Au8; 60];
                let (r, s) = ecdsa_sign(priv_key, &data);
                assert!(
                    ecdsa_verify(&cx, &cy, &r, &s, &data),
                    "cert {i}: a consistent keydb pair must sign→self-verify"
                );
            } else {
                let hostid: String = hc[4..10].iter().map(|b| format!("{b:02x}")).collect();
                mispaired.push(hostid);
            }
        }
        assert!(
            consistent >= 1,
            "at least one internally-consistent real cert must exist"
        );
        if !mispaired.is_empty() {
            eprintln!(
                "note: {} keydb ent/ies are MISPAIRED (priv·G != cert pubkey): {mispaired:?} — \
                 the step-7 self-verify guard correctly rejects these host-side",
                mispaired.len()
            );
        }
    }

    /// The precise root-cause reproduction, keydb-driven: the `ffff80000210`
    /// entry pairs a valid, LA-signed certificate with the WRONG private key —
    /// a byte-for-byte duplicate of the `ffff000000ae` entry's key — so
    /// `priv·G` yields the OTHER entry's public key and the step-7 self-verify
    /// guard (correctly) rejects it. Documents that the bug is a corrupt keydb
    /// entry, not a defect in `ecdsa_sign` / `cert_pub_key`.
    #[test]
    fn keydb_entry_ffff80000210_is_mispaired_with_a_duplicate_private_key() {
        let Some(certs) = load_keydb_host_certs() else {
            eprintln!("skip: local keydb JSON not present");
            return;
        };
        let find = |hostid_hex: &str| -> Option<(Vec<u8>, [u8; 20])> {
            certs.iter().find_map(|(hc, pk)| {
                let hid: String = hc[4..10].iter().map(|b| format!("{b:02x}")).collect();
                (hid == hostid_hex).then(|| (hc.clone(), *pk))
            })
        };
        let (Some((cert210, pk210)), Some((_certae, pkae))) =
            (find("ffff80000210"), find("ffff000000ae"))
        else {
            eprintln!("skip: expected keydb host ids not present in this keydb");
            return;
        };

        // Its certificate is genuine (LA-signed) — the cert is NOT the problem.
        assert!(
            verify_cert(&cert210),
            "the ffff80000210 cert is genuinely LA-signed"
        );

        // The stored private key is a byte-for-byte duplicate of another entry.
        assert_eq!(
            pk210, pkae,
            "the ffff80000210 private key is a duplicate of the ffff000000ae key"
        );

        // Consequently priv·G != this cert's public key: the mispairing.
        let (cx, cy) = cert_pub_key(&cert210);
        let (qx, qy) = priv_times_g_v1(&pk210);
        assert!(
            qx != cx || qy != cy,
            "priv·G must NOT equal the ffff80000210 cert public key (mispaired)"
        );

        // And a signature by the stored key fails to self-verify — precisely
        // what the drive rejects as KEY NOT ESTABLISHED and what the guard now
        // catches host-side.
        let data = [0x5Au8; 60];
        let (r, s) = ecdsa_sign(&pk210, &data);
        assert!(
            !ecdsa_verify(&cx, &cy, &r, &s, &data),
            "the mispaired key must fail to self-verify against its cert pubkey"
        );
    }
}
