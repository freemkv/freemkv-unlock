//! AACS bus authentication handshake — ECDH key agreement + bus key derivation.
//!
//! Implements the AACS SCSI authentication protocol to obtain the Volume ID
//! (needed for VUK derivation) and, for AACS 2.0 (UHD), the Read Data Key:
//! allocate an AGID, exchange host/drive certs and key points, verify
//! signatures, derive the bus key via ECDH, then read VID / Read Data Keys.
//!
//! Supports AACS 1.0 and AACS 2.0 cert chains.
use crate::aacs::error::{Error, Result};
use crate::scsi::{AgidGuard, DataDirection, ScsiTransport};
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

fn scsi_write(session: &mut dyn ScsiTransport, cdb: &[u8], data: &[u8]) -> Result<()> {
    let mut buf = data.to_vec();
    let r = session.execute(cdb, DataDirection::ToDevice, &mut buf, 5_000)?;
    check_status(cdb, &r)
}

/// Turn a non-GOOD SCSI status into the structured `Scsi` error, carrying the
/// parsed sense.
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

// Hold an allocated AGID. A drive has only four, so its drop releases it (REPORT KEY
// format 0x3F) via `execute_cleanup`, so even a Stop frees it: one release per
// allocation (SS-7, evidence: libaacs mmc.c AGID invalidation; stop-design-v5 §2.3).
fn agid_guard<'a>(session: &'a mut (dyn ScsiTransport + 'a), agid: u8) -> AgidGuard<'a> {
    AgidGuard::new(session, agid, cdb_report_key(agid, 0x3F, 2))
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

// EXPERIMENTAL gate for the native AACS 2.0 (P-256) AKE. The 2.0 cert offsets are PROVISIONAL,
// so only the production real-anchor verify is gated off; tests still exercise the AKE. Flip
// once a real cert lands.
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

// Scalar multiplication using double-and-add. Not constant-time (timing depends on the secret
// scalar) — accepted tradeoff for a local, once-per- disc handshake.
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

// Verify an AACS 2.0 drive cert (type 0x11) against an AACS 2.0 LA key.
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
    // Defensive: a point at infinity has no usable x (stored x is 0), so never
    // reduce it to a bus key. Can't happen for d in [1, n) on a prime-order
    // subgroup point, but guard rather than derive an all-zero-ish key.
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
/// on a short cert, a private key `≡ 0 (mod n)`, or a point at infinity. A key
/// `>= n` is reduced mod n, exactly as `ecdsa_sign` effectively uses it.
pub fn aacs1_keypair_matches(private_key: &[u8; 20], cert: &[u8]) -> bool {
    if cert.len() < 52 {
        return false;
    }
    let p = BigUint::from_bytes_be(&EC_P);
    let a = BigUint::from_bytes_be(&EC_A);
    let n = BigUint::from_bytes_be(&EC_N);
    let d = BigUint::from_bytes_be(private_key) % &n;
    if d.is_zero() {
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

    // Bus key = lowest 128 bits (last 16 bytes) of x-coordinate; wipe the byte
    // buffer on drop. LIMITATION: the `BigUint`s `d` and `shared.x` keep secret
    // heap limbs zeroize can't reach (num-bigint has no Zeroize) — best-effort.
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
        // Rejection-sample d in [1, n): reducing raw RNG bytes mod n would bias d
        // toward small values (same modulo bias the ECDSA nonce path rejects), so
        // redraw any 0-or->=n candidate, like the AACS 1.0 generate_host_key_pair.
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
    /// Drive cert's Bus Encryption Capable flag: only such a drive is asked for
    /// the read data key.
    #[zeroize(skip)]
    pub bus_encryption_capable: bool,
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
            .field("bus_encryption_capable", &self.bus_encryption_capable)
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
    // AKE-only callers read the VID themselves under `auth.agid`, so the AGID is
    // handed over still held, exactly as before the guard existed.
    aacs1_ake(session, host_priv_key, host_cert, la_x, la_y)
        .map(|(auth, guard)| {
            guard.defuse();
            auth
        })
        .map_err(V1Fail::into_error)
}

/// Why the 1.0 AKE failed. `DriveCert`: the drive presented a recognised cert
/// that failed for a drive-side reason (type 0x01 failing LA verification, or
/// type 0x11 on the 1.0 path), so no other host cert can pass the 1.0 AKE.
enum V1Fail {
    DriveCert,
    Other(Error),
}

impl From<Error> for V1Fail {
    fn from(e: Error) -> Self {
        V1Fail::Other(e)
    }
}

impl V1Fail {
    fn into_error(self) -> Error {
        match self {
            V1Fail::DriveCert => Error::AacsCertVerify,
            V1Fail::Other(e) => e,
        }
    }
}

/// [`aacs_authenticate_with_anchor`] keeping the [`V1Fail`] distinction. On
/// success the AGID comes back still held in its [`AgidGuard`], which the caller
/// hands to [`finish_auth`]; on any failure the guard has already released it.
fn aacs1_ake<'a>(
    session: &'a mut (dyn ScsiTransport + 'a),
    host_priv_key: &[u8; 20],
    host_cert: &[u8],
    la_x: &[u8; 20],
    la_y: &[u8; 20],
) -> std::result::Result<(AacsAuth, AgidGuard<'a>), V1Fail> {
    if host_cert.len() < 92 {
        return Err(Error::AacsCertShort.into());
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

    // From here on we HOLD the AGID: an error below drops the guard, releasing it.
    let mut guard = agid_guard(session, agid);
    let auth =
        aacs_authenticate_with_agid(&mut *guard, agid, host_priv_key, host_cert, la_x, la_y)?;
    Ok((auth, guard))
}

/// Steps 3-9 of [`aacs_authenticate`], with the AGID already allocated and held
/// by the caller's [`AgidGuard`], which releases it on any of the early returns.
fn aacs_authenticate_with_agid(
    session: &mut dyn ScsiTransport,
    agid: u8,
    host_priv_key: &[u8; 20],
    host_cert: &[u8],
    la_x: &[u8; 20],
    la_y: &[u8; 20],
) -> std::result::Result<AacsAuth, V1Fail> {
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

    // Only a type-0x01 (1.0) cert is verifiable here; accepting 0x11 would skip this and
    // the step-6 verify yet run ECDH (bus-key hole). 0x11 gets P-256 only when enabled
    // (AACS2_P256_EXPERIMENTAL, off in production); otherwise the handshake fails.
    if drive_cert[0] == 0x01 {
        if !verify_cert_with_anchor(&drive_cert, la_x, la_y) {
            return Err(V1Fail::DriveCert);
        }
    } else {
        tracing::debug!(
            target: "freemkv::disc",
            phase = "aacs_cert_unsupported_type",
            cert_type = drive_cert[0],
            "drive certificate is not a verifiable AACS 1.0 (type 0x01) cert on the \
             1.0 path; rejecting"
        );
        // 0x11 is a real 2.0 drive; any other type (e.g. a zeroed cert) is unproven.
        return Err(if drive_cert[0] == 0x11 {
            V1Fail::DriveCert
        } else {
            V1Fail::Other(Error::AacsCertVerify)
        });
    }

    // Step 6: Read drive key point + signature (REPORT KEY format 0x02)
    let cdb = cdb_report_key(agid, 0x02, 84);
    let response =
        scsi_read(session, &cdb, 84).map_err(|e| handshake_err(e, Error::AacsKeyRead))?;

    let mut drive_key_point = [0u8; 40]; // x(20) + y(20)
    let mut drive_key_sig = [0u8; 40]; // r(20) + s(20)
    drive_key_point.copy_from_slice(&response[4..44]);
    drive_key_sig.copy_from_slice(&response[44..84]);

    // Verify sign(host_nonce || drive_key_point) against the LA-verified drive
    // cert's key. Always runs: only the type-0x01 cert verified above reaches
    // here, so cert_pub_key's AACS-1.0 offsets are correct (0x11 was let through).
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
            return Err(Error::AacsKeyVerify.into());
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
        return Err(Error::AacsHostSignVerify.into());
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
        // Drive cert byte 1 bit 0 (libaacs `_get_bus_encryption_capable`).
        bus_encryption_capable: drive_cert[1] & 0x01 != 0,
    })
}

// Native AACS 2.0 handshake (P-256/SHA-256), returning the AGID still held in its guard like
// `aacs1_ake`. LA anchor is a parameter so tests drive the full AKE; its 2.0 cert offsets are
// PROVISIONAL, so run_cert_handshake gates it off (see AACS2_P256_EXPERIMENTAL).
fn aacs2_authenticate_p256_with_anchor<'a>(
    session: &'a mut (dyn ScsiTransport + 'a),
    host_priv_key: &[u8; 32],
    host_cert: &[u8],
    la_x: &[u8; 32],
    la_y: &[u8; 32],
) -> Result<(AacsAuth, AgidGuard<'a>)> {
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

    // From here we HOLD the AGID: an error below drops the guard, releasing it.
    let mut guard = agid_guard(session, agid);
    let auth =
        aacs2_authenticate_p256_with_agid(&mut *guard, agid, host_priv_key, host_cert, la_x, la_y)?;
    Ok((auth, guard))
}

/// Steps 3-9 of [`aacs2_authenticate_p256_with_anchor`] with the AGID already
/// allocated and held by the caller's [`AgidGuard`].
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

    // Chain-of-trust gate, mandatory on this live path: (a) reject any non-0x11 cert type
    // outright, (b) treat cert verify failure as FATAL, not logged-and-continued.
    if drive_cert[0] != 0x11 {
        tracing::debug!(
            target: "freemkv::disc",
            phase = "aacs2_cert_unknown_type",
            cert_type = drive_cert[0],
            "AACS 2.0 drive certificate carries an unexpected type byte; rejecting"
        );
        return Err(Error::AacsCertVerify);
    }
    if !verify_cert_p256(drive_cert, la_x, la_y) {
        tracing::debug!(
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

    // The 2.0 cert's BEC position is unconfirmed, so keep always requesting.
    Ok(AacsAuth {
        bus_key,
        agid,
        volume_id: None,
        read_data_key: None,
        bus_encryption_capable: true,
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
/// host certs (already collected by the consumer) and, on success, read the
/// Volume ID + `read_data_key`. This is the cert "remove bus encryption"
/// primitive, shared by the in-tree path and the external `freemkv-unlock-aacs`
/// plugin. Wedge-guarded: caps drive attempts and sleeps between them. Every
/// no-VID outcome is a structured [`crate::UnlockError`].
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
/// [`CertHandshake`]. Takes the AGID's guard and so releases it on EVERY exit,
/// including success (nothing downstream needs the AGID once the VID and data
/// keys are read) and before the caller's P-256 fall-through. `idx` is for log
/// correlation only.
fn finish_auth(
    mut guard: AgidGuard<'_>,
    mut auth: AacsAuth,
    idx: usize,
) -> std::result::Result<CertHandshake, FinishErr> {
    debug_assert_eq!(guard.agid(), auth.agid, "the guard holds this auth's AGID");
    let scsi: &mut dyn ScsiTransport = &mut *guard;
    let volume_id = match read_volume_id(scsi, &mut auth) {
        Ok(vid) => vid,
        Err(e) => {
            let transport = e.is_scsi_transport_failure();
            let vid_mac = matches!(e, Error::AacsVidMac);
            tracing::debug!(
                target: "freemkv::disc",
                phase = "handshake_vid_read_failed",
                cert_index = idx,
                error_code = e.code(),
                transport_failure = transport,
                "auth ok but volume ID read failed"
            );
            // The guard releases the AGID on this return.
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
    let rdk = if auth.bus_encryption_capable {
        Some(read_data_keys(scsi, &mut auth))
    } else {
        None
    };
    let (read_data_key, read_data_key_err) = match rdk {
        // Not Bus Encryption Capable: no read data key to fetch, and not a failure.
        None => (None, None),
        Some(Ok((rdk, _))) => (Some(rdk), None),
        Some(Err(e)) => {
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
            // Abort like VID (the guard releases the AGID).
            if transport {
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
        bus_encryption_capable = auth.bus_encryption_capable,
        has_read_data_key = read_data_key.is_some(),
        "AACS bus-auth handshake complete"
    );
    // Release the AGID on the fully-successful path too: nothing downstream needs
    // it, and holding it slowly leaks the drive's 4-AGID pool across discs.
    drop(guard);
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
    /// Rejected (non-transport) — record + try the next cert. `v1_drive_dead`:
    /// the 1.0 AKE failed on the drive's own cert ([`V1Fail::DriveCert`]).
    Reject {
        code: u16,
        v1_drive_dead: bool,
    },
}

/// The cert's v1 creds pass every host-side check the 1.0 AKE makes before
/// touching the drive: length, then `priv·G == cert pubkey`.
fn v1_creds_usable(hc: &crate::HostCert) -> bool {
    hc.certificate.len() >= 92 && aacs1_keypair_matches(&hc.private_key, &hc.certificate)
}

/// The cert carries v2 creds the P-256 AKE would accept host-side.
fn v2_creds_usable(hc: &crate::HostCert, allow_p256: bool) -> bool {
    allow_p256
        && hc.private_key_v2.is_some()
        && hc.certificate_v2.as_ref().is_some_and(|c| c.len() >= 132)
}

/// One host cert's drive round-trip: AACS 1.0 AKE first (also the backward-compat
/// path a 2.0 drive accepts) when `try_v1`, then the native P-256 (AACS 2.0) AKE
/// when `has_v2` AND the 1.0 AKE was skipped, cert-rejected, or completed with a
/// failed VID MAC. The caller guarantees `try_v1 || has_v2`.
fn attempt_one_cert(
    scsi: &mut dyn ScsiTransport,
    hc: &crate::HostCert,
    idx: usize,
    la: (&[u8; 20], &[u8; 20], &[u8; 32], &[u8; 32]),
    try_v1: bool,
    has_v2: bool,
) -> CertOutcome {
    let mut v1_drive_dead = false;
    if try_v1 {
        match aacs1_ake(scsi, &hc.private_key, &hc.certificate, la.0, la.1) {
            // `finish_auth` drops the guard (releasing the 1.0 AGID) on every
            // return, so it is free before the P-256 fall-through below.
            Ok((auth, guard)) => match finish_auth(guard, auth, idx) {
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
            Err(V1Fail::Other(e)) if e.is_scsi_transport_failure() => {
                return CertOutcome::Transport;
            }
            Err(f) => {
                v1_drive_dead = matches!(f, V1Fail::DriveCert);
                let e = f.into_error();
                if !has_v2 {
                    return CertOutcome::Reject {
                        code: e.code(),
                        v1_drive_dead,
                    };
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "aacs1_reject_p256_fallback",
                    cert_index = idx,
                    error_code = e.code(),
                    "AACS 1.0 AKE rejected; falling through to the native P-256 AKE"
                );
            }
        }
    }

    // Native AACS 2.0 (P-256) AKE. Reached only when `has_v2`.
    let (Some(k), Some(c)) = (hc.private_key_v2.as_ref(), hc.certificate_v2.as_deref()) else {
        // `has_v2` guarantees both are Some; unreachable in practice.
        return CertOutcome::VidUnavailable;
    };
    match aacs2_authenticate_p256_with_anchor(scsi, k, c, la.2, la.3) {
        Ok((auth, guard)) => match finish_auth(guard, auth, idx) {
            Ok(ch) => CertOutcome::Ok(ch),
            Err(FinishErr::Transport) => CertOutcome::Transport,
            // A VID failure on the P-256 path is terminal for this cert.
            Err(FinishErr::VidMac) | Err(FinishErr::VidUnavailable) => CertOutcome::VidUnavailable,
        },
        Err(e) if e.is_scsi_transport_failure() => CertOutcome::Transport,
        Err(e) => CertOutcome::Reject {
            code: e.code(),
            v1_drive_dead,
        },
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
    // firmware wedge. Defense-in-depth: cap drive attempts, sleep between them.
    const MAX_CERT_ATTEMPTS: usize = 3;
    const PER_CERT_BACKOFF_MS: u64 = 1000;
    let la = (la_v1.0, la_v1.1, la_v2.0, la_v2.1);
    let mut last_err_code: Option<u16> = None;
    // The wedge guard caps attempts that TOUCH the drive; the free up-front
    // skip below does not consume it, so bad keydb entries at the front of the
    // list can't exhaust the cap before a VALID cert further down is tried.
    let mut drive_attempts = 0usize;
    // Set once the drive's own 1.0 cert/key failed: no later 1.0 AKE can pass.
    let mut v1_drive_dead = false;
    for (idx, hc) in host_certs.iter().enumerate() {
        if drive_attempts >= MAX_CERT_ATTEMPTS {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "cert_attempt_cap_reached",
                max_attempts = MAX_CERT_ATTEMPTS,
                "reached the cert-attempt wedge-guard cap; not trying more certs"
            );
            break;
        }
        // Up-front host-side gate (no drive round-trip): skip a cert that has
        // neither a 1.0 AKE that can still pass nor usable v2 creds.
        let has_v2 = v2_creds_usable(hc, allow_p256);
        if !has_v2 && v1_drive_dead {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "cert_skip_v1_drive_dead",
                cert_index = idx,
                "skipping v1-only host cert: the drive's own 1.0 cert already failed"
            );
            continue;
        }
        let v1_ok = v1_creds_usable(hc);
        if !v1_ok && !has_v2 {
            tracing::info!(
                target: "freemkv::disc",
                phase = "cert_skip_dead_pairing",
                cert_index = idx,
                host_id = %cert_host_id_hex(&hc.certificate),
                "skipping host cert: it is truncated or its stored private key does not \
                 match its certificate public key (dead keydb pairing); no drive round-trip"
            );
            continue;
        }
        // Halt-aware (stop-design-v5 §2.3 "The per-cert backoff … uses `pause`"): a
        // Stop ends the wait at once, surfacing as the transport abort it is.
        if drive_attempts > 0
            && scsi
                .pause(std::time::Duration::from_millis(PER_CERT_BACKOFF_MS))
                .is_err()
        {
            tracing::debug!(
                target: "freemkv::disc",
                phase = "cert_backoff_interrupted",
                cert_index = idx,
                "per-cert backoff interrupted (operation stopped); aborting"
            );
            return Err(UnlockError::Transport);
        }
        drive_attempts += 1;
        match attempt_one_cert(scsi, hc, idx, la, v1_ok && !v1_drive_dead, has_v2) {
            CertOutcome::Ok(ch) => return Ok(ch),
            CertOutcome::Transport => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "handshake_transport_fault",
                    cert_index = idx,
                    "transport fault during AACS auth; aborting"
                );
                return Err(UnlockError::Transport);
            }
            CertOutcome::VidUnavailable => return Err(UnlockError::VidUnavailable),
            CertOutcome::Reject {
                code,
                v1_drive_dead: dead,
            } => {
                last_err_code = Some(code);
                v1_drive_dead |= dead;
            }
        }
    }
    // No cert reached the drive (all skipped as dead pairings, or list empty):
    // a keydb/host-cert problem, not a drive rejection — report it as such rather
    // than the less accurate HandshakeRejected the drive never issued.
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
        drive_side = v1_drive_dead,
        "The drive rejected the AACS host certificate, so no Volume ID was obtained."
    );
    Err(UnlockError::HandshakeRejected)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "handshake_tests.rs"]
pub(crate) mod tests;
