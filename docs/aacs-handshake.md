# AACS bus authentication handshake

## Flow

1. Invalidate AGIDs → allocate fresh AGID
2. Send host certificate + nonce
3. Receive drive certificate + nonce
4. Receive drive key point + signature, verify
5. Sign host key point, send
6. ECDH: host_priv × drive_key_point → bus key (low 128 bits of x)
7. Read VID or Read Data Keys (encrypted with bus key)

## Why `scsi_read`/`scsi_write` check status at the seam

The contract this crate is built on (`ScsiTransport::execute`) returns `Ok`
on a SCSI sense and `Err` ONLY on a transport-layer fault. These two helpers
used to propagate the `?` and nothing else — so a CHECK CONDITION (`Ok`,
non-zero `status`) handed the caller back its own ZERO-FILLED buffer and
every REPORT/SEND KEY step consumed zeros as valid drive data: a drive
certificate of zeros, a key point of zeros, a Volume ID of zeros, all
reported as success. It has not fired in production only because the sole
transport implementor violates the contract in the opposite direction (it
returns `Err` for any non-zero status). Plugging in a CONFORMING transport
would have turned the whole handshake into a zero-buffer success, so the
status and the transferred length are checked here, at the seam.

## Why `scsi_write` shares this reasoning

Same contract reasoning as `scsi_read`: a drive that REFUSES the host
certificate answers with `Ok` + CHECK CONDITION, and treating that as a
successful send carried the handshake on against a drive that never
accepted it.

## `ec_mul` design notes

**Constant-time tradeoff:** this branches on `scalar.bit(0)` and clones
BigUints per iteration, so its timing is data-dependent on the secret scalar
(the long-term host private key in `ecdsa_sign`, the ephemeral key in ECDH).
This is deliberate: the handshake runs once per disc against a local optical
drive, so throughput and the narrow local-timing surface do not justify
pulling in a vetted constant-time backend. Revisit if this ever signs in a
remote/shared context.

**Cofactor:** both AACS curves used here have cofactor 1, so a point that
lies on the curve is automatically in the prime-order subgroup — no
small-subgroup defense / `n·P == O` check is required for the inputs this is
called with.

## `verify_cert_p256` — provisional AACS 2.0 cert layout

Verifies an AACS 2.0 drive certificate (type 0x11) against an AACS 2.0 LA
key. PROVISIONAL LAYOUT — the byte offsets below are NOT yet confirmed
against a genuine AACS 2.0 cert, and no such cert exists on this machine to
pin them (an exhaustive hunt found only 2.0 *content* certs, a different
format; a real host/drive AKE cert needs a live USB/SCSI capture). What IS
confirmed: first, the P-256/SHA-256 ECDSA primitive and curve constants are
correct (`ecdsa_verify_p256_verifies_a_genuine_aacs2_content_cert` verifies a
real 2.0 content cert under the published CC key); second, the 132-byte
4-byte-header framing MATCHES the step-6 drive-key message (x[4..36] /
y[36..68] / r[68..100] / s[100..132]), the natural 20→32-byte scaling of the
established AACS 1.0 84-byte key-message framing.

What is NOT confirmed: that a *certificate* shares that framing. No known
implementation verifies 2.0 certs against a confirmed layout (the published
spec draft leaves that format ambiguous), and the AACS 2.0 draft architecture
lists the 2.0 host cert (type 0x12) with a 6-byte Host ID + a NEW 4-byte
paired-Device-Key-Set field before the 64-byte public key — implying a
~140–144-byte cert with the pubkey near offset 12–16 and a signed range of
~76–80 bytes, NOT 68. The drive cert (type 0x11) has no paired-DKS field
(~140 bytes, pubkey ~[12..76], signed ~first 76). So the offsets HERE
(pubkey [4..68], signed [..68]) are a best-effort self-consistent
placeholder, chosen to match the confirmed key message; they will almost
certainly move when a real cert lands (see the `#[ignore]` real-cert slot).
This matters for USEFULNESS, not SAFETY: a wrong signed range makes
verification FAIL, and since the caller treats a verify failure as FATAL,
the path fails CLOSED (rejects) rather than trusting anything — never the
reverse.

The `>= 132` guard keeps the `cert[100..132]` slice safe while letting a
full-length cert reach verification (the old `>= 138` guard rejected every
132-byte input unconditionally).

The LA anchor is a PARAMETER, not the compiled-in constant, so a unit test
can drive the whole chain under a test LA keypair (sign a synthetic drive
cert, prove it is accepted / a bad-sig cert is rejected) without the real
anchor's private half, which no one has. Production always threads
`AACS2_LA_PUB_X/Y` from `aacs2_authenticate_p256`.

## Why an unknown drive-cert type must be rejected

This used to be an `if` / `else if` with NO `else`, so an unknown type
(e.g. 0x02) fell straight through: `is_aacs20` stayed false, so the step-6
key-signature check still ran — against `cert_pub_key(drive_cert)`, the
drive's OWN key lifted out of a cert that was never checked against the LA.
A rogue USB bridge could set byte 0 to 0x02, present its own keypair, sign
`host_nonce || drive_key_point`, and the handshake would return Ok with an
attacker-chosen bus key. The chain of trust must not appear to have run
when it did not.

## AACS 2.0 chain-of-trust gate (`aacs2_authenticate_p256_with_agid`)

The SAME shape the AACS 1.0 sibling (`aacs_authenticate_with_agid`)
enforces, now MANDATORY because this path is live. Two distinct rejections,
both BEFORE any drive key is trusted:

**(a) Cert TYPE gate.** An AACS 2.0 drive cert is type 0x11. Anything else
is unexpected on the native P-256 AKE and is REJECTED here, never allowed to
fall through. The earlier `if type==0x11 && !verify` form left NO branch for
a non-0x11 type: a rogue bridge could send a type-0x10 (or any) cert, skip
verification entirely, and still reach the step-6 key check against
`cert_pub_key_p256(drive_cert)` — its OWN key, lifted from a cert the LA
never signed — winning an attacker-chosen bus key. The chain of trust must
not merely LOOK like it ran.

**(b) Cert VERIFY is FATAL.** A type-0x11 cert whose P-256/SHA-256 signature
does not verify under the real 2.0 LA anchor (`AACS2_LA_PUB`, on-curve — see
`la_anchor_keys_are_on_curve`) is REJECTED, not logged-and-continued.
`ecdsa_verify_p256` range/curve-checks every point (`point_on_curve`), so a
forged or off-curve cert key cannot slip past. The previous "non-fatal for
backward compat" behaviour was the exact hole the SECURITY note demanded be
closed before wiring.

## `run_cert_handshake` — cert-agnostic AKE selection

The AACS 1.0 host cert is always present and is tried FIRST: an AACS 2.0
drive accepts a 1.0 host cert for backward compatibility, which is enough to
learn the Volume ID. If the drive REFUSES the 1.0 cert (a plain cert-level
rejection — NOT a dead or wedged bus) and THIS host cert also carries AACS
2.0 (P-256) credentials, fall back to the native P-256 AKE.

This does NOT branch on "do we possess 2.0 certs?" as a feature switch: it
consumes whatever the supplied `HostCert` carries, exactly as the 1.0 path
consumes `hc.certificate`. A host cert without v2 credentials simply has
nothing more to present and keeps its 1.0 error; a host cert WITH them
drives the P-256 AKE the moment the drive asks for it. When a real 2.0 host
cert is supplied at runtime, the P-256 handshake runs — no code change, no
possession gate.

A transport fault on the 1.0 attempt short-circuits the fallback:
re-running the P-256 AKE against a bus that is gone re-issues AGID
invalidation + SEND/REPORT KEY for nothing and buries the real (replug)
cause. The `Err` arm below still classifies it as `Transport`.

## AACS 2.0 (P-256) host-certificate handshake — live-path test plumbing

No genuine 2.0 host cert exists for us to sign with (a side agent is hunting
one; see the `#[ignore]` slot at the end). So the tests below prove the
PLUMBING under a self-generated test LA keypair: a 132-byte drive cert
signed by the test LA is threaded through the SAME code the production
anchor uses, only the anchor differs (a parameter, not a recompile). The
layout mirrored is the code's self-consistent 4-byte-header framing —
header(4)+pub_x(32)+pub_y(32)+sig_r(32)+sig_s(32)=132, LA signs SHA-256 over
cert[..68] — identical to the step-6 drive-key message framing and the
156-byte SEND KEY host-cert payload (4+20 nonce+132 cert).

## `ecdsa_verify_p256_verifies_a_genuine_aacs2_content_cert` — why it matters

SANITY: `ecdsa_verify_p256` + the P-256 curve constants + SHA-256 are correct
against GENUINE AACS 2.0 material. No real 2.0 host/drive AKE cert exists
anywhere on this machine (an exhaustive hunt found none — it needs a live
USB/SCSI AKE capture), but a real AACS 2.0 CONTENT certificate does
(`research/aacs/iso-aacs/CivilWar/Content000.cer`, type 0x10, 232 bytes). It
is signed by the AACS 2.0 *Content Cert* key (P-256/SHA-256, 64-byte
signature over the first `signed_len` bytes) — a DIFFERENT key for a
DIFFERENT purpose than the AKE LA anchor, but it exercises the EXACT same
`ecdsa_verify_p256` primitive `verify_cert_p256` relies on; only the pubkey
and the offsets differ. Proving it verifies here pins that the P-256
ECDSA/SHA-256 math and the `point_on_curve` gate are right, so when a
genuine 2.0 host/drive cert (and its correct signed range) lands, only the
offsets — not the crypto — remain to be fixed.

The CC pubkey is the published AACS 2.0 Content Certificate public key
(P-256). Corrupting any `P256_*` constant, or removing SHA-256, makes this
real-vector verification go red.

## Cert support

- AACS 1.0: custom 160-bit curve, SHA-1, 20-byte keys
- AACS 2.0: an AACS 2.0 drive accepts an AACS 1.0 host cert for backward
  compatibility (that yields the Volume ID), and the native P-256/SHA-256
  AACS 2.0 AKE is the fallback when the drive refuses the 1.0 cert AND the
  supplied host cert carries AACS 2.0 (P-256) credentials. Both paths are
  LIVE and share the same chain-of-trust hardening; see
  `run_cert_handshake` for the cert-agnostic dispatch.
