# `src/css/mod.rs` — extended notes

Long-form rationale relocated out of doc-comments in `src/css/mod.rs` to keep
each in-source comment within the comment-guard caps. Pointers in the source
reference the anchors below.

## css_scsi

The single seam every bus-auth step now goes through. It closes two holes
that each step open-coded before:
  * `Err` was collapsed to `CssAuthFailed`, so a dead bus looked like "this
    unlocker doesn't apply" and the consumer kept probing it (`step_err`);
  * `Ok` was never inspected, but per the contract a CHECK CONDITION arrives
    as `Ok` with a non-zero `status` — so a refused command handed the step
    back its own zero-filled buffer to parse as drive data.

`min_bytes` is the number of bytes the step must actually receive (0 for a
write / no-data command, whose transferred count no transport promises).

## mounted_disc_is_dvd

`Err(Transport)` on a dead bus. This is the FIRST command the DVD unlocker
issues, and its match had no `Err` arm at all: a transport fault fell into
`_ => false`, which the caller turned into `NotApplicable` — a dead bus read
as "not a DVD", with nothing logged anywhere on the path.

## establish_authenticated_session

Runs invalidate AGIDs → allocate AGID → host challenge → brute-force the
variant → drive challenge → send host key. Completing the handshake sets the
drive's Authentication Success Flag (ASF=1) — which is the ENTIRE purpose: it
unlocks scrambled-sector reads. Returns the negotiated AGID (the caller needs
it for the best-effort disc-key REPORT KEY). The CSS bus key is intentionally
NOT derived: descrambling is keyless — the key is recovered directly from the
data — so the bus key has no consumer.

## read_disc_key

Issues READ DVD STRUCTURE format 0x02 (the Disc Key block — opcode 0xAD, NOT
the REPORT KEY 0xA4 disc-key block; format 0x01 is Copyright Information)
purely for the bus-auth unlock side effect. The returned block contents are
not used — the descramble title key is recovered keylessly elsewhere, so the
genuine disc-key REPORT KEY is intentionally skipped. (If a drive is ever
found where bus-auth alone does not open scrambled reads, a real REPORT KEY
format 0x02 belongs here.)

## disc-key-report-key

Disc-key REPORT KEY: issued BEST-EFFORT for any firmware that ties part of
its read-unlock to it. The bytes are unused (the descramble key is recovered
keylessly) and a failure is NON-FATAL — the gate is already open from
bus-auth. This replaces the title-key REPORT KEY, whose hard failure used to
abort the whole unlock (the 7014 bug on USB bridges).

## dvdunlocker-name

User-facing unlocker label. This unlocker's job is the DVD read-enablement
bus-auth (it clears the drive's scrambled-read barrier and learns no key) —
a property of the DVD medium, NOT of whether the content happens to be
CSS-scrambled. Reporting it as "DVD" is honest: on any DVD the bus-auth ran;
the CSS descramble itself is keyless and handled downstream, so it is not a
separate "did an unlocker run" signal.

## key-guard (no_key_bytes_in_instrumentation)

SECURITY REGRESSION GUARD: no instrumentation in libfreemkv may emit raw key
material. Scans every source file for a `tracing` field that binds a
forbidden key name to a value-producing expression (`= expr` or `%expr` /
`?expr`). The only allowed forms are a string literal (e.g.
`disc_key = "<redacted>"`) or a `_fp` fingerprint field. This is a
source-scan test (not a runtime capture) so it stays cheap and catches
re-introductions at compile/CI time.

## perm-challenge-rows

Grounding: crypt_key does `scratch[i] = challenge[perm[i]]` for i in 0..10 —
perm must be a bijection on 0..10 to use every challenge byte exactly once.
Mutation: change PERM_CHALLENGE[0] entry `9` to `8` (duplicate) -> the
"covers 0..10" assert fires.

## perm-variant-rows

Grounding: `css_variant = PERM_VARIANT[k][variant]` then indexes
VARIANTS[css_variant] (0..32). Mutation: set PERM_VARIANT[0][1] =
PERM_VARIANT[0][0] -> duplicate assert fires; also any value >= 32 would
later index VARIANTS OOB.

## crypt-key-byte-dependence

Grounding: scratch[i]=challenge[perm[i]] for all 10 i, and scratch seeds both
LFSRs (bytes 5..10 via tmp1) and the round terms (bytes 0..5). Mutation: in
`scratch[i] = challenge[perm[i]]` replace with `challenge[i]` for a perm that
drops a byte — or hardcode one scratch entry — and some challenge byte stops
mattering; this fails.

## crypt-key-type0-distinct

Grounding: variant selects css_variant -> VARIANTS[css_variant] -> cse, which
feeds every round; distinct variants give distinct cse-driven keys in
practice. Mutation: make `cse` ignore the variant (e.g. `let cse = 0`) -> all
32 outputs collapse to one value; the distinctness assert fires.

## crypt-key-preconditions

`key_type < 3`: `debug_assert!(key_type < 3, ...)`; PERM_CHALLENGE has 3 rows
(indices 0,1,2). Mutation: delete the debug_assert AND the match-arm guard —
but the match `_ =>` arm would then index PERM_CHALLENGE[3] OOB and panic
differently; with the assert in place this test pins the contract.

`variant < 32`: `debug_assert!((variant as usize) < 32, ...)`. Mutation:
removing the assert makes this index VARIANTS[32] (still a panic, but
unguarded); the assert documents/enforces the contract.

## cdb-builders

report_key_cdb encodes a 12-byte MMC REPORT KEY (opcode 0xA4) CDB: byte 0 =
operation code 0xA4, bytes 8-9 = allocation length (big-endian), byte 10 =
(AGID << 6) | (key_format & 0x3F), all other bytes zero. Mutation: change
`(alloc_len >> 8)` to `alloc_len` for byte 8 (lose the big-endian split) ->
byte 8/9 assert fails; change `agid << 6` to `agid << 5` -> the AGID-position
assert fails.

The key format field is masked to 6 bits so a format with high bits set
cannot corrupt the AGID: `report_key_cdb(0, 0xFF, _)` -> byte 10 low 6 bits =
0x3F, AGID = 0. Grounding: `(agid << 6) | (format & 0x3F)`.

send_key_cdb encodes a 12-byte MMC SEND KEY (opcode 0xA3) CDB with the
parameter-list length at bytes 8-9 (big-endian) and AGID/format at byte 10.
Mutation: change opcode to SCSI_REPORT_KEY -> opcode assert fails; swap
bytes 8/9 -> length assert fails.

Allocation length larger than 255 must split across bytes 8 (high) and 9
(low) — a 16-bit big-endian field. report_key_cdb with alloc_len 0x0804
(2052, the disc-key block size used in read_disc_key) -> byte 8 = 0x08, byte
9 = 0x04. Mutation: write only byte 9 without byte 8 -> the drive sees a
4-byte transfer, truncating the disc-key block.

## Defect regression tests

**defect-7** (`transport_fault_probing_for_a_dvd_aborts`): `mounted_disc_is_dvd`
is the FIRST command the DVD unlocker issues and its match had no `Err` arm:
a transport fault fell into `_ => false`, so a dead bus was reported as "not
a DVD" (`NotApplicable`) and the consumer kept probing it — with nothing
logged anywhere on the path. Catches restoring that catch-all arm.

**defect-2** (`transport_fault_during_bus_auth_aborts`): a DVD is mounted,
then the bus dies during bus-auth. Every CSS step used to do
`.map_err(|_| CssAuthFailed)`, discarding the `ScsiError` and making the
`Transport` arm of the error conversion unreachable from any real call site —
so a dead bus arrived as `NotApplicable` and the consumer went on probing it.
</content>
