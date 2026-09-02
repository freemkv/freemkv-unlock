# `src/ld/mod.rs` — design notes

Long-form rationale relocated out of inline comments to satisfy the
comment-guard's per-audience line caps. See the pointer comments in
`src/ld/mod.rs` for where each section applies.

## `cdb` gating

`cdb` carries ONLY the unlock-handshake wire format that the bdemu emulator
needs (the real unlocker drives its CDBs from per-drive profile templates,
not these constants). Compile it only when the `emulation` feature exposes
it, so it never dead-codes in a normal build. Compiled under `cfg(test)` as
well as the feature: its tests pin the unlock wire format, and gating the
whole module on a non-default feature meant CI (which builds with default
features) never ran them.

## Public catalog design

The catalog of drives the MT1959 unlocker recognizes is the one piece of
`ld` worth exposing publicly: it answers "is this drive supported?" without
unlocking, and the bdemu test-emulator reads it to impersonate a supported
drive. The unlock *mechanism* (firmware blobs, upload sequence, CDB wire
format) stays private — only the catalog and its match result are public.

## `firmware_unlock` contract

The MediaTek firmware unlock. Because the MT1959 unlocker removes AACS bus
encryption AT THE DRIVE (the unlocked drive serves CLEAR content), this ONE
operation satisfies BOTH the drive-features and the bus-removal capability
— so `unlock_features` and `unlock_bus` both delegate here. The result
carries `drive_unlocked: true` (no bus key needed) and the OEM Volume ID.

A no-firmware-route drive (Renesas / no profile) returns `NotApplicable`; a
transport fault propagates as `Transport`; any other firmware failure also
falls through as `NotApplicable`.

## Half-unlock fallback

`init` only proves the handshake COMPLETED — `do_unlock` returns Ok on a
response that carried the per-drive signature but not both firmware
markers. Only `is_unlocked()` means the drive actually reached the
extended-access state and serves clear content. Reporting
`drive_unlocked: true` off `init` alone told the consumer the bus was clear
on a half-unlocked drive, which suppressed the cert-auth fallback and
shipped ciphertext at rc=0. A partial unlock must fall through to the next
unlocker.

## `probe_disc` dead-bus classification

A transport fault during disc-speed probing is a DEAD BUS, not a
speed-calibration miss. The rest of this path (`read_oem_vid`) is a no-op
for the 140/206 profiles that carry no `read_vid_cdb`, so it never touches
the bus again — meaning this swallowed fault was the ONLY dead-bus signal,
and warn-and-continue turned it into `Ok(Unlocked{drive_unlocked: true})`:
a dead bus rendered as a fully-unlocked drive (the flagship
failure-that-looks-like-success). A genuine calibration miss (drive sense /
short reply) still continues on the default speed table.

## Probe-disc dead-bus test / mutation notes

THE probe-disc dead-bus test. The drive unlocks fully (both firmware
markers), then the bus DIES during disc-speed calibration. `probe_disc`
used to be warn-and-continued regardless of the fault, and — because the
140/206 profiles without a `read_vid_cdb` never touch the bus again — a
dead bus was reported as `Ok(Unlocked{drive_unlocked:true})`: a dead bus
rendered as a successful unlock (the flagship failure-that-looks-like-
success). `firmware_unlock` must now abort with `Transport`.

MUTATION: reverting the `if e.is_transport_failure()` return in
`firmware_unlock` (warn-and-continue), OR flattening the probe loops'
transport classification, makes this go red.
