# freemkv-unlock-ld

The **LibreDrive** unlocker plugin for [libfreemkv](https://github.com/freemkv/libfreemkv).

libfreemkv ships only the `Unlocker` trait + registry and stays firmware-clean.
This crate owns *how* MediaTek MT1959 drives are firmware-unlocked: the bundled
drive-profile database (`profiles.json`), the firmware blobs, the
WRITE_BUFFER / MODE SELECT upload, the unlock CDBs, and the variant-A / variant-B
handshake logic.

## Usage

Register the unlocker once at process start, before any rip:

```rust
libfreemkv::register_unlocker(Box::new(freemkv_unlock_ld::LibreDrive::new()));
```

That single line is the whole plug. Any drive whose identity matches a bundled
profile is firmware-unlocked at drive-prep; everything else falls through to
libfreemkv's host-certificate AACS handshake.

## The `Unlocker` contract

This crate is the LibreDrive unlocker — an implementation of libfreemkv's
`Unlocker` trait. The trait is a 3-method capability contract:

- `unlock_drive` — put the drive into extended-access mode. The one required
  capability.
- `read_volume_id` — read the disc Volume ID directly, bypassing the AACS cert
  handshake. `None` → libfreemkv falls back to the cert-based read. No-op
  default.
- `set_max_read_speed` — raise the drive to its maximum read speed. No-op
  default.

libfreemkv's AACS layer is the always-present baseline; it uses an unlocker's
capabilities when one matches, and does the full cert handshake when none do.
Remove this crate and libfreemkv still compiles and rips — every capability
falls back to the OEM/baseline path.

## Scope: RAM microcode only (`#2`), never the bootloader flash (`#1`)

freemkv uploads the RAM microcode to an **already-bootloader-flashed** drive.
The permanent bootloader flash (`#1`) is the drive owner's one-time manual
step; it is **never** automated by freemkv. This crate only performs the
non-persistent `#2` step — the microcode lives in RAM and is gone on power
cycle.

<!-- TODO(owner): MakeMKV attribution + thanks -->

