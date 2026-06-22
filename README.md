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

<!-- TODO(owner): add MakeMKV / LibreDrive attribution. -->
