[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/freemkv/freemkv-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/freemkv/freemkv-unlock/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/freemkv/freemkv-unlock/branch/dev/graph/badge.svg)](https://codecov.io/gh/freemkv/freemkv-unlock)

# freemkv-unlock

The unlock layer for the freemkv toolchain.

An unlocker removes a drive-level bus-encryption barrier so the drive serves
readable (de-bused, de-scrambled) sectors. Decrypting content keys is a separate
job and belongs to the consumer.

This crate defines the `Unlocker` trait and a generic SCSI transport trait
(`ScsiTransport`), and holds the self-contained unlockers:

- `FreemkvUnlocker`: freemkv firmware drives.
- `LdUnlocker`: drives with a LibreDrive profile (see License below).
- `AacsUnlocker`: the AACS host-certificate handshake. It is built with the
  host certificates it should use.
- `DvdUnlocker`: DVD bus authentication.

The consumer ([libfreemkv](https://github.com/freemkv/libfreemkv)) depends on
this crate, assembles its own list of unlockers and drives each one through the
same trait. Clients of libfreemkv never see unlockers, just as they never see
the SCSI layer.

```rust
use freemkv_unlock::{FreemkvUnlocker, LdUnlocker, UnlockCtx, UnlockError, Unlocker};

// Try each unlocker until one claims the drive. `Ok(None)` means "not this
// unlocker's drive", so move on. Only a dead bus is an error.
let ctx = UnlockCtx::new(&drive_id, disc_kind);
let chain: [&dyn Unlocker; 2] = [&FreemkvUnlocker::new(), &LdUnlocker::new()];
for u in chain {
    match u.unlock(&mut scsi, &ctx) {
        Ok(Some(unlocked)) => return Ok(Some(unlocked)), // carries vid / bus_key
        Ok(None) => continue,
        Err(e) => return Err(e), // UnlockError::Transport
    }
}
```

`unlocker_name(&drive_id)` tells you which firmware unlocker owns a drive by
identity alone, without touching the drive.

The optional `emulation` feature exposes the LibreDrive handshake wire format
for the [bdemu](https://github.com/freemkv/bdemu) test emulator. Real clients
should not enable it.

Requires Rust 1.88 or later (`rust-version` in `Cargo.toml`). The crate is not
published on crates.io because it carries drive firmware. Depend on it by git
tag.

## License

freemkv-unlock's own source is MIT. See [LICENSE](LICENSE).

`src/ld/profiles.json` bundles volatile, RAM-only **LibreDrive** microcode
authored and owned by the **MakeMKV team** (GuinpinSoft inc.), *Copyright (c)
MakeMKV team, all rights reserved.* That microcode is third-party proprietary
material, **not** covered by the MIT license, and no ownership is claimed. See
[`NOTICE`](NOTICE). With thanks to the MakeMKV team for
[LibreDrive](http://www.makemkv.com/libredrive/).
