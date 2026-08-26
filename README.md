[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/freemkv/freemkv-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/freemkv/freemkv-unlock/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/freemkv/freemkv-unlock/branch/dev/graph/badge.svg)](https://codecov.io/gh/freemkv/freemkv-unlock)

# freemkv-unlock

The unlock layer for the freemkv toolchain.

An **unlocker removes a drive-level bus-encryption barrier** so the drive serves
readable (de-bus'd / de-scrambled) sectors. Content-key decryption is a separate
concern — the consumer's job.

This crate defines the `Unlocker` contract and a generic SCSI transport
contract, and holds the self-contained unlocker modules. The consumer
([libfreemkv](https://github.com/freemkv/libfreemkv)) depends on this crate and
dispatches through `all_unlockers()`; it never names an individual unlocker, and
clients of libfreemkv are oblivious to unlockers entirely (as they are to the
SCSI layer).

```rust
use freemkv_unlock::UnlockError;

// Drive-prep: try each unlocker's feature unlock until one claims the drive.
// `NotApplicable` means "not this unlocker's drive" — move on; a transport
// error means a dead bus — abort. `unlock_bus` follows the same contract for
// removing per-disc bus encryption.
for u in freemkv_unlock::all_unlockers() {
    match u.unlock_features(&mut scsi, &ctx) {
        Ok(unlocked) => return Ok(unlocked),
        Err(UnlockError::NotApplicable) => continue,
        Err(e) => return Err(e),
    }
}
```

To remove an unlocker, delete its module directory and its one line in
`all_unlockers()` — nothing else changes.

License: MIT.
