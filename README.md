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
for u in freemkv_unlock::all_unlockers() {
    if u.matches(&ctx) {
        return u.unlock(&mut scsi, &ctx);
    }
}
```

To remove an unlocker, delete its module directory and its one line in
`all_unlockers()` — nothing else changes.

License: AGPL-3.0-only.
