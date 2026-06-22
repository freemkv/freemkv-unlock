# freemkv-unlock

Unlocker plugins for [libfreemkv](https://github.com/freemkv/libfreemkv).

libfreemkv ships only the pluggable `Unlocker` trait + registry and stays
firmware-clean — it contains no concrete unlock code. Each crate in this
workspace implements one unlocker and is registered into libfreemkv by a single
line in the consuming binary:

```rust
libfreemkv::register_unlocker(Box::new(my_unlocker::MyUnlocker::new()));
```

Removing an unlocker is deleting that one line and the dependency
(delete-to-comply).

## Members

Each member is a self-contained unlocker plugin — see its own README for details.

License: AGPL-3.0-only.
