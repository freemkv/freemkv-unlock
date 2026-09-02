# `DriveProfile` field visibility and `allow(dead_code)`

Only `identity` and `signature` are public — they are what the catalog is
public FOR ("is this drive supported?", and the emulator's impersonation).
Everything below them is unlock MECHANISM: the MediaTek firmware image and
the per-drive vendor CDB templates. `Cargo.toml` says this crate is never
published because it carries drive firmware; re-exporting `DriveProfile`
with a `pub firmware: Vec<u8>` handed that firmware, and every vendor CDB,
to any downstream crate that called `ld::profile()`. They are `pub(crate)`
so the mechanism stays inside the unlocker.

`allow(dead_code)`: this is the on-disk catalog schema, and several
captured CDB templates have no in-crate consumer yet. They were `pub`
before, so the compiler saw the (external) use; making them `pub(crate)`
is what exposes them as unread. Deleting them would silently drop fields
from the format the profile-extraction pipeline emits.
