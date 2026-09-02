# Module visibility rationale (`src/lib.rs`)

Why each unlocker module is `pub mod` or `mod`, and what's actually public
about it. The consumer never reaches an unlocker impl directly — only through
[`all_unlockers`] — so "public" here means "exposes something other than the
unlocker impl itself."

## `ld`

Public ONLY for its drive-profile catalog (`ld::profiles` / the `Profiles`
object) and, under the `emulation` feature, the unlock-handshake wire format
the bdemu test-emulator needs. The unlocker impl itself (`Mt1959Unlocker`) is
`pub(crate)` — clients still reach unlockers only through `all_unlockers`.
`aacs` and `css` carry no such public catalog, so they stay fully private.

## `renesas`

Public for its `is_renesas` drive-probe, which reports a dead bus as
`Err(UnlockError::Transport)` rather than "not a Renesas drive" — a
distinction the consumer needs before it can trust a negative probe result.
The unlocker impl (`Renesas`) is `pub(crate)` — reached only through
`all_unlockers`.

## `freemkv`

Carries no public catalog (the firmware self-identifies rather than matching
a bundled profile) and no emulation wire format yet, so it stays fully
private — the unlocker impl (`FreemkvUnlocker`) is reached only through
`all_unlockers`.
