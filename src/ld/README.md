# ld — the LibreDrive unlocker

The **LibreDrive** unlocker module for freemkv-unlock.

freemkv-unlock defines the generic `Unlocker` contract; this module is one
implementation of it. It recognizes a bundled catalog of supported drives
(`profiles.json`) and, for a matching drive, lifts the drive-level
bus-encryption barrier so the drive serves readable sectors. Content-key
decryption is a separate concern, handled by the consumer.

Clients never name this module directly —
[libfreemkv](https://github.com/freemkv/libfreemkv) dispatches through
`freemkv_unlock::all_unlockers()`, and this module answers `matches()` /
`unlock()` when the drive identity is one it supports.

## Scope: non-persistent unlock only

This module performs only the **non-persistent** unlock — the access state it
sets up lives in drive RAM and is gone on power cycle. The one-time, permanent
drive preparation is the drive owner's own manual step and is **never**
automated here.

## Credits

LibreDrive was created by **Mike Chen** and the **MakeMKV team**. This module
builds on their work — our thanks and full credit to them for the LibreDrive
capabilities.
