# ld — the drive bus-unlock module

A drive bus-unlock module for freemkv-unlock.

freemkv-unlock defines the generic `Unlocker` contract; this module is one
implementation of it. It recognizes a bundled catalog of supported drives
(`profiles.json`) and, for a matching drive, lifts the drive-level
bus-encryption barrier so the drive serves readable sectors. Content-key
decryption is a separate concern, handled by the consumer.

Clients never name this module directly —
[libfreemkv](https://github.com/freemkv/libfreemkv) dispatches through
`freemkv_unlock::all_unlockers()`, and this module answers `unlock_features()` /
`unlock_bus()` when the drive identity is one it supports.

## Scope: non-persistent unlock only

This module performs only the **non-persistent** unlock — the access state it
sets up lives in drive RAM and is gone on power cycle. The one-time, permanent
drive preparation is the drive owner's own manual step and is **never**
automated here.

## Third-party microcode (`profiles.json`)

`profiles.json` bundles volatile, RAM-only optical-drive microcode
("LibreDrive") authored and owned by the **MakeMKV team** (GuinpinSoft inc.).
Each payload carries its own notice — *"Copyright (c) MakeMKV team, all rights
reserved."* This microcode is **third-party proprietary material and is NOT
covered by this repository's MIT license**; no ownership is claimed. See the
[`NOTICE`](./NOTICE) in this directory and the repository-root `NOTICE`. With
thanks to the MakeMKV team for [LibreDrive](http://www.makemkv.com/libredrive/).
