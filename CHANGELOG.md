# Changelog

## [1.6.15] — 2026-09-02

### Changed

- Version aligned to 1.6.15 for the unified release.

### Docs

- Added a third-party NOTICE clarifying that the LibreDrive microcode bundled in `src/ld/profiles.json` is proprietary MakeMKV material, not covered by this repository's MIT license.

## [1.6.14] — 2026-08-31

### Changed

- Version aligned to 1.6.14 for the unified release.

## [1.6.13] — 2026-08-28

### Changed

- Version aligned to 1.6.13 for the unified release.

## [1.6.12] — 2026-08-27

### Changed

- Version aligned to 1.6.12 for the unified release; no functional changes.

## [1.6.11] — 2026-08-26

### Changed

- Version aligned to 1.6.11 for the unified release. No functional changes to
  this crate; the release was driven by the libfreemkv main-feature selection
  improvements and the autorip mux-quarantine fix (see the libfreemkv and
  autorip 1.6.11 notes).

### Added

- Codecov coverage reporting and badge.
- Substantially expanded unit-test coverage.

## [1.6.10] — 2026-08-23

### Changed

- Version aligned to 1.6.10 for the unified release. No functional changes to
  this crate; the release was driven by libfreemkv (TrueHD/MLP audio now resyncs
  to the next major-sync access unit after a source transport-stream
  discontinuity, instead of splicing post-gap audio mid-stream — fixing
  decoder-choking seams on discs whose stream carries a continuity-counter gap;
  see the libfreemkv 1.6.10 notes).
- MSRV lowered from 1.97 to 1.90. The crate does not use anything newer than
  1.90 stabilized; CI's pinned toolchain and `rust-version` are updated to
  match.

## [1.6.9] — 2026-08-22

### Changed

- Version aligned to 1.6.9 for the unified release. No functional changes to
  this crate; the release was driven by autorip (automatic per-episode TV
  ripping — each episode named `S{NN}E{MM}`, with TMDB runtime-aligned episode
  numbering across multi-disc seasons — a Manual Rename option, and a unified
  per-disc staging state file — see the autorip 1.6.9 notes).

## [1.6.8] — 2026-08-21

### Changed

- Version aligned to 1.6.8 for the unified release. No functional changes to
  this crate; the release was driven by autorip (webhooks now fire per pipeline
  stage — Rip / Mux / Move — with the Rip hook firing the moment the drive is
  free again, plus a Ripper-tab activity-banner fix so it also shows during
  moves — see the autorip 1.6.8 notes).

## [1.6.7] — 2026-08-21

### Changed

- Version aligned to 1.6.7 for the unified release. No functional changes to
  this crate; the release was driven by autorip (per-webhook event selection,
  a progress bar per moved artifact, and move-queue / webhook-error fixes —
  see the autorip 1.6.7 notes).

## [1.6.6] — 2026-08-20

### Changed

- Version aligned to 1.6.6 for the unified release. No functional changes
  to this crate; the release was driven by autorip (webhooks may now target
  private/LAN addresses — see the autorip 1.6.6 notes).

## [1.6.5] — 2026-08-20

### Added

- **AACS 2.0 (P-256) drives now complete a live host-certificate
  handshake.** The elliptic-curve (P-256) authentication path is wired
  into the cert handshake for real, not left as dead code. A drive is
  first tried with the AACS 1.0 certificate (a 2.0 drive accepts it for
  the Volume ID); if the drive refuses it and the supplied host
  certificate carries AACS 2.0 credentials, the crate falls back to the
  native P-256 handshake. It is cert-agnostic — it uses whatever the host
  certificate carries, with no separate feature gate — and a bus fault on
  the 1.0 attempt short-circuits the fallback so a dead bus is not
  hammered. The 2.0 path enforces the same chain-of-trust checks as the
  1.0 path (drive-cert type gate, fatal certificate verification under the
  real 2.0 Licensing Administrator key, on-curve validation of every
  attacker-supplied point, and AGID release on every exit). The 2.0
  certificate byte layout is documented as provisional pending a genuine
  drive certificate to pin it against; a wrong layout fails closed and
  never trusts.

### Security

- **A rogue drive or bridge can no longer forge its way to a trusted bus
  key.** A drive certificate whose type was neither AACS 1.0 nor 2.0 used
  to skip Licensing Administrator verification yet still have its own key
  trusted for the bus-key signature check, letting an attacker inject a
  chosen bus key; unknown cert types are now rejected at the type gate
  before any key is trusted. ECDSA verification now validates the signer's
  public key (on-curve, in-field, not the identity point) before use — a
  key of (0,0) previously collapsed verification to a forgeable form. The
  compiled-in AACS 1.0 and 2.0 Licensing Administrator anchor keys, which
  were off-curve, are replaced with the real published keys (both
  confirmed on-curve; the 1.0 key verifies a genuine LA-signed
  certificate). The P-256 certificate-length check now matches the real
  132-byte layout, so AACS 2.0 certificates verify at all.

- **Sensitive material no longer leaks through debug output.** `Unlocked`
  (which carries the bus key and Volume ID) and `DriveProfile` (which
  carries the MediaTek drive firmware image and per-drive vendor SCSI
  templates) now use hand-written redacting `Debug` implementations
  instead of printing everything. The AACS 2.0 authentication path now
  releases the drive AGID on every failure exit, matching the 1.0 path.

### Fixed

- **A dead or failing drive bus is no longer reported as a successful
  unlock.** A transport fault during the AACS data-key read, during
  firmware-unlock disc probing, and in both MediaTek speed-probe passes
  used to be swallowed or flattened into a generic failure — in the
  firmware-unlock case surfacing as `drive_unlocked: true` on a bus that
  had actually died. These paths now abort with a transport error so the
  fault is visible instead of masquerading as clear content.

- **Transport faults are no longer misclassified as "wrong drive" or
  "bad credentials."** A dead bus on the first probe command previously
  read as "not a Renesas drive" or "not a supported DVD profile"; a bus
  that died mid-handshake was reported as a credentials rejection after
  three retries against dead hardware; and CSS bus-auth collapsed every
  fault into a generic auth failure. Each call site now honours the
  transport contract — abort on a real bus fault, fall through only on a
  genuine "not applicable." A merely short probe response is no longer
  fabricated into a transport failure, so rips that would have succeeded
  are no longer aborted.

- **A half-unlocked drive now falls through to certificate
  authentication instead of claiming the bus is clear.** The firmware
  unlocker set `drive_unlocked: true` whenever the handshake merely
  completed, ignoring the computed unlock flag; a drive returning zero
  bytes could even report a full unlock from a buffer it never wrote.
  The unlock outcome is now actually consulted, so a partial unlock
  correctly steers to the cert-auth fallback. Related read paths that
  parsed the caller's own zero-filled buffer as drive data on a CHECK
  CONDITION are fixed to inspect status and bytes transferred.

### Changed

- **Drive preparation issues 88 fewer SCSI commands per disc.** The
  probe's two passes previously walked the same 88 addresses twice; the
  redundant pass is removed.

## [1.6.4] — 2026-08-15

### Changed

- **No functional change.** This crate ships alongside the rest of freemkv at a
  matching version; its behaviour is untouched.

## [1.6.3] — 2026-08-10

### Changed

- **Housekeeping only — nothing about how a drive is unlocked has changed.** The
  cryptography and compression crates this crate builds on were moved to their
  current releases and brought into line with the versions the rest of freemkv
  uses, so one version of each is built instead of two.

## [1.6.2] — 2026-08-08

Version sync with the workspace. No functional change in this crate.

## [1.6.1] — 2026-08-07

Version sync with the workspace. No functional change in this crate.

## [1.6.0] — 2026-08-03

Version sync with the workspace. No functional change in this crate.

## [1.5.2] — 2026-07-22

### Changed

- The DVD read-unlocker (bus-auth) is renamed `CSS` → `DVD`: it reports the
  medium it unlocks, not whether a title-key crack ran. The unlocker report now
  reads `DVD: yes` on any DVD.

## [1.4.1] — 2026-07-14

Version sync with the workspace; inherits libfreemkv 1.4.1.

## [1.4.0] — 2026-07-13

Version sync with the workspace; inherits libfreemkv 1.4.0.

## [1.3.2] — 2026-07-10

Version sync with the workspace; inherits libfreemkv 1.3.2.

## [1.3.1] — 2026-07-10

### Licensing

- **Relicensed to the MIT License, from 1.3.1 onwards** (releases up to and
  including 1.3.0 remain under AGPL-3.0).

Version sync with the workspace; inherits libfreemkv 1.3.1.

## [1.3.0] — 2026-07-08

### Changed

- **`Unlocker` is now two capability methods.** `unlock_features` (drive
  riplock / speed / OEM VID at drive-prep) and `unlock_bus` (bus-encryption
  removal for the mounted disc) replace the single `matches()` + `unlock()`
  contract. Each defaults to `NotApplicable`, so an unlocker implements only the
  capabilities it actually provides.
- **`DriveId` gains a `product_id` field** carrying the SCSI INQUIRY product
  string, so consumers can match on it.
