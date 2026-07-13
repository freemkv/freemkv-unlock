# Changelog

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
