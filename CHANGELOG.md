# Changelog

## [1.3.0] — 2026-07-08

### Changed

- **`Unlocker` is now two capability methods.** `unlock_features` (drive
  riplock / speed / OEM VID at drive-prep) and `unlock_bus` (bus-encryption
  removal for the mounted disc) replace the single `matches()` + `unlock()`
  contract. Each defaults to `NotApplicable`, so an unlocker implements only the
  capabilities it actually provides.
- **`DriveId` gains a `product_id` field** carrying the SCSI INQUIRY product
  string, so consumers can match on it.
