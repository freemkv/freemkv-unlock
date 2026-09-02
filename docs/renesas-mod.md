# src/renesas/mod.rs — design notes

## `is_renesas` transport-fault handling

A TRANSPORT fault is `Err(Transport)`. It used to be folded into the same
`false` as a drive rejection, and because this probe is the first SCSI
command the unlocker issues, a dead bus read as "not a Renesas drive" — the
consumer then walked the remaining unlockers against a bus that was gone.

## `Renesas::vendor_open`

The Pioneer/Renesas vendor "open" — MakeMKV's live sequence, replicated in
full: a primary read, and on its failure a payload-less "knock" + a second
read at a different window.

  A. `READ_BUFFER 0x02/0xB0 @0x000004` (164 B) — the primary open.
  B. (only if A refuses) `WRITE_BUFFER 0x02/0x41 @0xA5AAAA` (0-byte knock)
     then `READ_BUFFER 0x02/0xB0 @0x500000` (164 B).

Success is by SCSI *status* alone (the 164-byte payload CONTENT is not
validated — verified empirically: a real drive's table and an all-zero
buffer are accepted identically as long as status is GOOD). We run the
whole A→knock→B path rather than bailing after A, because the knock is a
per-firmware fallback: some firmware revisions only answer the `0x500000`
window *after* the knock (MakeMKV issues the knock exactly when A returns
CHECK CONDITION). If NEITHER A nor B returns GOOD, the drive did not open →
defer to the next unlocker.

(There may be more than one knock offset across firmware families; only
the observed `0xA5AAAA` is issued here — add variants as they are proven.)

`Ok(true)` = opened (A or B GOOD). `Ok(false)` = neither opened (CHECK
CONDITION). `Err(Transport)` = dead bus.

## `Renesas::unlock_features`

Recognize and open a Renesas/Pioneer drive the way MakeMKV does:
  1. `READ_BUFFER 0xF1` identity gate (the `SAT` marker) — else this is
     not our drive → `NotApplicable`.
  2. the single vendor open read `READ_BUFFER 0xB0 @0x04` — GOOD status
     confirms the drive is rip-ready. A CHECK CONDITION here is exactly
     where MakeMKV gives up on the drive, so we defer to the next unlocker
     (`NotApplicable`) rather than claim a drive we could not open.

On success returns `drive_unlocked: false`: the vendor open makes the
drive readable, but AACS bus decryption is still the host cert's job (the
cert unlocker runs next), so we do not assert the bus is handled here.

## Test fixture notes

`RejectingTransport` rejects the command the way a MediaTek drive does:
ILLEGAL REQUEST. The sense is what distinguishes this from a dead bus —
the old fixture sent `sense: None`, which is the wire shape of a
TRANSPORT fault, and the test built on it asserted `NotApplicable`,
pinning exactly the misclassification this file had.

`check_condition_is_not_a_renesas_drive`: the same rejection delivered the
way a CONFORMING transport delivers it — `Ok` with a CHECK CONDITION
status — must reach the same answer. Catches dropping the `r.status == 0`
check, which would read the probe buffer's zero fill as an identity block.

`open_rejection_defers_to_next_unlocker`: a genuine Renesas drive (passes
the `0xF1` SAT gate) that REFUSES the vendor open read `RB 0xB0@0x04` with
CHECK CONDITION — the exact point where MakeMKV abandons the drive.
`unlock_features` must defer to the next unlocker (`NotApplicable`), not
claim a drive it could not open. MUTATION: dropping the `vendor_open` gate
makes this return `Ok` and wrongly claim the drive.
