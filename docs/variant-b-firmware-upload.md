# MT1959 variant B firmware upload — rationale

## `trace_step`

Trace the outcome of a best-effort firmware-upload step and swallow
everything EXCEPT a transport fault. These steps are advisory (the unlock
retries are the real gate) but their results were previously thrown away
entirely, so a firmware upload could fail end to end and leave nothing in
the log to say so — and a dead bus kept the sequence running.

## Step 1 — MODE SELECT upload

The profile's `firmware` is the exact per-drive image — extracted at the
drive's own load-CDB length (2192..2528 bytes; the old fixed 0x9C0 truncated
some drives and over-read others into blob strings). Upload all of it.
MODE SELECT(10)'s parameter-list length is 16-bit, so reject only a blob
that can't be expressed in the CDB.

## Step 4 — vendor verify (0xF1, B-only, not standard SCSI)

PER-DRIVE: take it from the profile (39 distinct values across the 140 B
drives). The const `VENDOR_VERIFY` is only a legacy fallback — it carries
one drive's token. The result used to be discarded with `let _ =` despite
the comment calling this a verify step: a corrupt upload proceeded straight
to the `do_unlock` retries with no diagnostic. There is no documented
expected payload, so the outcome is TRACED; only a dead bus aborts.

## Step 5 — unlock retries

Up to 5 attempts, then a final fatal attempt. On a successful unlock we
issue one confirmation pass; its result is intentionally best-effort — the
first call already established the unlock state, so a hiccup on the
redundant confirmation must not fail an otherwise-good unlock.
