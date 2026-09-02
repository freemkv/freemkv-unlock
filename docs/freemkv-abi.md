# freemkv vendor ABI (READ BUFFER hijack)

Background for `src/freemkv/mod.rs`. Unlike [`crate::ld`] (MediaTek MT1959,
matched against a bundled drive profile database), a freemkv-firmware drive
needs no catalog: it answers a single vendor Identity probe with an ASCII
payload starting `"freemkv"`. That self-identification IS the detection
mechanism — there is no profile lookup here and none is needed.

## The freemkv vendor ABI (READ BUFFER hijack)

Every freemkv command hijacks the standard SCSI `READ BUFFER` (`0x3C`) in
"knock mode". The 10-byte CDB is
`3C 0E C0 DE <subfn> <state> <len_hi> <len_mid> <len_lo> 00`
— opcode `0x3C`, mode byte `0x0E`, the `C0 DE` knock, a one-byte
sub-function, a one-byte state, and a 24-bit big-endian allocation length.
(This mirrors the canonical `freemkv-firmware` `abi.rs` frame exactly; the
host must never diverge from it.)

Sub-functions (`cdb[4]`) — the numbers ARE the wire protocol and match
`freemkv-firmware`'s `abi.rs::SubFn`:
- `0x01` **Identity** — read; returns `b"freemkv"` + version, ignores state.
- `0x02` **Speed** — the state byte IS the speed cap value: `0x00` = OEM,
  `0x01`..=`0xFF` a read-speed ceiling, `0xFF` = uncapped / max. NOT a plain
  on/off toggle — see `SPEED_CAP_OEM` / `SPEED_CAP_MAX`.
- `0x03` **Region** — toggle; `state 01` = DVD RPC region-free, `00` = OEM.
- `0x04` **Raw Read** — the transport-unlock command. The state byte selects
  the firmware's cert-gate behaviour (see `RAW_READ_OFF` /
  `RAW_READ_CERT_VALID` / `RAW_READ_ACCEPT_ANY`):
    - `0x00` OEM enforcement.
    - `0x01` "cert is valid" — the drive treats host auth as already
      succeeded, so a BARE `READ DISC STRUCTURE` (`0xAD` fmt `0x80`) returns
      the Volume ID with NO cert and NO AKE. This is the path this unlocker
      drives.
    - `0x02` "accept any host cert, revoked or not" — the host still runs the
      real AKE (`0xA3`/`0xA4`) but may present a revoked cert; the drive
      accepts it. Driven by the AACS cert unlocker, not here.
- `0x09` **DumpAll** — diagnostic RAM read; 32-bit address big-endian in
  `cdb[5..9]`, returns a fixed 64-byte window.

## Fixed-length replies

EVERY knock command returns the same fixed `KNOCK_RESP_LEN`-byte data-in
response (Identity carries `b"freemkv"` + version; DumpAll carries the RAM
window; the control toggles return it zeroed). Because `0x3C` is a data-in
opcode the host MUST read that response. The Volume ID is NOT a vendor read:
after Raw Read is on, the VID comes from the STANDARD AACS
`READ DISC STRUCTURE` (`0xAD` fmt `0x80`), exactly as a stock drive would
answer an authenticated host.

A short/zero allocation on a toggle command desyncs the transfer and the
drive returns ABORTED COMMAND, then wedges the response FIFO so later
commands hang. So a toggle reads and discards these bytes; only its GOOD
status matters.

## Toggle polarity

For the plain toggle (Region) the state byte is `0x00` = OEM, `0x01` =
patched. Speed (`0x02`) carries a cap value, Raw Read (`0x04`) carries a
mode selector, and DumpAll (`0x09`) carries a 32-bit address — those three
are not plain on/off toggles.

## `read_vid` return-value semantics

`Ok(vid)` on a GOOD reply carrying at least the header + VID;
`Err(VidUnavailable)` on a CHECK CONDITION / short / all-zero read (no disc,
or Raw Read not honoured); `Err(Transport)` only on a dead bus.

## `full_unlock` sequence and failure modes

The full freemkv unlock sequence, in fixed order:
`01 Identity → 03 Region → 02 Speed → 04 01 Raw Read → bare 0xAD VID`.

Identity is a hard gate (a non-freemkv drive is `NotApplicable`). Region and
Speed are best-effort features (a firmware lacking one is logged and
skipped). Raw Read (`04 01`) and the VID read are LOAD-BEARING: this
firmware's whole purpose is the one-command VID unlock, so if Raw Read is
rejected or the bare `0xAD` returns no VID, the unlock FAILS
(`VidUnavailable`) — there is no fallback. A dead bus (`Transport`) always
aborts. On success `drive_unlocked` is true (Raw Read on ⇒ no bus
encryption; the VID and sectors come back clear).
