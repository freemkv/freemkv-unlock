# `scsi::mock` — crate-wide mock transport

The crate-wide mock transport. Before this existed, EVERY mock in the crate
returned `Ok` with status 0 and a full `bytes_transferred` — so no test could
ever exercise the three outcomes the contract actually distinguishes, and a
whole class of transport-fault misclassification bugs sat uncaught (a dead bus
read as "this unlocker doesn't apply", a zero-filled buffer read as valid
drive data). This fixture can express all of them, and is the red-before-green
vehicle for the transport-contract fixes across ld / aacs / css / renesas.
