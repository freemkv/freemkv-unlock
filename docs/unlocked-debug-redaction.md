# Why `Unlocked`'s `Debug` impl is hand-written

`Unlocked` is the public carrier that leaves this crate, and both `bus_key`
(the AACS bus key) and `vid` (the Volume ID that feeds VUK derivation) are key
material that must never reach a log or a test-failure message in plaintext.
The `AacsAuth` / `CertHandshake` siblings already redact; a derived `Debug`
here would print the very bytes they hide.

Presence is still observable (`Some`/`None`) so a log can say WHETHER a key
was obtained without revealing WHAT it is.
