use super::*;

// SECURITY REGRESSION GUARD: scans source files for a `tracing` field
// binding a forbidden key name to a value expression (only a string
// literal or `_fp` field is allowed).
#[test]
fn no_key_bytes_in_instrumentation() {
    use std::path::Path;

    // Forbidden field names whose VALUES must never be logged.
    const FORBIDDEN: &[&str] = &[
        "title_key",
        "disc_key",
        "unit_key",
        "vuk",
        "player_key",
        "bus_key",
    ];

    fn scan_dir(dir: &Path, forbidden: &[&str], violations: &mut Vec<String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path, forbidden, violations);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for (lineno, line) in src.lines().enumerate() {
                let trimmed = line.trim_start();
                // Only inspect tracing instrumentation lines.
                if !(trimmed.contains("tracing::")
                    || trimmed.starts_with("debug!")
                    || trimmed.starts_with("info!")
                    || trimmed.starts_with("warn!")
                    || trimmed.starts_with("trace!")
                    || trimmed.starts_with("error!"))
                {
                    continue;
                }
                // This guard test itself contains the forbidden names.
                if path.file_name().and_then(|n| n.to_str()) == Some("auth.rs")
                    && line.contains("FORBIDDEN")
                {
                    continue;
                }
                for &name in forbidden {
                    // A fingerprint field (`<name>_fp = ...`) is allowed;
                    // match `<name>` then `=` with a value that is not a
                    // string-literal redaction marker.
                    if let Some(idx) = line.find(name) {
                        let after = &line[idx + name.len()..];
                        let after = after.trim_start();
                        // `<name>_fp` / `<name>_id` etc. are safe.
                        if after.starts_with('_') {
                            continue;
                        }
                        // Must be a field binding `name = ...`.
                        let Some(rest) = after.strip_prefix('=') else {
                            continue;
                        };
                        let rest = rest.trim_start();
                        // Redaction string literal is the only allowed value.
                        if rest.starts_with('"') {
                            continue;
                        }
                        // Anything else (`%expr`, `?expr`, bare expr) leaks bytes.
                        violations.push(format!(
                            "{}:{}: forbidden key field `{}` logged with a value: {}",
                            path.display(),
                            lineno + 1,
                            name,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }

    // Scan this crate's `src` plus sibling workspace crates so the
    // guard covers everything that can reach CSS/AACS internals.
    // Missing sibling dirs (standalone builds) are simply skipped.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap_or(manifest);
    let mut violations = Vec::new();
    scan_dir(&manifest.join("src"), FORBIDDEN, &mut violations);
    for sibling in ["autorip", "freemkv", "freemkv-keysources"] {
        let dir = workspace.join(sibling).join("src");
        if dir.is_dir() {
            scan_dir(&dir, FORBIDDEN, &mut violations);
        }
    }
    assert!(
        violations.is_empty(),
        "key material logged in instrumentation:\n{}",
        violations.join("\n")
    );
}

#[test]
fn crypt_key_is_deterministic() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    for v in 0..32u8 {
        let r1 = crypt_key(0, v, &challenge);
        let r2 = crypt_key(0, v, &challenge);
        assert_eq!(r1, r2);
    }
}

#[test]
fn crypt_key_varies_by_variant() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    assert_ne!(crypt_key(0, 0, &challenge), crypt_key(0, 1, &challenge));
}

#[test]
fn crypt_key_varies_by_type() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    assert_ne!(crypt_key(0, 5, &challenge), crypt_key(1, 5, &challenge));
}

#[test]
fn crypt_key_nonzero() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    for v in 0..32u8 {
        assert_ne!(crypt_key(0, v, &challenge), [0u8; 5]);
    }
}

// ── CSS constant-table integrity ───────────────────────────────────────

// Each PERM_CHALLENGE row must be a permutation of indices 0..10; a
// non-permutation would drop/duplicate bytes.
#[test]
fn perm_challenge_rows_are_permutations() {
    for (row, perm) in PERM_CHALLENGE.iter().enumerate() {
        let mut seen = [false; 10];
        for &idx in perm.iter() {
            assert!(idx < 10, "PERM_CHALLENGE[{row}] index {idx} out of range");
            assert!(!seen[idx], "PERM_CHALLENGE[{row}] duplicates index {idx}");
            seen[idx] = true;
        }
        assert!(
            seen.iter().all(|&b| b),
            "PERM_CHALLENGE[{row}] misses an index"
        );
    }
}

// Each PERM_VARIANT row must map the 32 variants to 32 distinct 5-bit
// values; a collision would make two variants indistinguishable.
#[test]
fn perm_variant_rows_are_permutations_of_0_31() {
    for (row, perm) in PERM_VARIANT.iter().enumerate() {
        let mut seen = [false; 32];
        for &v in perm.iter() {
            let v = v as usize;
            assert!(v < 32, "PERM_VARIANT[{row}] value {v} out of 0..32");
            assert!(!seen[v], "PERM_VARIANT[{row}] duplicates {v}");
            seen[v] = true;
        }
        assert!(
            seen.iter().all(|&b| b),
            "PERM_VARIANT[{row}] misses a value"
        );
    }
}

// ── crypt_key behaviour ────────────────────────────────────────────────

// crypt_key's result must depend on every challenge byte: flipping any
// single byte must change the output.
#[test]
fn crypt_key_depends_on_every_challenge_byte() {
    let base: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let base_out = crypt_key(0, 5, &base);
    for i in 0..10 {
        let mut c = base;
        c[i] ^= 0x55;
        assert_ne!(
            crypt_key(0, 5, &c),
            base_out,
            "flipping challenge byte {i} did not change the bus-key derivation"
        );
    }
}

// crypt_key(0, v, ..) must be distinct for each of the 32 variants:
// bus-auth brute-forces the variant by matching against key1, so a
// collision could select the wrong one.
#[test]
fn crypt_key_type0_distinct_per_variant() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut outs = Vec::new();
    for v in 0..32u8 {
        let k = crypt_key(0, v, &challenge);
        assert!(
            !outs.contains(&k),
            "variant {v} collides with an earlier variant"
        );
        outs.push(k);
    }
}

// crypt_key's `key_type < 3` assert! (not debug_assert!) must fire in
// every profile; `expected` rejects the index-OOB panic that would follow.
#[test]
#[should_panic(expected = "crypt_key: key_type out of range")]
fn crypt_key_rejects_out_of_range_key_type() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let _ = crypt_key(3, 0, &challenge);
}

// crypt_key's `variant < 32` assert! must fire in every profile, not
// the VARIANTS/PERM_VARIANT index-OOB panic that would follow it.
#[test]
#[should_panic(expected = "crypt_key: variant out of range")]
fn crypt_key_rejects_out_of_range_variant() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let _ = crypt_key(0, 32, &challenge);
}

// ── SCSI CDB builders (MMC REPORT KEY / SEND KEY layout) ───────────────

// report_key_cdb encodes a 12-byte MMC REPORT KEY (opcode 0xA4) CDB:
// byte 0=0xA4, bytes 8-9=big-endian len, byte 10=(AGID<<6)|(format&0x3F).
#[test]
fn report_key_cdb_matches_mmc_layout() {
    let cdb = report_key_cdb(0b10, 0x04, 0x010C); // AGID=2, format=0x04, len=268
    assert_eq!(cdb[0], 0xA4, "REPORT KEY opcode");
    assert_eq!(cdb[8], 0x01, "alloc_len high byte (big-endian)");
    assert_eq!(cdb[9], 0x0C, "alloc_len low byte");
    assert_eq!(
        cdb[10],
        (0b10 << 6) | 0x04,
        "AGID in bits 6-7, format in bits 0-5"
    );
    // Every other byte must be zero.
    for (i, &b) in cdb.iter().enumerate() {
        if ![0, 8, 9, 10].contains(&i) {
            assert_eq!(b, 0, "CDB byte {i} must be zero");
        }
    }
    assert_eq!(cdb.len(), 12, "REPORT KEY is a 12-byte CDB");
}

// The key-format field is masked to 6 bits so a format with high bits
// set (e.g. 0xFF) cannot corrupt the AGID bits of byte 10.
#[test]
fn report_key_cdb_masks_format_to_6_bits() {
    let cdb = report_key_cdb(0, 0xFF, 8);
    assert_eq!(cdb[10], 0x3F, "format masked to 6 bits, AGID stays 0");
}

// send_key_cdb encodes a 12-byte MMC SEND KEY (opcode 0xA3) CDB with the
// parameter-list length at bytes 8-9 (big-endian) and AGID/format at
// byte 10.
#[test]
fn send_key_cdb_matches_mmc_layout() {
    let cdb = send_key_cdb(0b11, 0x03, 0x000C); // AGID=3, format=3, param_len=12
    assert_eq!(cdb[0], 0xA3, "SEND KEY opcode");
    assert_eq!(cdb[8], 0x00, "param_len high byte");
    assert_eq!(cdb[9], 0x0C, "param_len low byte");
    assert_eq!(
        cdb[10],
        (0b11 << 6) | 0x03,
        "AGID bits 6-7, format bits 0-5"
    );
    assert_eq!(cdb.len(), 12);
}

// Allocation length > 255 must split across bytes 8 (high) and 9 (low)
// as a 16-bit big-endian field, e.g. 0x0804 (the disc-key block size).
#[test]
fn report_key_cdb_alloc_len_is_16bit_big_endian() {
    let cdb = report_key_cdb(0, 0x00, 0x0804);
    assert_eq!(cdb[8], 0x08, "high byte of 2052-byte transfer");
    assert_eq!(cdb[9], 0x04, "low byte of 2052-byte transfer");
}

// The unlocker's user-facing name is "DVD" (the medium), not "CSS" (the
// scheme); apps render the unlocker report from this name, so it is a
// stable contract.
#[test]
fn dvd_unlocker_is_named_dvd() {
    use crate::Unlocker;
    assert_eq!(DvdUnlocker::new().name(), "DVD");
}

/// `Default` must delegate to `new()` — there is only one way to build a
/// `DvdUnlocker` (it is a unit struct), so this pins the two never drift.
#[test]
#[allow(clippy::default_constructed_unit_structs)]
fn default_matches_new() {
    let _ = DvdUnlocker::default();
    let _ = DvdUnlocker::new();
}

/// DvdUnlocker provides bus removal only — it never provides drive features.
// Defense in depth: even when the caller declares `DiscKind::Css`,
// DvdUnlocker self-verifies against GET CONFIGURATION; a BD profile
// must yield NotApplicable with no CSS CDB issued.
#[test]
fn dvd_unlocker_self_guards_against_non_dvd() {
    use crate::scsi::{DataDirection, ScsiResult};
    use crate::{DiscKind, DriveId, UnlockCtx, Unlocker};

    /// Reports a BD-ROM profile (0x0040) to GET CONFIGURATION and counts any
    /// other CDB (i.e. CSS bus-auth activity).
    struct BdTransport {
        non_config_cdbs: usize,
    }
    impl ScsiTransport for BdTransport {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            if cdb[0] == crate::scsi::SCSI_GET_CONFIGURATION {
                if data.len() >= 8 {
                    data[6] = 0x00;
                    data[7] = 0x40; // BD-ROM current profile
                }
                return Ok(ScsiResult {
                    status: 0,
                    bytes_transferred: 8,
                    sense: [0u8; 32],
                });
            }
            self.non_config_cdbs += 1;
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: 0,
                sense: [0u8; 32],
            })
        }
    }

    let id = DriveId {
        vendor_id: "FAKEVNDR".to_string(),
        ..Default::default()
    };

    let mut t = BdTransport { non_config_cdbs: 0 };
    let r = DvdUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Css));
    assert!(
        r.expect("BD profile declines, not a hard error").is_none(),
        "a BD-profile drive must be refused"
    );
    assert_eq!(
        t.non_config_cdbs, 0,
        "no CSS CDB may be issued at a non-DVD drive"
    );
}
// ── Transport-contract tests ────────────────────────────────────────────

use crate::scsi::mock::{MockTransport, Reply};
use crate::{DiscKind, DriveId, UnlockCtx, UnlockError, Unlocker};

// Defect-7 regression: a transport fault on the first probe command
// must abort as Transport, not fall through to NotApplicable (which
// let the consumer keep probing a dead bus).
#[test]
fn transport_fault_probing_for_a_dvd_aborts() {
    let id = DriveId::default();
    let mut t = MockTransport::always(Reply::TransportFault);
    let r = DvdUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Css));
    assert_eq!(r.unwrap_err(), UnlockError::Transport);
    assert_eq!(
        t.calls(),
        1,
        "must abort on the first command, not probe on"
    );
}

/// A drive that REFUSES GET CONFIGURATION (CHECK CONDITION, delivered as
/// `Ok` per the contract) is inconclusive, not a dead bus → decline. Guards
/// against over-correcting defect 7 into "any probe failure aborts the rip".
#[test]
fn check_condition_probing_for_a_dvd_declines() {
    let id = DriveId::default();
    let mut t = MockTransport::always(Reply::illegal_request());
    let r = DvdUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Css));
    assert!(r.expect("inconclusive probe declines").is_none());
}

// Defect-2 regression: a DVD is mounted, then the bus dies mid
// bus-auth — must abort as Transport, not collapse to CssAuthFailed /
// NotApplicable.
#[test]
fn transport_fault_during_bus_auth_aborts() {
    let id = DriveId::default();
    // GET CONFIGURATION reports a DVD-ROM profile (0x0010), then the bus dies.
    let mut config = vec![0u8; 8];
    config[6] = 0x00;
    config[7] = 0x10;
    let mut t = MockTransport::scripted(vec![Reply::good(config)], Reply::TransportFault);
    let r = DvdUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Css));
    assert_eq!(r.unwrap_err(), UnlockError::Transport);
}

/// The same shape with the drive REFUSING the bus-auth commands: a CSS
/// auth failure is a fall-through, not an abort.
#[test]
fn drive_refusing_bus_auth_is_not_applicable() {
    let id = DriveId::default();
    let mut config = vec![0u8; 8];
    config[7] = 0x10;
    let mut t = MockTransport::scripted(vec![Reply::good(config)], Reply::illegal_request());
    let r = DvdUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Css));
    assert!(r.expect("a refused bus-auth declines").is_none());
}

// A CHECK CONDITION on AGID allocation must not let the handshake carry
// on off the caller's own zero-filled buffer; catches a dropped
// `status` check in `css_scsi`.
#[test]
fn agid_allocation_check_condition_fails_the_auth() {
    // 4 AGID invalidations are best-effort; the 5th command is the alloc.
    let mut t = MockTransport::scripted(
        vec![
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
        ],
        Reply::illegal_request(),
    );
    let e = establish_authenticated_session(&mut t).expect_err("refused alloc");
    assert!(matches!(e, Error::CssAuthFailed));
}

// Defect 18: an AGID lost to a failed challenge must be RELEASED
// (REPORT KEY format 0x3F), not abandoned, even though a drive's four
// AGIDs self-heal on the next session's invalidation pass.
#[test]
fn a_failed_handshake_releases_the_agid_it_allocated() {
    let mut t = MockTransport::scripted(
        vec![
            Reply::good(vec![0u8; 8]), // 4 × AGID invalidate
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]), // AGID allocated
        ],
        Reply::illegal_request(), // every challenge step is refused
    );
    establish_authenticated_session(&mut t).expect_err("refused challenge");
    let last = t.cdbs.last().expect("commands were issued");
    assert_eq!(last[0], crate::scsi::SCSI_REPORT_KEY);
    assert_eq!(last[10] & 0x3F, 0x3F, "AGID released on the failure path");
}

/// A short AGID-allocation response is equally unusable — the AGID would be
/// read out of bytes the drive never sent.
#[test]
fn short_agid_allocation_fails_the_auth() {
    let mut t = MockTransport::scripted(
        vec![
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
            Reply::good(vec![0u8; 8]),
        ],
        Reply::short(vec![0u8; 8], 3),
    );
    let e = establish_authenticated_session(&mut t).expect_err("short alloc");
    assert!(matches!(e, Error::CssAuthFailed));
}

// ── authenticate_with_agid step failures ────────────────────────────────

/// The drive refuses the host-challenge SEND KEY (step 1) — the very first
/// command `authenticate_with_agid` issues.
#[test]
fn host_challenge_send_failure_fails_the_auth() {
    let mut t = MockTransport::scripted(vec![Reply::illegal_request()], Reply::illegal_request());
    let e = authenticate_with_agid(&mut t, 0).expect_err("refused host challenge");
    assert!(matches!(e, Error::CssAuthFailed));
    assert_eq!(t.calls(), 1, "must not proceed past the first refused step");
}

/// The host challenge SEND KEY succeeds but the Key1 REPORT KEY (step 2) is
/// refused.
#[test]
fn key1_report_failure_fails_the_auth() {
    let mut t = MockTransport::scripted(
        vec![Reply::good(vec![]), Reply::illegal_request()],
        Reply::illegal_request(),
    );
    let e = authenticate_with_agid(&mut t, 0).expect_err("refused Key1 report");
    assert!(matches!(e, Error::CssAuthFailed));
    assert_eq!(t.calls(), 2);
}

/// Both SCSI steps succeed but the drive's Key1 does not match any of the
/// 32 CryptKey variants for the (randomly generated) host challenge — the
/// brute-force loop exhausts and `variant.ok_or(CssAuthFailed)` fires.
#[test]
fn key1_matching_no_variant_fails_the_auth() {
    let mut t = MockTransport::scripted(
        vec![Reply::good(vec![]), Reply::good(vec![0xABu8; 12])],
        Reply::illegal_request(),
    );
    let e = authenticate_with_agid(&mut t, 0).expect_err("no variant matches");
    assert!(matches!(e, Error::CssAuthFailed));
    assert_eq!(
        t.calls(),
        2,
        "the brute-force loop issues no further SCSI commands"
    );
}

// Host challenge + Key1 succeed but the drive-challenge REPORT KEY
// (step 3) is refused; distinct from the step-2 and step-4 failure
// tests, each pinning a different `css_scsi` call site's `?`.
#[test]
fn drive_challenge_report_failure_fails_the_auth() {
    struct FailAtDriveChallenge(FakeDvdDrive);
    impl ScsiTransport for FailAtDriveChallenge {
        fn execute(
            &mut self,
            cdb: &[u8],
            dir: DataDirection,
            data: &mut [u8],
            timeout_ms: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            if cdb[0] == crate::scsi::SCSI_REPORT_KEY && cdb[10] & 0x3F == 0x01 {
                return Ok(crate::scsi::ScsiResult {
                    status: 0x02,
                    bytes_transferred: 0,
                    sense: [0u8; 32],
                });
            }
            self.0.execute(cdb, dir, data, timeout_ms)
        }
    }
    let mut t = FailAtDriveChallenge(FakeDvdDrive {
        variant: 4,
        host_challenge: [0u8; 10],
    });
    let e = authenticate_with_agid(&mut t, 0).expect_err("refused drive challenge");
    assert!(matches!(e, Error::CssAuthFailed));
}

/// Host challenge, Key1, and the drive challenge all succeed, but the
/// Key2 SEND KEY (step 4, the last command in the handshake) is refused.
#[test]
fn key2_send_failure_fails_the_auth() {
    struct FailAtKey2Send(FakeDvdDrive);
    impl ScsiTransport for FailAtKey2Send {
        fn execute(
            &mut self,
            cdb: &[u8],
            dir: DataDirection,
            data: &mut [u8],
            timeout_ms: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            if cdb[0] == crate::scsi::SCSI_SEND_KEY && cdb[10] & 0x3F == 0x03 {
                return Ok(crate::scsi::ScsiResult {
                    status: 0x02,
                    bytes_transferred: 0,
                    sense: [0u8; 32],
                });
            }
            self.0.execute(cdb, dir, data, timeout_ms)
        }
    }
    let mut t = FailAtKey2Send(FakeDvdDrive {
        variant: 4,
        host_challenge: [0u8; 10],
    });
    let e = authenticate_with_agid(&mut t, 0).expect_err("refused Key2 send");
    assert!(matches!(e, Error::CssAuthFailed));
}

// ── read_disc_key ────────────────────────────────────────────────────────

/// The best-effort disc-key REPORT KEY is refused — `read_disc_key` must
/// surface the failure to its caller (who treats it as non-fatal), not
/// silently return `Ok`.
#[test]
fn read_disc_key_refused_is_an_error() {
    let mut t = MockTransport::always(Reply::illegal_request());
    let e = read_disc_key(&mut t, 0).expect_err("drive refused disc-key read");
    assert!(matches!(e, Error::CssAuthFailed));
}

/// A transport fault reading the disc key must classify as a transport
/// failure, not a generic auth failure.
#[test]
fn read_disc_key_transport_fault_is_transport_failure() {
    let mut t = MockTransport::always(Reply::TransportFault);
    let e = read_disc_key(&mut t, 0).expect_err("dead bus");
    assert!(e.is_transport_failure());
}

// ── Full happy-path bus-auth ────────────────────────────────────────────

// A fake drive that plays its half of the CSS handshake for real:
// answers Key1 honestly, and DVD/disc-key probes as success.
struct FakeDvdDrive {
    variant: u8,
    host_challenge: [u8; 10],
}

impl ScsiTransport for FakeDvdDrive {
    fn execute(
        &mut self,
        cdb: &[u8],
        _dir: DataDirection,
        data: &mut [u8],
        _timeout_ms: u32,
    ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
        use crate::scsi::ScsiResult;
        let ok = |bytes_transferred: usize| ScsiResult {
            status: 0,
            bytes_transferred,
            sense: [0u8; 32],
        };
        match cdb[0] {
            crate::scsi::SCSI_GET_CONFIGURATION => {
                data[6] = 0x00;
                data[7] = 0x10; // DVD-ROM current profile
                Ok(ok(8))
            }
            crate::scsi::SCSI_SEND_KEY => {
                let format = cdb[10] & 0x3F;
                if format == 0x01 {
                    // Host challenge: capture it for the Key1 answer.
                    for i in 0..10 {
                        self.host_challenge[i] = data[4 + (9 - i)];
                    }
                }
                // format 0x03 (Key2) is accepted unconditionally: the
                // real handshake never verifies it drive-side in this
                // primitive (ASF=1 is set on the drive's own say-so).
                Ok(ok(0))
            }
            crate::scsi::SCSI_REPORT_KEY => {
                match cdb[10] & 0x3F {
                    0x00 => {
                        // Allocate AGID 0.
                        data[7] = 0x00;
                        Ok(ok(8))
                    }
                    0x02 => {
                        // Key1, honestly derived from the captured challenge.
                        let key1 = crypt_key(0, self.variant, &self.host_challenge);
                        for i in 0..5 {
                            data[4 + (4 - i)] = key1[i];
                        }
                        Ok(ok(12))
                    }
                    0x01 => {
                        // Drive challenge (arbitrary, fixed).
                        let drive_challenge: [u8; 10] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
                        for i in 0..10 {
                            data[4 + (9 - i)] = drive_challenge[i];
                        }
                        Ok(ok(16))
                    }
                    _ => Ok(ok(0)), // 0x3F release, best-effort
                }
            }
            crate::scsi::SCSI_READ_DISC_STRUCTURE => Ok(ok(2048 + 4)),
            _ => Ok(ok(0)),
        }
    }
}

// End-to-end happy path for the bus-auth handshake (AGID, challenge,
// Key1/Key2, disc-key REPORT KEY), exercising the `Ok` returns that
// the failure-path tests above never reach.
#[test]
fn full_bus_auth_and_disc_key_succeed() {
    let mut t = FakeDvdDrive {
        variant: 7,
        host_challenge: [0u8; 10],
    };
    let agid = establish_authenticated_session(&mut t).expect("full bus-auth handshake succeeds");
    assert_eq!(agid, 0);
    read_disc_key(&mut t, agid).expect("disc-key REPORT KEY succeeds");
}

// The same happy path through the public `unlock` entry point, proving it
// returns `Some(Unlocked::default())` on success — the path every
// failure-injection test above deliberately avoids.
#[test]
fn dvd_unlocker_succeeds_end_to_end() {
    let id = DriveId::default();
    let mut t = FakeDvdDrive {
        variant: 3,
        host_challenge: [0u8; 10],
    };
    let r = DvdUnlocker::new().unlock(&mut t, &UnlockCtx::new(&id, DiscKind::Css));
    let unlocked = r
        .expect("full unlock succeeds")
        .expect("DVD bus-auth unlocks the drive");
    assert!(unlocked.vid.is_none(), "CSS yields no Volume ID");
    assert!(unlocked.bus_key.is_none(), "CSS yields no AACS bus key");
}

/// `unlock_css_reads` (the crate-level public entry point, distinct from
/// the `DvdUnlocker` wrapper) also succeeds end to end.
#[test]
fn unlock_css_reads_succeeds() {
    let mut t = FakeDvdDrive {
        variant: 11,
        host_challenge: [0u8; 10],
    };
    // unlock_css_reads doesn't probe GET CONFIGURATION itself (that's
    // DvdUnlocker's job); it goes straight to bus-auth.
    unlock_css_reads(&mut t, 0).expect("css bus-auth + best-effort disc key succeed");
}

// A drive whose bus-auth succeeds but refuses the best-effort disc-key
// REPORT KEY; `unlock_css_reads_inner` must swallow that failure since
// the read barrier is already open from bus-auth.
struct DiscKeyRefusingDrive(FakeDvdDrive);

impl ScsiTransport for DiscKeyRefusingDrive {
    fn execute(
        &mut self,
        cdb: &[u8],
        dir: DataDirection,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
        if cdb[0] == crate::scsi::SCSI_READ_DISC_STRUCTURE {
            return Ok(crate::scsi::ScsiResult {
                status: 0x02,
                bytes_transferred: 0,
                sense: [0u8; 32],
            });
        }
        self.0.execute(cdb, dir, data, timeout_ms)
    }
}

#[test]
fn disc_key_refusal_is_non_fatal_to_the_overall_unlock() {
    let mut t = DiscKeyRefusingDrive(FakeDvdDrive {
        variant: 5,
        host_challenge: [0u8; 10],
    });
    unlock_css_reads(&mut t, 0)
        .expect("bus-auth succeeded; a refused best-effort disc-key read must not fail it");
}

// `crypt_key`'s key_type==2 arm (`PERM_VARIANT[1]`) has no production
// caller (only 0 and 1 are invoked from `authenticate_with_agid`) but
// is a pure, directly-testable function.
#[test]
fn crypt_key_type2_is_deterministic_and_distinct_from_type1() {
    let challenge: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let a = crypt_key(2, 9, &challenge);
    let b = crypt_key(2, 9, &challenge);
    assert_eq!(a, b, "crypt_key(2, ..) must be deterministic");
    assert_ne!(
        crypt_key(1, 9, &challenge),
        crypt_key(2, 9, &challenge),
        "key_type 1 and 2 must diverge (distinct PERM_VARIANT rows)"
    );
}

// ── Stop (stop-design-v5 §2.3, ST-U1) ───────────────────────────────────

/// A drive that completes the CSS bus-auth for real: it answers Key1 for the
/// host challenge under `variant`, serves a challenge, and allocates AGID 1.
struct CssEmu {
    variant: u8,
    host_challenge: [u8; 10],
    /// Answer Key1 with zeros, which matches no variant → CssAuthFailed.
    bad_key1: bool,
}

impl ScsiTransport for CssEmu {
    fn execute(
        &mut self,
        cdb: &[u8],
        _dir: DataDirection,
        data: &mut [u8],
        _timeout_ms: u32,
    ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
        let mut r = vec![0u8; data.len()];
        match (cdb[0], cdb[10] & 0x3F) {
            (crate::scsi::SCSI_REPORT_KEY, 0x00) => r[7] = 1 << 6, // AGID 1
            (crate::scsi::SCSI_REPORT_KEY, 0x02) if !self.bad_key1 => {
                let k = crypt_key(0, self.variant, &self.host_challenge);
                (0..5).for_each(|j| r[4 + j] = k[4 - j]);
            }
            (crate::scsi::SCSI_SEND_KEY, 0x01) => {
                (0..10).for_each(|i| self.host_challenge[i] = data[4 + 9 - i]);
            }
            _ => {}
        }
        if cdb[0] != crate::scsi::SCSI_SEND_KEY {
            data.copy_from_slice(&r);
        }
        Ok(crate::scsi::ScsiResult {
            status: 0,
            bytes_transferred: data.len(),
            sense: [0u8; 32],
        })
    }
}

fn css_emu() -> CssEmu {
    CssEmu {
        variant: 7,
        host_challenge: [0u8; 10],
        bad_key1: false,
    }
}

// UT4 / G2 (stop-design-v5 §5.2, D9 "Keep holding it"): on success the AGID is
// `defuse`d, so it is still held for `read_disc_key` and never released.
// Per design D9; do not change without a design citation proving otherwise.
#[test]
fn css_success_keeps_agid() {
    use crate::scsi::mock::{StopFake, agid_ledger, is_agid_release};
    let mut t = StopFake::new(css_emu());
    unlock_css_reads(&mut t, 0).expect("the bus-auth completes");
    let (allocs, held) = agid_ledger(&t.log);
    assert_eq!(
        (allocs, held),
        (1, true),
        "one AGID, still held after success"
    );
    assert!(t.cleanups().is_empty(), "no release on success");
    let execs = t.execs();
    let alloc = execs.iter().position(|c| c[0] == 0xA4 && c[10] & 0x3F == 0);
    let after = &execs[alloc.expect("allocated") + 1..];
    assert!(
        !after.iter().any(|c| is_agid_release(c)),
        "no 0x3F after success"
    );
    let disc_key = after.last().expect("the disc-key read follows");
    assert_eq!(
        (disc_key[0], disc_key[7]),
        (0xAD, 0x02),
        "READ DVD STRUCTURE fmt 2"
    );
    assert_eq!(disc_key[10], 1 << 6, "issued under the still-held AGID 1");
}

// SS-7 (evidence): a CSS challenge that fails after allocation releases the
// AGID exactly once, through `execute_cleanup`, even when a Stop caused it.
#[test]
fn css_failed_challenge_releases_agid_once_via_cleanup() {
    use crate::scsi::mock::{StopFake, agid_ledger};
    let stop_at_challenge: fn(&[u8]) -> bool =
        |c| c[0] == crate::scsi::SCSI_SEND_KEY && c[10] & 0x3F == 0x01;
    for cancel in [false, true] {
        let mut emu = css_emu();
        if !cancel {
            emu.bad_key1 = true;
        }
        let mut t = StopFake::new(emu);
        if cancel {
            t.cancel_after = Some(stop_at_challenge);
        }
        let e = establish_authenticated_session(&mut t).expect_err("auth fails");
        assert_eq!(e.is_transport_failure(), cancel, "a Stop is a refusal");
        assert_eq!(agid_ledger(&t.log), (1, false), "cancel={cancel}");
        assert_eq!(
            t.cleanups().len(),
            1,
            "exactly one release, cancel={cancel}"
        );
    }
}

// UT5 (stop-design-v5 §5.2): "zero invalidate CDBs after a cancel" — the
// pre-allocation invalidate loop uses `execute`, so a Stop refuses it.
#[test]
fn invalidate_loops_refused_after_cancel() {
    use crate::scsi::mock::StopFake;
    let mut t = StopFake::new(css_emu());
    t.cancelled = true;
    let e = establish_authenticated_session(&mut t).expect_err("cancelled");
    assert!(e.is_transport_failure());
    assert!(
        t.execs().is_empty(),
        "no CDB reached the drive: {:?}",
        t.log
    );
    assert!(
        t.cleanups().is_empty(),
        "nothing allocated, nothing released"
    );
}
