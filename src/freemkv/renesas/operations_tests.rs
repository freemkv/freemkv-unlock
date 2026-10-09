// Execute generated instructions; mock only the OEM call boundaries.
use super::*;
use std::collections::BTreeMap;
const ORIGIN: u32 = 0xa08000;
const HELPER: u32 = 0x412000;
const INVALID: u32 = 0x413000;
struct Vm {
    m: BTreeMap<u32, u8>,
    r: [u32; 8],
}
impl Vm {
    fn put(&mut self, a: u32, b: &[u8]) {
        for (i, v) in b.iter().enumerate() {
            self.m.insert(a + i as u32, *v);
        }
    }
    fn b(&self, a: u32) -> u8 {
        *self.m.get(&a).unwrap_or_else(|| panic!("unmapped {a:x}"))
    }
    fn l(&self, a: u32) -> u32 {
        u32::from_be_bytes(std::array::from_fn(|i| self.b(a + i as u32)))
    }
    fn push(&mut self, v: u32) {
        self.r[7] -= 4;
        self.put(self.r[7], &v.to_be_bytes());
    }
    fn pop(&mut self) -> u32 {
        let v = self.l(self.r[7]);
        self.r[7] += 4;
        v
    }
}
fn execute(op: Operation, failed: bool, foreign: bool) -> (bool, Vec<u8>) {
    execute_command(op, failed, foreign, op.cdb(), true)
}
fn execute_command(
    op: Operation,
    failed: bool,
    foreign: bool,
    cdb: [u8; 10],
    expects_call: bool,
) -> (bool, Vec<u8>) {
    execute_from_policy(op, failed, foreign, cdb, expects_call, false, false)
}
fn execute_from_policy(
    op: Operation,
    failed: bool,
    foreign: bool,
    cdb: [u8; 10],
    expects_call: bool,
    suppressed: bool,
    foreign_policy: bool,
) -> (bool, Vec<u8>) {
    execute_at_sites(
        op,
        failed,
        foreign,
        cdb,
        expects_call,
        (&Sites::fixture(), suppressed, foreign_policy),
    )
}
fn execute_at_sites(
    op: Operation,
    failed: bool,
    foreign: bool,
    cdb: [u8; 10],
    expects_call: bool,
    policy: (&Sites, bool, bool),
) -> (bool, Vec<u8>) {
    execute_with_read_state(
        op,
        failed,
        foreign,
        cdb,
        expects_call,
        (policy.0, policy.1, policy.2, 0),
    )
}
fn execute_with_read_state(
    op: Operation,
    failed: bool,
    foreign: bool,
    cdb: [u8; 10],
    expects_call: bool,
    policy: (&Sites, bool, bool, u8),
) -> (bool, Vec<u8>) {
    execute_with_wait(
        op,
        failed,
        foreign,
        cdb,
        expects_call,
        policy,
        (None, false),
    )
}
fn execute_with_wait<const N: usize>(
    op: Operation,
    failed: bool,
    foreign: bool,
    cdb: [u8; N],
    expects_call: bool,
    policy: (&Sites, bool, bool, u8),
    wait: (Option<usize>, bool),
) -> (bool, Vec<u8>) {
    let (sites, suppressed, foreign_policy, read_state) = policy;
    let vid_request = N == 12;
    let security_table: Vec<u8> = (0..sites.table_length).map(|i| (i % 251) as u8).collect();
    let t = assemble(
        0x411000,
        HELPER,
        INVALID,
        sites,
        op,
        String::new(),
        &security_table,
    )
    .unwrap();
    let mut b = t.bytes.clone();
    for f in &t.relocations {
        let addr = ORIGIN + f.addend - if f.controller_relative { 0xa00000 } else { 0 };
        b[f.offset..f.offset + 4].copy_from_slice(&addr.to_be_bytes());
    }
    let original = [
        0x900, 0x2000, 0x22334455, 0x33445566, 0x44556677, 0x55667788, 0x66778899, 0x7000,
    ];
    let mut v = Vm {
        m: BTreeMap::new(),
        r: original,
    };
    v.put(ORIGIN, &b);
    let policy = sites.policy_table(ORIGIN, b.len());
    let initial_policy = if foreign_policy {
        0xdeadbeef
    } else if suppressed {
        policy
    } else {
        sites.security_table
    };
    v.put(sites.security_slot, &initial_policy.to_be_bytes());
    for (i, expected) in security_table.iter().enumerate() {
        if !(0x100..0x104).contains(&i) {
            assert_eq!(v.b(policy + i as u32), *expected);
        }
    }
    let eligibility = v.l(policy + 0x100);
    assert_eq!(
        (0..4).map(|i| v.b(eligibility + i)).collect::<Vec<_>>(),
        [0x1a, 0x80, 0x54, 0x70]
    );
    v.put(0x10, &(0..16).map(|i| i * 13 + 1).collect::<Vec<u8>>());
    v.put(0x2000, &cdb);
    v.put(sites.loaded, &[0x5a, 1, 0, 0xa5]);
    v.put(sites.reset.cpu_address, &sites.reset.expected);
    let g = sites.acquisition.clone();
    v.put(
        g.cpu_address,
        &if foreign {
            0xdeadbeefu32.to_be_bytes().to_vec()
        } else {
            g.expected.clone()
        },
    );
    v.put(sites.vid.status, &[read_state]);
    v.put(sites.vid.source, &(1..=16).collect::<Vec<u8>>());
    let mut pc = ORIGIN + if vid_request { t.vid_wrapper_offset } else { 0 };
    let mut zero = false;
    let mut carry = false;
    v.put(sites.read_engine_state, &[read_state]);
    let mut invalid = false;
    let mut reply = vec![];
    let mut called = false;
    let mut delay_calls = 0;
    for _ in 0..10000 {
        let x = v.b(pc);
        let y = v.b(pc + 1);
        match (x, y) {
            (1, 0) => {
                let z = v.b(pc + 2);
                let r = v.b(pc + 3);
                let i = (r & 7) as usize;
                match z {
                    0x6d => {
                        if r & 0xf0 == 0xf0 {
                            v.push(v.r[i]);
                        } else {
                            v.r[i] = v.pop();
                        }
                        pc += 4;
                    }
                    0x6b => {
                        let at = v.l(pc + 4);
                        if r & 0x80 != 0 {
                            v.put(at, &v.r[i].to_be_bytes());
                        } else {
                            v.r[i] = v.l(at);
                        }
                        pc += 8;
                    }
                    0x69 => {
                        assert_eq!(r, 0xf2);
                        v.put(v.r[7], &v.r[2].to_be_bytes());
                        pc += 4;
                    }
                    _ => panic!("opcode {z:x}"),
                }
            }
            (0x6e, 0x1a) => {
                let off = u16::from_be_bytes([v.b(pc + 2), v.b(pc + 3)]);
                v.r[2] = (v.r[2] & !255) | v.b(v.r[1] + off as u32) as u32;
                pc += 4;
            }
            (0x6f, 0x13) => {
                let off = u16::from_be_bytes([v.b(pc + 2), v.b(pc + 3)]);
                let at = v.r[1] + u32::from(off);
                v.r[3] =
                    (v.r[3] & 0xffff0000) | u32::from(u16::from_be_bytes([v.b(at), v.b(at + 1)]));
                pc += 4;
            }
            (0x17, 0x73) => {
                v.r[3] &= 0xffff;
                pc += 2;
            }
            (0xea, _) => {
                v.r[2] = (v.r[2] & !255) | u32::from(v.r[2] as u8 & y);
                zero = v.r[2] as u8 == 0;
                pc += 2;
            }
            (0x6e, 0xca) => {
                let off = u16::from_be_bytes([v.b(pc + 2), v.b(pc + 3)]);
                v.put(v.r[4] + u32::from(off), &[v.r[2] as u8]);
                pc += 4;
            }
            (0xaa, _) => {
                zero = v.r[2] as u8 == y;
                carry = (v.r[2] as u8) < y;
                pc += 2;
            }
            (0x6a, 0x2a) => {
                v.r[2] = (v.r[2] & !255) | v.b(v.l(pc + 2)) as u32;
                pc += 6;
            }
            (0x7a, _) => {
                let n = v.l(pc + 2);
                if y & 0xf0 == 0x30 {
                    v.r[(y & 7) as usize] = v.r[(y & 7) as usize].wrapping_sub(n);
                } else if y & 0xf0 == 0x20 {
                    zero = v.r[(y & 7) as usize] == n;
                    carry = v.r[(y & 7) as usize] < n;
                } else {
                    v.r[y as usize] = n;
                }
                pc += 6;
            }
            (0x44 | 0x45 | 0x46 | 0x47 | 0x40, _) => {
                let take = x == 0x40
                    || (x == 0x46 && !zero)
                    || (x == 0x47 && zero)
                    || (x == 0x44 && !carry)
                    || (x == 0x45 && carry);
                pc = ((pc + 2) as i64 + if take { y as i8 as i64 } else { 0 }) as u32;
            }
            (0x58, _) => {
                let take = y == 0
                    || (y == 0x60 && !zero)
                    || (y == 0x70 && zero)
                    || (y == 0x50 && carry)
                    || (y == 0x40 && !carry);
                let d = i16::from_be_bytes([v.b(pc + 2), v.b(pc + 3)]);
                pc = ((pc + 4) as i64 + if take { d as i64 } else { 0 }) as u32;
            }
            (0x1a, 0x80 | 0x91 | 0xa2) => {
                v.r[(y & 7) as usize] = 0;
                zero = true;
                pc += 2;
            }
            (0x18, 0x88 | 0x99 | 0xaa) => {
                v.r[(y & 7) as usize] &= !255;
                zero = true;
                pc += 2;
            }
            (0x1b, 0x05) => {
                v.r[5] -= 1;
                pc += 2;
            }
            (0x0d, 0x00) => {
                zero = v.r[0] as u16 == 0;
                pc += 2;
            }
            (0x1b, 0x97) => {
                v.r[7] -= 4;
                pc += 2;
            }
            (0x0b, 0x97) => {
                v.r[7] += 4;
                pc += 2;
            }
            (0x0f, _) if y & 0x80 != 0 => {
                v.r[(y & 7) as usize] = v.r[((y >> 4) & 7) as usize];
                pc += 2;
            }
            (0x0c, 0x88) => {
                zero = v.r[0] as u8 == 0;
                pc += 2;
            }
            (0xfa, _) => {
                v.r[2] = (v.r[2] & !255) | y as u32;
                pc += 2;
            }
            (0xf8, _) => {
                v.r[0] = (v.r[0] & !255) | y as u32;
                pc += 2;
            }
            (0x6a, 0x8a) => {
                let at = u16::from_be_bytes([v.b(pc + 2), v.b(pc + 3)]) as u32;
                v.put(at, &[v.r[2] as u8]);
                pc += 4;
            }
            (0x6a, 0xaa) => {
                let at = v.l(pc + 2);
                v.put(at, &[v.r[2] as u8]);
                pc += 6;
            }
            (0x5e, _) => {
                let target = v.l(pc) & 0xffffff;
                match target {
                    address if address == sites.scheduler_delay => {
                        delay_calls += 1;
                        assert!(delay_calls <= 500, "firmware wait exceeded its budget");
                        assert_eq!(v.r[0], 10, "delay is ten OEM ticks");
                        assert_eq!(
                            v.l(sites.security_slot),
                            initial_policy,
                            "wait must precede policy writes"
                        );
                        assert_eq!(
                            v.l(g.cpu_address),
                            if foreign {
                                0xdeadbeef
                            } else {
                                u32::from_be_bytes(g.expected[..].try_into().unwrap())
                            }
                        );
                        // Exercise caller-clobbered registers; CDB pointer must survive.
                        v.r[0] = if wait.1 { 0xffe7 } else { 0 };
                        v.r[1] = 0xdead0001;
                        v.r[2] = 0xdead0002;
                        if wait.0 == Some(delay_calls) {
                            v.put(sites.read_engine_state, &[9]);
                        }
                    }
                    address if address == sites.dispatcher => {
                        called = true;
                        for dest in sites.buffers {
                            for i in 0..16 {
                                assert_eq!(v.b(dest + i), v.b(0x10 + i));
                            }
                        }
                        assert_eq!(v.l(v.r[1]), 0x00cf0000);
                        assert_eq!((v.r[0], v.r[2]), (0, 0));
                        let table = v.l(g.cpu_address);
                        let off = cdb[6] == crate::protocol::STATE_OFF;
                        assert_eq!(
                            v.l(sites.security_slot),
                            if off { policy } else { sites.security_table },
                            "policy must change before OEM initialization"
                        );
                        if off {
                            assert_ne!(
                                table,
                                u32::from_be_bytes(g.expected[..].try_into().unwrap())
                            );
                            let callback = v.l(table + 0x10);
                            for off in [0x1a, 0x24, 0x2e, 0x38, 0x42] {
                                assert_eq!(v.l(table + off), callback);
                            }
                            assert_eq!(
                                (0..16).map(|i| v.b(callback + i)).collect::<Vec<_>>(),
                                [
                                    0xfa,
                                    1,
                                    0x6a,
                                    0x8a,
                                    (sites.checked >> 8) as u8,
                                    sites.checked as u8,
                                    0x18,
                                    0xaa,
                                    0x6a,
                                    0x8a,
                                    (sites.result >> 8) as u8,
                                    sites.result as u8,
                                    0x1a,
                                    0x80,
                                    0x54,
                                    0x70
                                ]
                            );
                        } else {
                            assert_eq!(
                                table,
                                u32::from_be_bytes(g.expected[..].try_into().unwrap())
                            );
                        }
                        // OEM initialization invalidates the cache. An eligible OEM drive
                        // recomputes one, while the persistent method supplies zero.
                        v.put(sites.loaded, &[0, 0, 0]);
                        v.put(sites.checked, &[1, u8::from(!off)]);
                        v.r[0] = u32::from(failed);
                    }
                    HELPER => {
                        assert_eq!(
                            v.l(g.cpu_address),
                            u32::from_be_bytes(g.expected[..].try_into().unwrap()),
                            "callback must be restored before reply"
                        );
                        assert_eq!(v.r[0], original[0]);
                        assert_eq!(v.r[1] as u8, 0);
                        let length = if vid_request {
                            usize::from(u16::from_be_bytes([cdb[8], cdb[9]])).min(36)
                        } else {
                            op.length()
                        };
                        assert_eq!(v.l(v.r[7]), length as u32);
                        reply = (0..length as u32)
                            .map(|i| v.b(0xa00000 + v.r[2] + i))
                            .collect();
                        v.r[0] = u32::from(vid_request && failed);
                    }
                    INVALID => {
                        invalid = true;
                    }
                    _ => panic!("unexpected OEM call {target:x}"),
                }
                pc += 4;
            }
            (0x5a, _) => {
                assert_eq!(
                    v.l(pc) & 0xffffff,
                    if vid_request {
                        sites.vid.main
                    } else {
                        0x411000
                    }
                );
                assert_eq!(
                    v.r, original,
                    "OEM tail call preserves all original arguments"
                );
                return (false, vec![]);
            }
            (0x54, 0x70) => {
                assert_eq!(
                    &v.r[2..],
                    &original[2..],
                    "callee registers and stack restored"
                );
                assert_eq!(called, expects_call && !foreign && !foreign_policy);
                if (1..8).contains(&read_state)
                    && cdb.as_slice()
                        == crate::protocol::build_set_cdb(
                            crate::protocol::Feature::Encryption,
                            cdb[6],
                        )
                {
                    assert_eq!(delay_calls, if wait.1 { 1 } else { wait.0.unwrap_or(500) });
                } else {
                    assert_eq!(delay_calls, 0);
                }
                assert_eq!(
                    v.l(g.cpu_address),
                    if foreign {
                        0xdeadbeef
                    } else {
                        u32::from_be_bytes(g.expected[..].try_into().unwrap())
                    }
                );
                if called {
                    let off = cdb[6] == crate::protocol::STATE_OFF;
                    assert_eq!(
                        v.l(sites.security_slot),
                        if off { policy } else { sites.security_table },
                        "requested policy survives OEM success or rejection"
                    );
                    assert_eq!(
                        (v.b(sites.loaded), v.b(sites.checked), v.b(sites.result)),
                        (0, 1, u8::from(!off))
                    );
                    // Another cache invalidation must not remove the suppression method.
                    v.put(sites.checked, &[0, 0]);
                    assert_eq!(
                        v.l(sites.security_slot),
                        if off { policy } else { sites.security_table }
                    );
                } else {
                    assert_eq!(v.l(sites.security_slot), initial_policy);
                    assert_eq!(
                        (v.b(sites.loaded), v.b(sites.checked), v.b(sites.result)),
                        (0x5a, 1, 0)
                    );
                }
                assert_eq!(v.b(sites.result + 1), 0xa5);
                if vid_request {
                    assert_eq!(
                        (0..b.len())
                            .map(|i| v.b(ORIGIN + i as u32))
                            .collect::<Vec<_>>(),
                        b,
                        "VID staging bytes must be cleared even if transfer fails"
                    );
                    if !invalid {
                        assert_eq!(v.r[0] as u8, u8::from(failed && !reply.is_empty()));
                    }
                }
                return (invalid, reply);
            }
            _ => panic!("unknown {x:x} {y:x} at{pc:x}"),
        }
    }
    panic!("instruction budget exceeded")
}
#[test]
fn suppression_restores_nested_callback_on_success_and_oem_failure() {
    assert_eq!(
        execute(Operation::Suppress, false, false),
        (false, vec![0; 64])
    );
    assert_eq!(execute(Operation::Suppress, true, false), (true, vec![]));
    assert_eq!(execute(Operation::Suppress, false, true), (true, vec![]));
}
#[test]
fn identity_reports_runtime_without_activating() {
    assert_eq!(
        execute_command(
            Operation::Suppress,
            false,
            false,
            crate::protocol::build_identity_cdb(64),
            false
        ),
        (false, crate::protocol::pioneer_identity().to_vec())
    );
}

#[test]
fn standard_vid_hook_frames_clamps_and_clears_hardware_response() {
    let run = |cdb, status, failed| {
        execute_with_wait(
            Operation::Suppress,
            failed,
            false,
            cdb,
            false,
            (&Sites::fixture(), true, false, status),
            (None, false),
        )
    };
    let mut expected = vec![0, 0x22, 0, 0];
    expected.extend(1..=16);
    expected.resize(36, 0);
    for length in [0u16, 1, 4, 19, 20, 35, 36, 64, 256, 65535] {
        let mut cdb = crate::vid::build_vid_cdb();
        cdb[8..10].copy_from_slice(&length.to_be_bytes());
        for failed in [false, true] {
            assert_eq!(
                run(cdb, 3, failed),
                (false, expected[..usize::from(length).min(36)].to_vec())
            );
        }
    }
    for status in [0, 1, 4, 0xfd] {
        assert_eq!(
            run(crate::vid::build_vid_cdb(), status, false),
            (true, vec![])
        );
    }
    for offset in [2, 3, 4, 5, 6, 10, 11] {
        let mut cdb = crate::vid::build_vid_cdb();
        cdb[offset] = 1;
        assert_eq!(run(cdb, 3, false), (true, vec![]));
    }
    for offset in [0, 1, 7] {
        let mut cdb = crate::vid::build_vid_cdb();
        cdb[offset] ^= 1;
        assert_eq!(run(cdb, 3, false), (false, vec![]));
    }
    for agid in [0, 0x40, 0x80, 0xc0] {
        let mut cdb = crate::vid::build_vid_cdb();
        cdb[10] = agid;
        for foreign in [false, true] {
            assert_eq!(
                execute_with_wait(
                    Operation::Suppress,
                    false,
                    false,
                    cdb,
                    false,
                    (&Sites::fixture(), false, foreign, 3),
                    (None, false)
                ),
                (false, vec![])
            );
        }
        if agid != 0 {
            assert_eq!(run(cdb, 3, false), (false, vec![]));
        }
    }
}
#[test]
fn unsupported_feature_state_and_verb_are_rejected_without_activation() {
    for verb in [2, 3, 4, 7, 9, 11, 255] {
        for feature in [0, 1, 2, 3, 4, 5, 6, 7] {
            for state in [0, 1, 2, 254, 255] {
                if verb == 2
                    && (matches!(feature, 1 | 2 | 3 | 5)
                        || feature == 6 && matches!(state, 0 | 1 | 255))
                {
                    continue;
                }
                let cdb = [0x3c, 0x0e, 0xc0, 0xde, verb, feature, state, 0, 64, 0];
                assert_eq!(
                    execute_command(Operation::Suppress, false, false, cdb, false),
                    (true, vec![])
                );
            }
        }
    }
}

#[test]
fn optional_sets_acknowledge_without_policy_reset_or_wait() {
    for feature in [1, 2, 3, 5] {
        for state in [0, 1, 2, 15, 254, 255] {
            let cdb = [0x3c, 0x0e, 0xc0, 0xde, 2, feature, state, 0, 64, 0];
            for suppressed in [false, true] {
                assert_eq!(
                    execute_with_read_state(
                        Operation::Suppress,
                        false,
                        false,
                        cdb,
                        false,
                        (&Sites::fixture(), suppressed, false, 1),
                    ),
                    (false, vec![0; 64])
                );
            }
            for offset in [7, 8, 9] {
                let mut malformed = cdb;
                malformed[offset] ^= 1;
                assert_eq!(
                    execute_command(Operation::Suppress, false, false, malformed, false),
                    (true, vec![])
                );
            }
        }
    }
}

#[test]
fn foreign_namespace_preserves_oem_arguments() {
    for i in 0..4 {
        let mut cdb = Operation::Suppress.cdb();
        cdb[i] ^= 1;
        assert_eq!(
            execute_command(Operation::Suppress, false, false, cdb, false),
            (false, vec![])
        );
    }
}

#[test]
fn on_and_passthrough_restore_policy_before_full_reinitialization() {
    for state in [1, 255] {
        let cdb = crate::protocol::build_set_cdb(crate::protocol::Feature::Encryption, state);
        assert_eq!(
            execute_command(Operation::Suppress, false, false, cdb, true),
            (false, vec![0; 64])
        );
        for offset in [7, 8, 9] {
            let mut malformed = cdb;
            malformed[offset] ^= 1;
            assert_eq!(
                execute_command(Operation::Suppress, false, false, malformed, false),
                (true, vec![])
            );
        }
    }
}

#[test]
fn transitions_accept_owned_policy_and_reject_foreign_policy() {
    for state in [0, 1, 255] {
        for suppressed in [false, true] {
            for failed in [false, true] {
                let cdb =
                    crate::protocol::build_set_cdb(crate::protocol::Feature::Encryption, state);
                assert_eq!(
                    execute_from_policy(
                        Operation::Suppress,
                        failed,
                        false,
                        cdb,
                        true,
                        suppressed,
                        false
                    ),
                    if failed {
                        (true, vec![])
                    } else {
                        (false, vec![0; 64])
                    }
                );
                assert_eq!(
                    execute_from_policy(
                        Operation::Suppress,
                        failed,
                        false,
                        cdb,
                        false,
                        suppressed,
                        true
                    ),
                    (true, vec![])
                );
            }
        }
    }
}

#[test]
#[ignore = "requires RENESAS_CORPUS_MANIFEST and RENESAS_CORPUS_IMAGES fixture paths"]
fn acquisition_signatures_match_corpus() {
    let manifest = std::env::var_os("RENESAS_CORPUS_MANIFEST").unwrap();
    let images = std::path::PathBuf::from(std::env::var_os("RENESAS_CORPUS_IMAGES").unwrap());
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(manifest).unwrap(),
    )
    .unwrap();
    let mut uhd = 0;
    let mut additional = 0;
    let mut additional_complete = 0;
    let mut report = Vec::new();
    let rows = rows.as_array().unwrap();
    for row in rows
        .iter()
        .filter(|r| r["uhd"] == true)
        .chain(rows.iter().filter(|r| r["uhd"] != true))
    {
        if row["classification"] != "mapped" {
            continue;
        }
        let sha = row["sha256"].as_str().unwrap();
        let image = std::fs::read(images.join(format!("{sha}.bin"))).unwrap();
        let guard = acquisition_guard(&image, row["comp_base"].as_u64().unwrap() as u32)
            .unwrap_or_else(|e| panic!("{sha}: {e:#}"));
        let expected = &row["matches"][0];
        assert_eq!(
            guard.cpu_address as u64,
            expected["pointer_slot"].as_u64().unwrap(),
            "{sha}"
        );
        assert_eq!(
            guard.expected,
            (expected["initializers"][0]["original_table"]
                .as_u64()
                .unwrap() as u32)
                .to_be_bytes(),
            "{sha}"
        );
        let validation = (|| -> anyhow::Result<usize> {
            let (payload, sites) = build(&image, Operation::Suppress)?;
            assert_eq!(sites.acquisition.cpu_address, guard.cpu_address);
            assert_eq!(sites.acquisition.expected, guard.expected);
            let profile = crate::freemkv::renesas::hook::discovery::profile(&image)?;
            let spaces = crate::freemkv::renesas::hook::layout::free_ranges(
                &profile.reserved_windows,
                &profile.occupied,
                payload.alignment,
            )?;
            anyhow::ensure!(
                spaces
                    .iter()
                    .any(|s| (s.length()) as usize >= payload.bytes.len()),
                "payload does not fit"
            );
            Ok(payload.bytes.len())
        })();
        let operation_discovery = if row["uhd"] == true {
            None
        } else {
            Some(
                Sites::discover(&image, row["comp_base"].as_u64().unwrap() as u32)
                    .map(|_| ())
                    .map_err(|e| format!("{e:#}")),
            )
        };
        report.push(serde_json::json!({"sha256": sha, "model": row["model"], "uhd": row["uhd"], "operation_discovery": operation_discovery,
            "payload_bytes": validation.as_ref().ok(), "error": validation.as_ref().err().map(|e|format!("{e:#}"))}));
        if row["uhd"] == true {
            validation.unwrap_or_else(|e| panic!("{sha}: {e:#}"));
            uhd += 1;
        } else {
            additional += 1;
            if validation.is_ok() {
                additional_complete += 1;
            }
        }
    }
    if let Some(path) = std::env::var_os("RENESAS_CORPUS_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    assert_eq!(uhd, 121);
    assert_eq!(additional, 239);
    assert_eq!(
        additional_complete, additional,
        "every mapped BD image must build and fit"
    );
    eprintln!(
        "Built {uhd} UHD activation payloads; {additional_complete}/{additional} additional images pass full build and RAM fit; all {additional} pass acquisition discovery"
    );
}

#[test]
fn acquisition_discovery_rejects_ambiguous_and_broken_evidence() {
    for base in [0x410000u32, 0x510000] {
        let mut image = vec![0u8; 8192];
        let slot = 0xa01234u32;
        let table = base + 256;
        let mut lookup = vec![
            0x17, 0xf0, 0x0f, 0x81, 0x10, 0x30, 0x0a, 0x90, 0x10, 0x30, 0x7a, 0x10,
        ];
        lookup.extend((base + 2048).to_be_bytes());
        lookup.extend([0x54, 0x70]);
        image[32..50].copy_from_slice(&lookup);
        image[2048 + 0x13a * 6..2052 + 0x13a * 6].copy_from_slice(&slot.to_be_bytes());
        image[2052 + 0x13a * 6] = 1;
        let mut caller = vec![0x69, 0x10];
        caller.extend(abs(0x5e, base + 32).unwrap());
        caller.extend([
            0x0f, 0x86, 1, 0, 0x69, 1, 1, 0, 0x69, 0x10, 1, 0, 0x6f, 3, 0, 0x10,
        ]);
        image[64..64 + caller.len()].copy_from_slice(&caller);
        let mut init = vec![0x7a, 3];
        init.extend(table.to_be_bytes());
        init.extend([1, 0, 0x6b, 0xa3]);
        init.extend(slot.to_be_bytes());
        image[128..142].copy_from_slice(&init);
        for off in [16, 26, 36, 46, 56, 66] {
            image[256 + off..260 + off].copy_from_slice(&(base + 1024).to_be_bytes());
        }
        let found = acquisition_guard(&image, base).unwrap();
        assert_eq!(found.cpu_address, slot);
        assert_eq!(found.expected, table.to_be_bytes());
        for candidate in [0u32, 0x7ffe, 0x8000, 0x410100, 0x9ffffc, 0xdffffe, 0xfffffc] {
            let mut broken = image.clone();
            broken[3932..3936].copy_from_slice(&candidate.to_be_bytes());
            broken[138..142].copy_from_slice(&candidate.to_be_bytes());
            assert!(
                acquisition_guard(&broken, base).is_err(),
                "slot {candidate:x}"
            );
        }
        for case in 0..6 {
            let mut broken = image.clone();
            match case {
                0 => broken[512..530].copy_from_slice(&lookup),
                1 => broken[512..526].copy_from_slice(&init),
                2 => broken[272..276].copy_from_slice(&0xffffffffu32.to_be_bytes()),
                3 => broken[64] = 0,
                4 => broken[2052 + 0x13a * 6] = 2,
                _ => broken[256 + 10] = 1,
            }
            assert!(acquisition_guard(&broken, base).is_err(), "case {case}");
        }
    }
}

#[test]
fn eligibility_discovery_checks_consistent_state_and_uniqueness() {
    let getter = [
        0x1, 0x0, 0x6d, 0xf3, 0x6a, 0x28, 0x0, 0x0, 0x2f, 0x87, 0x46, 0x34, 0x1, 0x0, 0x6b, 0x23,
        0x0, 0x0, 0x13, 0xb2, 0x1, 0x0, 0x69, 0x30, 0x1, 0x0, 0x6f, 0x2, 0x1, 0x0, 0x1, 0x0, 0x6f,
        0x0, 0x0, 0xfa, 0xa, 0xb0, 0x5d, 0x20, 0xc, 0x88, 0x47, 0x4, 0xf8, 0x1, 0x40, 0x2, 0x18,
        0x88, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x88, 0xf8, 0x1, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x87, 0x6a,
        0x28, 0x0, 0x0, 0x2f, 0x88, 0x1, 0x0, 0x6d, 0x73, 0x54, 0x70,
    ];
    for (checked, result, object) in [(0x2f87u32, 0x2f88u32, 0x13b2u32), (0x3021, 0x3022, 0x1400)] {
        let mut image = vec![0; 512];
        image[32..32 + getter.len()].copy_from_slice(&getter);
        for (off, value) in [
            (6, checked),
            (16, object),
            (52, result),
            (60, checked),
            (66, result),
        ] {
            image[32 + off..36 + off].copy_from_slice(&value.to_be_bytes());
        }
        assert_eq!(
            eligibility_state(&image).unwrap(),
            (checked, result, object)
        );
        let mut inconsistent = image.clone();
        inconsistent[32 + 60..36 + 60].copy_from_slice(&(checked + 1).to_be_bytes());
        assert!(eligibility_state(&inconsistent).is_err());
        let copy = image[32..32 + getter.len()].to_vec();
        image[256..256 + getter.len()].copy_from_slice(&copy);
        assert!(eligibility_state(&image).is_err());
    }
}

#[test]
fn security_table_discovery_preserves_null_methods_and_checks_extent() {
    let root = [
        0x6d, 0xf3, 0x18, 0xbb, 0xf8, 0x2, 0x5e, 0x54, 0xff, 0x20, 0x5e, 0x58, 0xa, 0x96, 0xa8,
        0x21, 0x46, 0x20, 0xf8, 0x3, 0x5e, 0x54, 0xff, 0x20, 0x5e, 0x58, 0x1b, 0xec, 0xa8, 0x21,
        0x46, 0xa, 0xfb, 0x1, 0x7a, 0x0, 0x0, 0x90, 0x9c, 0x74, 0x40, 0xe, 0x7a, 0x0, 0x0, 0x90,
        0x9c, 0xf7, 0x40, 0x6, 0x7a, 0x0, 0x0, 0x90, 0x9c, 0x5b, 0x5e, 0x54, 0xcc, 0x72, 0xc, 0xb8,
        0x6d, 0x73, 0x54, 0x70,
    ];
    let base = 0x410000u32;
    let mut image = vec![0; 8192];
    image[512..512 + root.len()].copy_from_slice(&root);
    for method in 0..85 {
        let callback = if method == 24 {
            base + 512
        } else if method == 42 {
            0
        } else {
            base + 1024
        };
        let off = 2048 + 16 + 10 * method;
        image[off..off + 4].copy_from_slice(&callback.to_be_bytes());
    }
    let mut init = vec![0x7a, 2];
    init.extend((base + 2048).to_be_bytes());
    init.extend([1, 0, 0x6b, 0xa2]);
    init.extend(0x1456u32.to_be_bytes());
    image[128..142].copy_from_slice(&init);
    let mut assignment = abs(0x5e, base + 192).unwrap().to_vec();
    assignment.extend([1, 0, 0x6b, 0xa0]);
    assignment.extend(0x1400u32.to_be_bytes());
    image[96..108].copy_from_slice(&assignment);
    let accessor = [
        0x7a, 0, 0, 0x90, 0, 0, 0x5e, 0x42, 0, 0, 0x7a, 0, 0, 0, 0x14, 0x56, 0x54, 0x70,
    ];
    image[192..210].copy_from_slice(&accessor);

    let mut next = vec![0x7a, 0];
    next.extend((base + 2048 + 860).to_be_bytes());
    next.extend([1, 0, 0x69, 0x90]);
    image[160..170].copy_from_slice(&next);
    assert_eq!(
        security_layout(&image, base, 0x1400).unwrap(),
        (0x1456, base + 2048, 860)
    );
    for (slot, valid) in [
        (0u32, false),
        (0x7ffe, false),
        (0x8000, false),
        (0x410100, false),
        (0x9ffffc, false),
        (0xdffffe, false),
        (0xfffffc, false),
        (0x7ffc, true),
        (0xa00000, true),
        (0xdffffc, true),
    ] {
        let mut mutated = image.clone();
        mutated[138..142].copy_from_slice(&slot.to_be_bytes());
        mutated[204..208].copy_from_slice(&slot.to_be_bytes());
        assert_eq!(
            security_layout(&mutated, base, 0x1400).is_ok(),
            valid,
            "slot {slot:x}"
        );
    }
    let a_only = [
        0x6d, 0xf3, 0x18, 0xbb, 0xf8, 2, 0x5e, 0x52, 0x12, 0x34, 0x5e, 0x57, 0x56, 0x78, 0xa8,
        0x21, 0x46, 0x0a, 0xfb, 1, 0x7a, 0, 0, 0x90, 0x20, 0, 0x40, 6, 0x7a, 0, 0, 0x90, 0x30, 0,
        0x5e, 0x51, 0x44, 0x66, 0x0c, 0xb8, 0x6d, 0x73, 0x54, 0x70,
    ];
    let mut bd = image.clone();
    bd[512..512 + root.len()].fill(0);
    bd[512..512 + a_only.len()].copy_from_slice(&a_only);
    assert_eq!(
        security_layout(&bd, base, 0x1400).unwrap(),
        (0x1456, base + 2048, 860)
    );
    bd[512 + 15] = 0x22;
    assert!(security_layout(&bd, base, 0x1400).is_err());
    let mut extra_method = image.clone();
    extra_method[2048 + 16 + 85 * 10..2048 + 20 + 85 * 10]
        .copy_from_slice(&(base + 1024).to_be_bytes());
    assert!(security_layout(&extra_method, base, 0x1400).is_err());
    image[2048 + 16 + 84 * 10..2048 + 20 + 84 * 10].copy_from_slice(&0xffffffffu32.to_be_bytes());
    assert!(security_layout(&image, base, 0x1400).is_err());
}

#[test]
fn generated_transitions_use_relocated_firmware_sites_and_larger_tables() {
    let mut sites = Sites::fixture();
    sites.acquisition.cpu_address += 0x100;
    sites.acquisition.expected = 0x5caabcu32.to_be_bytes().to_vec();
    sites.loaded += 0x100;
    sites.checked += 0x100;
    sites.result += 0x100;
    sites.security_slot += 0x100;
    sites.security_table += 0x1000;
    sites.table_length += 60;
    sites.dispatcher += 0x1000;
    sites.buffers = [0x3110, 0xa038f4];
    for state in [0, 1, 0xff] {
        let mut cdb = Operation::Suppress.cdb();
        cdb[6] = state;
        for failed in [false, true] {
            for suppressed in [false, true] {
                let (invalid, reply) = execute_at_sites(
                    Operation::Suppress,
                    failed,
                    false,
                    cdb,
                    true,
                    (&sites, suppressed, false),
                );
                assert_eq!(invalid, failed);
                assert_eq!(reply, if failed { vec![] } else { vec![0; 64] });
            }
        }
    }
}

#[test]
fn acquisition_buffers_require_aligned_complete_longword_ranges() {
    let mut code = vec![
        0x19, 0x33, 0x0d, 0x31, 0x17, 0x71, 0x6e, 0x1c, 0, 0, 0x78, 0x10, 0x6a, 0xac, 0, 0, 0, 0,
        0x0b, 0x53, 0x79, 0x23, 0, 0x10, 0x45, 0xe8,
    ];
    for (source, destination, valid) in [
        (0x2a10u16, 0xa027f4u32, true),
        (0x2a12, 0xa027f6, true),
        (0x2a11, 0xa027f4, false),
        (0x2a10, 0xa027f5, false),
        (0x7ff0, 0xdffff0, true),
        (0x7ff2, 0xa027f4, false),
        (0x2a10, 0xdffff2, false),
        (0, 0xa027f4, false),
    ] {
        code[8..10].copy_from_slice(&source.to_be_bytes());
        code[14..18].copy_from_slice(&destination.to_be_bytes());
        assert_eq!(
            activation_buffers(&code).is_ok(),
            valid,
            "{source:x} {destination:x}"
        );
    }
}

#[test]
fn cf_validation_links_mapping_reset_and_eligibility_calls() {
    let base = 0x410000u32;
    let mut image = vec![0; 8192];
    let slot = 0xa04000u32;
    let mut lookup = vec![
        0x17, 0xf0, 0x0f, 0x81, 0x10, 0x30, 0x0a, 0x90, 0x10, 0x30, 0x7a, 0x10,
    ];
    lookup.extend((base + 2048).to_be_bytes());
    lookup.extend([0x54, 0x70]);
    image[32..50].copy_from_slice(&lookup);
    image[2048 + 0xcf * 6..2052 + 0xcf * 6].copy_from_slice(&slot.to_be_bytes());
    let mut caller = vec![0x69, 0x10];
    caller.extend(abs(0x5e, base + 32).unwrap());
    caller.extend([
        0x0f, 0x86, 1, 0, 0x69, 1, 1, 0, 0x69, 0x10, 1, 0, 0x6f, 3, 0, 0x10,
    ]);
    image[64..64 + caller.len()].copy_from_slice(&caller);
    let mut init = vec![0x7a, 0];
    init.extend((base + 256).to_be_bytes());
    init.extend([1, 0, 0x6b, 0xa0]);
    init.extend(slot.to_be_bytes());
    image[128..142].copy_from_slice(&init);
    image[272..276].copy_from_slice(&(base + 512).to_be_bytes());
    let mut main = vec![1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 0x3c, 0x0f, 0x85];
    main.extend(abs(0x5e, base + 1024).unwrap());
    let mut tail = [
        0x79, 0x1, 0x1, 0x3a, 0x6f, 0xf1, 0x0, 0x28, 0xf9, 0x1, 0xc, 0xcc, 0x46, 0x2, 0x18, 0x99,
        0x6e, 0xf9, 0x0, 0x2a, 0xf, 0xf1, 0x79, 0x11, 0x0, 0x28, 0xf, 0xd0, 0x1a, 0xa2, 0x5e, 0x55,
        0x55, 0xa6, 0xa8, 0x1, 0x46, 0x8, 0x7a, 0x0, 0x0, 0x91, 0xc8, 0xf4, 0x40, 0x30, 0xa, 0xc,
        0x47, 0xce, 0x79, 0x1, 0x1, 0x2b, 0xf, 0xd0, 0x5e, 0x55, 0x57, 0x9c, 0xf8, 0x58, 0x5e,
        0x55, 0x5d, 0x88, 0x5e, 0x46, 0x8, 0xda, 0xc, 0x88, 0x47, 0x1a, 0x79, 0x1, 0x1, 0x3d, 0xf,
        0xd0, 0x5e, 0x55, 0x57, 0x9c, 0xa8, 0x1, 0x46, 0xc, 0x7a, 0x0, 0x0, 0x91, 0xc8, 0xe2, 0x5e,
        0x54, 0xcc, 0x72, 0x40, 0x4, 0x18, 0x88, 0x40, 0x2, 0xf8, 0x1, 0x79, 0x17, 0x0, 0x3c, 0x1,
        0x20, 0x6d, 0x76, 0x54, 0x70,
    ];
    tail[30..34].copy_from_slice(&abs(0x5e, base + 4096).unwrap());
    tail[66..70].copy_from_slice(&abs(0x5e, base + 1536).unwrap());
    main.extend(tail);
    image[512..512 + main.len()].copy_from_slice(&main);
    image[1024..1028].copy_from_slice(&abs(0x5e, base + 1800).unwrap());
    image[1028..1030].copy_from_slice(&[0x54, 0x70]);
    let getter = [
        0x1, 0x0, 0x6d, 0xf3, 0x6a, 0x28, 0x0, 0x0, 0x2f, 0x87, 0x46, 0x34, 0x1, 0x0, 0x6b, 0x23,
        0x0, 0x0, 0x13, 0xb2, 0x1, 0x0, 0x69, 0x30, 0x1, 0x0, 0x6f, 0x2, 0x1, 0x0, 0x1, 0x0, 0x6f,
        0x0, 0x0, 0xfa, 0xa, 0xb0, 0x5d, 0x20, 0xc, 0x88, 0x47, 0x4, 0xf8, 0x1, 0x40, 0x2, 0x18,
        0x88, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x88, 0xf8, 0x1, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x87, 0x6a,
        0x28, 0x0, 0x0, 0x2f, 0x88, 0x1, 0x0, 0x6d, 0x73, 0x54, 0x70,
    ];
    image[1536..1536 + getter.len()].copy_from_slice(&getter);
    let cache = [
        0x18, 0x88, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x84, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x86, 0x6a, 0xa8,
        0x0, 0x0, 0x2f, 0x85, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x87, 0x6a, 0xa8, 0x0, 0x0, 0x2f, 0x88,
        0x54, 0x70, 0x6a, 0x28, 0x0, 0x0, 0x2f, 0x86, 0x54, 0x70,
    ];
    image[1800..1800 + cache.len()].copy_from_slice(&cache);
    assert_eq!(
        verify_cf(&image, base, base + 4096).unwrap().cpu_address,
        slot
    );
    let mut smaller_frame = image.clone();
    for (at, value) in [
        (519, 0x3a),
        (526 + 7, 0x26),
        (526 + 19, 0x28),
        (526 + 25, 0x26),
        (526 + 109, 0x3a),
    ] {
        smaller_frame[at] = value;
    }
    assert_eq!(
        verify_cf(&smaller_frame, base, base + 4096)
            .unwrap()
            .cpu_address,
        slot
    );
    for at in [519, 526 + 7, 526 + 19, 526 + 25, 526 + 109] {
        let mut broken = smaller_frame.clone();
        broken[at] ^= 2;
        assert!(
            verify_cf(&broken, base, base + 4096).is_err(),
            "stack-layout mutation {at:x}"
        );
    }
    let mut legacy = image.clone();
    let mut legacy_tail = [
        0x79, 0x01, 0x01, 0x3a, 0x6f, 0xf1, 0x00, 0x1e, 0x18, 0x99, 0x6e, 0xf9, 0x00, 0x20, 0x0f,
        0xf1, 0x79, 0x11, 0x00, 0x1e, 0x0f, 0xc0, 0x1a, 0xa2, 0x5e, 0x55, 0xe7, 0x3c, 0xa8, 0x01,
        0x46, 0x08, 0x7a, 0x00, 0x00, 0x91, 0xb7, 0x7e, 0x40, 0x2c, 0x79, 0x01, 0x01, 0x2b, 0x0f,
        0xc0, 0x5e, 0x55, 0xe9, 0x32, 0xf8, 0x58, 0x5e, 0x55, 0xef, 0x66, 0x5e, 0x47, 0x39, 0xb8,
        0x0c, 0x88, 0x47, 0x1a, 0x79, 0x01, 0x01, 0x3d, 0x0f, 0xc0, 0x5e, 0x55, 0xe9, 0x32, 0xa8,
        0x01, 0x46, 0x0c, 0x7a, 0x00, 0x00, 0x91, 0xb7, 0x6c, 0x5e, 0x55, 0x54, 0x1a, 0x40, 0x04,
        0x18, 0x88, 0x40, 0x02, 0xf8, 0x01, 0x79, 0x17, 0x00, 0x32, 0x01, 0x10, 0x6d, 0x75, 0x54,
        0x70,
    ];
    legacy_tail[24..28].copy_from_slice(&abs(0x5e, base + 4096).unwrap());
    legacy_tail[56..60].copy_from_slice(&abs(0x5e, base + 1536).unwrap());
    legacy[512..512 + main.len()].fill(0);
    legacy[512..522].copy_from_slice(&[1, 0x10, 0x6d, 0xf4, 0x79, 0x37, 0, 0x32, 0x0f, 0x84]);
    legacy[522..526].copy_from_slice(&abs(0x5e, base + 1024).unwrap());
    legacy[526..526 + legacy_tail.len()].copy_from_slice(&legacy_tail);
    assert_eq!(
        verify_cf(&legacy, base, base + 4096).unwrap().cpu_address,
        slot
    );
    for at in [519, 526 + 27, 526 + 59, 526 + 73, 526 + 97] {
        let mut broken = legacy.clone();
        broken[at] ^= 2;
        assert!(
            verify_cf(&broken, base, base + 4096).is_err(),
            "legacy mutation {at:x}"
        );
    }
    let mut bypass = image.clone();
    bypass[1024..1026].copy_from_slice(&[0x46, 4]);
    bypass[1026..1030].copy_from_slice(&abs(0x5e, base + 1800).unwrap());
    bypass[1030..1032].copy_from_slice(&[0x54, 0x70]);
    assert!(verify_cf(&bypass, base, base + 4096).is_err());
    for at in [
        2048 + 0xcf * 6 + 3,
        2052 + 0xcf * 6,
        512 + 14 + 3,
        512 + 14 + 33,
        512 + 14 + 69,
        1027,
    ] {
        let mut broken = image.clone();
        broken[at] ^= 2;
        assert!(
            verify_cf(&broken, base, base + 4096).is_err(),
            "mutation {at:x}"
        );
    }
}
#[test]
fn dispatcher_rejects_corrupt_stack_and_register_restoration() {
    let valid = [
        0x0c, 0xd8, 0x79, 0x17, 0x00, 0x20, 0x01, 0x20, 0x6d, 0x76, 0x01, 0x00, 0x6d, 0x73, 0x54,
        0x70,
    ];
    for base in [0, 0x410000] {
        verify_dispatcher_returns(&valid, base, 0).unwrap();
        for (offset, replacement) in [(5, 0x22), (9, 0x75), (13, 0x72), (1, 0xc8)] {
            let mut corrupt = valid;
            corrupt[offset] = replacement;
            assert!(verify_dispatcher_returns(&corrupt, base, 0).is_err());
        }
        assert!(verify_dispatcher_returns(&valid, base, 2).is_err());
        let mut bypass = vec![0x46, 0x0e]; // BNE straight to RTS; fallthrough looks valid.
        bypass.extend(valid);
        assert!(verify_dispatcher_returns(&bypass, base, 0).is_err());
    }
}
#[test]
fn buffer_owner_requires_matching_dispatch_and_reachable_output() {
    for base in [0x410000u32, 0x510000] {
        let dispatcher = base + 800;
        let buffers = [0x2a10u32, 0xa027f4];
        let mut image = vec![0; 1024];
        let mut consumer = vec![
            0x79, 1, 1, 0x3a, 0x69, 0xf1, 0x18, 0x99, 0x6e, 0xf9, 0, 2, 0x0f, 0xf1, 0x1a, 0xa2,
        ];
        consumer.extend(abs(0x5e, dispatcher).unwrap());
        consumer.extend([
            0x6e, 0xf8, 0, 0x2c, 0xa8, 1, 0x58, 0x70, 0, 0xcc, 0x19, 0x33, 0x0d, 0x31, 0x17, 0x71,
            0x6e, 0x1c, 0x2a, 0x10, 0x78, 0x10, 0x6a, 0xac, 0, 0xa0, 0x27, 0xf4,
        ]);
        image[32..32 + consumer.len()].copy_from_slice(&consumer);
        image[144..148].copy_from_slice(&(base + 256).to_be_bytes());
        image[256..268].copy_from_slice(&[
            0x7a, 2, 0, 0, 0x2a, 0x10, 0x18, 0x99, 0x5d, 0x30, 0x54, 0x70,
        ]);
        let guard = Guard {
            cpu_address: 0xa01000,
            expected: (base + 128).to_be_bytes().to_vec(),
        };
        verify_buffer_owner(&image, base, dispatcher, &guard, buffers).unwrap();
        for offset in [32 + 3, 32 + 19, 32 + 39, 261] {
            let mut broken = image.clone();
            broken[offset] ^= 2;
            assert!(verify_buffer_owner(&broken, base, dispatcher, &guard, buffers).is_err());
        }
        // A correct-looking output after an unconditional return is not evidence.
        image[254..256].copy_from_slice(&[0x54, 0x70]);
        image[144..148].copy_from_slice(&(base + 254).to_be_bytes());
        assert!(verify_buffer_owner(&image, base, dispatcher, &guard, buffers).is_err());
    }
}
#[test]
fn busy_read_engine_times_out_before_every_policy_transition() {
    for state in 1..8 {
        for policy in [0, 1, 255] {
            let cdb = crate::protocol::build_set_cdb(crate::protocol::Feature::Encryption, policy);
            let (invalid, _) = execute_with_read_state(
                Operation::Suppress,
                false,
                false,
                cdb,
                false,
                (&Sites::fixture(), false, false, state),
            );
            assert!(invalid);
        }
    }
    for state in [0, 8, 9, 255] {
        let (invalid, _) = execute_with_read_state(
            Operation::Suppress,
            false,
            false,
            Operation::Suppress.cdb(),
            true,
            (&Sites::fixture(), false, false, state),
        );
        assert!(!invalid);
    }
}

#[test]
fn firmware_wait_preserves_arguments_and_handles_scheduler_failure() {
    for policy in [0, 1, 255] {
        for suppressed in [false, true] {
            for (idle_after, error, expected_call) in [
                (Some(1), false, true),
                (Some(12), false, true),
                (Some(500), false, true),
                (None, true, false),
            ] {
                let mut sites = Sites::fixture();
                sites.scheduler_delay += 0x200;
                sites.read_engine_state += 0x100;
                let (invalid, _) = execute_with_wait(
                    Operation::Suppress,
                    false,
                    false,
                    crate::protocol::build_set_cdb(crate::protocol::Feature::Encryption, policy),
                    expected_call,
                    (&sites, suppressed, false, 3),
                    (idle_after, error),
                );
                assert_eq!(invalid, !expected_call);
            }
        }
    }
}

#[test]
fn scheduler_delay_discovery_requires_unique_adapter_and_kernel_target() {
    let mut image = vec![0; 256];
    let adapter = [
        0x17, 0x70, 0x5e, 0x40, 0x90, 0x00, 0x0d, 0x08, 0x19, 0x11, 0x0d, 0x00, 0x46, 0x02, 0xf9,
        0x01, 0x0d, 0x10, 0xf0, 0x16, 0x18, 0x99, 0x5e, 0x55, 0x00, 0x00, 0x54, 0x70,
    ];
    image[32..60].copy_from_slice(&adapter);
    assert_eq!(scheduler_delay(&image).unwrap(), 0x409000);
    image[36..38].copy_from_slice(&0xabceu16.to_be_bytes());
    assert_eq!(scheduler_delay(&image).unwrap(), 0x40abce);
    image[35] = 0x50;
    assert!(scheduler_delay(&image).is_err());
    image[35] = 0x40;
    image[37] |= 1;
    assert!(scheduler_delay(&image).is_err());
    image[32..60].copy_from_slice(&adapter);
    image[128..156].copy_from_slice(&adapter);
    assert!(scheduler_delay(&image).is_err());
    image.fill(0);
    assert!(scheduler_delay(&image).is_err());
}
