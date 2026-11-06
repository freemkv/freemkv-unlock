use super::*;
use crate::scsi::mock::{MockTransport, Reply};
use pioneer_optical::settings::Observed;

// Synthetic F4 protocol responses, not captured hardware measurements.
fn settings(current: u8, writable: u8) -> Vec<u8> {
    let mut b = vec![0xff; 256];
    b[2] = current;
    b[3] = 2; // saved Quiet must remain unchanged
    b[43] = 1;
    b[45] = writable;
    b
}
const QUERY: [u8; 10] = [0x3c, 2, 0xf4, 0, 0, 0, 0, 1, 0, 0];
const QUIET_OFF: [u8; 12] = [0xbb, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0x80, 0];

#[test]
fn quiet_off_requires_readback_and_never_saves_the_setting() {
    let mut t = MockTransport::scripted(
        vec![
            Reply::good(settings(2, 1)),
            Reply::good(vec![]),
            Reply::good(settings(0, 1)),
        ],
        Reply::TransportFault,
    );
    match select(&mut t).unwrap() {
        WriteOutcome::Verified(s) => {
            assert_eq!(s.current, Observed::Known(QuietMode::Standard));
            assert_eq!(s.saved, Observed::Known(QuietMode::Quiet));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        t.cdbs,
        vec![QUERY.to_vec(), QUIET_OFF.to_vec(), QUERY.to_vec()]
    );
}

#[test]
fn already_quiet_off_does_not_write() {
    let mut t = MockTransport::always(Reply::good(settings(0, 1)));
    assert!(matches!(select(&mut t), Ok(WriteOutcome::Unchanged(_))));
    assert_eq!(t.calls(), 1);
}

#[test]
fn unknown_unsupported_and_malformed_capabilities_never_write() {
    for response in [
        settings(2, 0),
        settings(2, 255),
        vec![0; 256],
        vec![255; 256],
        vec![255; 255],
    ] {
        let mut t = MockTransport::always(Reply::good(response));
        assert!(select(&mut t).is_err());
        assert_eq!(t.cdbs, vec![QUERY.to_vec()]);
    }
}

#[test]
fn accepted_command_is_not_success_without_matching_readback() {
    for response in [
        Reply::good(settings(2, 1)),
        Reply::illegal_request(),
        Reply::good(vec![0; 256]),
    ] {
        let mut t = MockTransport::scripted(
            vec![Reply::good(settings(2, 1)), Reply::good(vec![]), response],
            Reply::TransportFault,
        );
        assert!(matches!(
            select(&mut t),
            Ok(WriteOutcome::Mismatch(_) | WriteOutcome::Unverified(_))
        ));
        assert_eq!(t.calls(), 3);
    }
}

#[test]
fn rejection_is_optional_but_dead_bus_aborts_at_each_stage() {
    for stage in 0..3 {
        for fault in [
            Reply::illegal_request(),
            Reply::illegal_request_as_err(),
            Reply::TransportFault,
        ] {
            let dead = matches!(fault, Reply::TransportFault);
            let mut replies = vec![
                Reply::good(settings(2, 1)),
                Reply::good(vec![]),
                Reply::good(settings(0, 1)),
            ];
            replies[stage] = fault;
            let mut t = MockTransport::scripted(replies, Reply::TransportFault);
            assert_eq!(
                configure(&mut t),
                if dead {
                    Err(UnlockError::Transport)
                } else {
                    Ok(())
                }
            );
            assert_eq!(
                t.calls(),
                stage + 1,
                "never retry a setting or continue after a fault"
            );
        }
    }
}

#[test]
fn impossible_transfer_count_is_not_verified() {
    struct BadCount(MockTransport);
    impl ScsiTransport for BadCount {
        fn execute(
            &mut self,
            c: &[u8],
            d: DataDirection,
            b: &mut [u8],
            t: u32,
        ) -> crate::scsi::Result<crate::scsi::ScsiResult> {
            let mut r = self.0.execute(c, d, b, t)?;
            if c[0] == 0xbb {
                r.bytes_transferred = 1;
            }
            Ok(r)
        }
    }
    let mut t = BadCount(MockTransport::scripted(
        vec![Reply::good(settings(2, 1)), Reply::good(vec![])],
        Reply::TransportFault,
    ));
    assert!(matches!(
        select(&mut t),
        Ok(WriteOutcome::Unverified(Error::Malformed))
    ));
    assert_eq!(t.0.calls(), 2);
}

// Execute the native vendor-policy branch from BDR-209M 1.33 (SAT8600 ID60),
// CPU 44B286..44B36A, to check the actual OEM argument mapping of our command.
// Extracted from Normal envelope SHA256
// 1930eb998112cd7aa6f695cc6d342d649f329125f006fc79d44a96bfef176ef5.
// Framing-only decoded body: this region is readable native code. No claim of
// complete firmware decoding or hardware throughput follows from this fixture.
// Calls to the OEM singleton getter/logger are mocked; the final setter receives
// the real computed R1H (save) and R1L (policy). No production model/address gate.
#[test]
fn bdr_209m_native_branch_selects_quiet_off_without_eeprom_save() {
    let code = include_bytes!("209m-133-bb.bin");
    for save in [false, true] {
        let mut regs = [0u32; 8];
        regs[4] = u32::from(QUIET_OFF[10] | if save { 0x40 } else { 0 }) << 8;
        let mut pc = 0usize;
        let mut zero = false;
        let get = |r: &[u32; 8], n: u8| -> u8 {
            (r[(n & 7) as usize] >> if n < 8 { 8 } else { 0 }) as u8
        };
        let put = |r: &mut [u32; 8], n: u8, v: u8| {
            let shift = if n < 8 { 8 } else { 0 };
            let slot = &mut r[(n & 7) as usize];
            *slot = (*slot & !(255 << shift)) | (u32::from(v) << shift);
        };
        let mut setter = None;
        let mut auto_enabled = false;
        for _ in 0..100 {
            let (x, y) = (code[pc], code[pc + 1]);
            match (x, y) {
                (0x0c, _) => {
                    let v = get(&regs, y >> 4);
                    put(&mut regs, y & 15, v);
                    zero = v == 0;
                    pc += 2;
                }
                (0xe0..=0xef, _) => {
                    let n = x & 15;
                    let v = get(&regs, n) & y;
                    put(&mut regs, n, v);
                    zero = v == 0;
                    pc += 2;
                }
                (0x18, 0xaa) => {
                    put(&mut regs, 10, 0);
                    zero = true;
                    pc += 2;
                }
                (0x19, 0x11) => {
                    regs[1] &= 0xffff0000;
                    zero = true;
                    pc += 2;
                }
                (0x6e, 0xfa) => {
                    pc += 4;
                } // zero the OEM command's temporary stack fields
                (0x58, 0x70) => {
                    let d = i16::from_be_bytes([code[pc + 2], code[pc + 3]]);
                    pc = ((pc + 4) as isize + if zero { isize::from(d) } else { 0 }) as usize;
                }
                (0x40 | 0x46 | 0x47, _) => {
                    let take = x == 0x40 || (x == 0x46 && !zero) || (x == 0x47 && zero);
                    pc = ((pc + 2) as isize + if take { y as i8 as isize } else { 0 }) as usize;
                }
                (0x0f, 0xf0) => {
                    regs[0] = regs[7];
                    pc += 2;
                }
                (0x18, 0x99) => {
                    put(&mut regs, 9, 0);
                    zero = true;
                    pc += 2;
                }
                (0xa6, _) => {
                    zero = get(&regs, 6) == y;
                    pc += 2;
                }
                (0xf9, _) => {
                    put(&mut regs, 9, y);
                    pc += 2;
                }
                (0x0f, _) => {
                    regs[(y & 7) as usize] = regs[((y >> 4) & 7) as usize];
                    pc += 2;
                }
                (0x7a, 0) => {
                    regs[0] = u32::from_be_bytes(code[pc + 2..pc + 6].try_into().unwrap());
                    pc += 6;
                }
                (0x5e, _) => {
                    let addr = u32::from_be_bytes(code[pc..pc + 4].try_into().unwrap()) & 0xffffff;
                    match addr {
                        0x455d2a => regs[0] = 0x10dc, // native singleton getter
                        0x54b5d0 => {}                // log message, preserves OEM callee registers
                        0x455d7c => {
                            setter = Some((regs[0], regs[1] as u16));
                        }
                        0x543efe => regs[0] = 1, // exercise the native enable path
                        0x456000 => auto_enabled = true,
                        0x44f458 => break, // native command dispatch
                        _ => panic!("unexpected native call {addr:x}"),
                    }
                    pc += 4;
                }
                _ => panic!("unhandled native opcode at {pc:x}: {x:02x}{y:02x}"),
            }
        }
        assert_eq!(setter, Some((0x10dc, if save { 0x01fd } else { 0x00fd })));
        assert!(
            !auto_enabled,
            "mode zero must skip native adaptive-controller enable"
        );
    }
    assert_eq!(
        QUIET_OFF[10] & 0x40,
        0,
        "the production command must not persist"
    );
}

// Native setter core 455DA8..455DE6 from the same 209M Normal image as above.
// Execute both policies: FD must select index zero AND disable adaptive control;
// FE selects the same index without disabling it. Only OEM call boundaries are
// mocked, so changing the tested branch or argument fails this regression.
#[test]
fn bdr_209m_quiet_off_disables_adaptive_control_where_performance_does_not() {
    let b = include_bytes!("209m-133-policy.bin");
    for policy in [0xfd, 0xfe] {
        let mut pc = 0;
        let mut zero = false;
        let mut r0h = 0xff; // initial requested policy is Quiet
        let mut r1 = 0u16;
        let mut r5l = policy;
        let mut stored = 0xff;
        let mut calls = vec![];
        for _ in 0..40 {
            if pc == b.len() {
                break;
            }
            match (b[pc], b[pc + 1]) {
                (0x6e, 0x40) => {
                    r0h = stored;
                    pc += 4;
                }
                (0x1c, 0xd0) => {
                    zero = r5l == r0h;
                    pc += 2;
                }
                (0x6e, 0xcd) => {
                    stored = r5l;
                    pc += 4;
                }
                (0xad, value) => {
                    zero = r5l == value;
                    pc += 2;
                }
                (0x40 | 0x46 | 0x47, displacement) => {
                    let take = b[pc] == 0x40 || (b[pc] == 0x46 && !zero) || (b[pc] == 0x47 && zero);
                    pc = ((pc + 2) as isize + if take { displacement as i8 as isize } else { 0 })
                        as usize;
                }
                (0x79, 0x01) => {
                    r1 = u16::from_be_bytes([b[pc + 2], b[pc + 3]]);
                    pc += 4;
                }
                (0x0f, 0xc0) => {
                    pc += 2;
                } // ER0 = existing policy singleton
                (0x5e, _) => {
                    let target = u32::from_be_bytes(b[pc..pc + 4].try_into().unwrap()) & 0xffffff;
                    assert!(matches!(target, 0x4567f6 | 0x4568c0));
                    calls.push((target, r1));
                    pc += 4;
                }
                (0x0c, 0x8d) => {
                    r5l = 0;
                    pc += 2;
                } // selector returns first table entry
                (0x18, 0x99) => {
                    r1 &= 0xff00;
                    zero = true;
                    pc += 2;
                }
                (0x19, 0x11) => {
                    r1 = 0;
                    zero = true;
                    pc += 2;
                }
                op => panic!("unexpected native setter opcode {op:?} at {pc:x}"),
            }
        }
        assert_eq!(pc, b.len());
        assert_eq!(stored, policy);
        let expected = if policy == 0xfd {
            vec![(0x4567f6, 1), (0x4568c0, 0)]
        } else {
            vec![(0x4567f6, 1)]
        };
        assert_eq!(calls, expected);
    }
}
