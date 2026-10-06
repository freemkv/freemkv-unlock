use super::*;
use mock::{MockTransport, Reply};

/// The fixed-format sense layout the whole crate reads its diagnostics off
/// (key at byte 2 low nibble, ASC at 12, ASCQ at 13). This file had no test
/// at all, so nothing pinned the offsets.
#[test]
fn sense_parses_at_the_fixed_format_offsets() {
    let mut buf = [0u8; 32];
    buf[2] = 0xF5; // sense key is the LOW nibble only
    buf[12] = 0x24;
    buf[13] = 0x01;
    let s = ScsiSense::from_buf(&buf);
    assert_eq!(s.sense_key, 0x05);
    assert_eq!(s.asc, 0x24);
    assert_eq!(s.ascq, 0x01);
    assert!(s.is_illegal_request());

    buf[2] = 0x02; // NOT READY
    assert!(!ScsiSense::from_buf(&buf).is_illegal_request());
}

/// SET CD SPEED encodes the read speed big-endian at bytes 2-3 and leaves
/// the write speed at 0xFFFF.
#[test]
fn set_cd_speed_encodes_the_read_speed_big_endian() {
    let cdb = build_set_cd_speed(0x1234);
    assert_eq!(cdb[0], SCSI_SET_CD_SPEED);
    assert_eq!([cdb[2], cdb[3]], [0x12, 0x34]);
    assert_eq!([cdb[4], cdb[5]], [0xFF, 0xFF]);
    assert_eq!(build_set_cd_speed(0xFFFF)[2..4], [0xFF, 0xFF]);
}

// The fixture must honour the contract it tests: a drive sense is `Ok`
// with non-zero status, a bus fault is `Err`. If this drifts, every
// transport-contract test built on it silently stops testing anything.
#[test]
fn mock_transport_expresses_the_three_contract_outcomes() {
    let mut t = MockTransport::scripted(
        vec![
            Reply::good(vec![0xAB; 4]),
            Reply::illegal_request(),
            Reply::zero_transfer(4),
        ],
        Reply::TransportFault,
    );
    let mut buf = [0u8; 4];

    let r = t
        .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
        .expect("data reply is Ok");
    assert_eq!(r.status, 0);
    assert_eq!(r.bytes_transferred, 4);
    assert_eq!(buf, [0xAB; 4]);

    let r = t
        .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
        .expect("A DRIVE SENSE IS Ok, NOT Err — the load-bearing contract");
    assert_eq!(r.status, SCSI_STATUS_CHECK_CONDITION);
    assert!(ScsiSense::from_buf(&r.sense).is_illegal_request());

    let r = t
        .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
        .expect("a zero-length transfer is still Ok");
    assert_eq!(r.bytes_transferred, 0);

    let e = t
        .execute(&[0x3C], DataDirection::FromDevice, &mut buf, 0)
        .expect_err("a transport fault is Err");
    assert_eq!(e.status, SCSI_STATUS_TRANSPORT_FAILURE);
    assert!(e.sense.is_none(), "a bus fault carries no drive sense");

    assert_eq!(t.calls(), 4);
}

// UT1 (stop-design-v5 §5.2; §2.3 "`enter` calls `begin_critical()?`. `Drop` calls
// `end_critical`"): refused after a cancel; closed on drop AND on unwind.
#[test]
fn critical_guard_refused_after_cancel_and_ends_on_unwind() {
    use mock::{Ev, StopFake};
    let mut t = StopFake::new(MockTransport::always(Reply::good(vec![0u8; 4])));
    {
        let mut g = CriticalGuard::enter(&mut t).expect("not cancelled: opens");
        g.execute(&[0x3B], DataDirection::ToDevice, &mut [0u8; 4], 0)
            .expect("inside the span");
    }
    assert_eq!(t.log[0], Ev::Begin);
    assert_eq!(t.log.last(), Some(&Ev::End), "closed on drop");

    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = CriticalGuard::enter(&mut t).expect("opens");
        panic!("unwind inside the span");
    }));
    assert!(r.is_err());
    assert_eq!(t.log.last(), Some(&Ev::End), "closed on unwind");

    t.cancelled = true;
    let e = CriticalGuard::enter(&mut t)
        .err()
        .expect("refused after a cancel");
    assert!(is_dead_bus(&e), "a refusal is the dead-bus shape");
    assert_eq!(t.log.last(), Some(&Ev::BeginRefused), "no span, so no End");
    let begins = t.log.iter().filter(|e| **e == Ev::Begin).count();
    let ends = t.log.iter().filter(|e| **e == Ev::End).count();
    assert_eq!(begins, ends, "every opened span closed exactly once");
}

// The defaults keep all 32 existing transports compiling and behaving as
// before: pause sleeps, spans are no-ops, cleanup is a plain execute.
#[test]
fn default_stop_methods_preserve_plain_transport_behaviour() {
    let mut t = MockTransport::always(Reply::good(vec![0u8; 2]));
    let t0 = std::time::Instant::now();
    t.pause(std::time::Duration::from_millis(20))
        .expect("plain sleep");
    assert!(t0.elapsed() >= std::time::Duration::from_millis(20));
    t.begin_critical().expect("no-op");
    t.end_critical();
    t.execute_cleanup(&[0xA4], DataDirection::FromDevice, &mut [0u8; 2], 0)
        .expect("plain execute");
    assert_eq!(t.cdbs, vec![vec![0xA4]], "cleanup reached the drive once");
}

// SS-7 (evidence): the guard's drop sends its REPORT KEY 3Fh CDB once, via
// execute_cleanup, even after a cancel; `defuse` sends nothing.
#[test]
fn agid_guard_releases_once_via_cleanup_and_defuse_keeps_it() {
    use mock::{Ev, StopFake};
    let mut rel = [0u8; 12];
    rel[0] = SCSI_REPORT_KEY;
    rel[10] = (2 << 6) | 0x3F;
    let mut t = StopFake::new(MockTransport::always(Reply::good(vec![0u8; 8])));
    t.cancelled = true;
    drop(AgidGuard::new(&mut t, 2, rel));
    assert_eq!(t.log, vec![Ev::Cleanup(rel.to_vec())]);

    t.log.clear();
    let g = AgidGuard::new(&mut t, 2, rel);
    assert_eq!(g.agid(), 2);
    assert_eq!(g.defuse(), 2);
    assert!(t.log.is_empty(), "defuse hands the AGID over unreleased");
}
