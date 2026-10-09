use super::*;
use crate::UnlockCtx;

mod tests {
    use super::*;
    use crate::DiscKind;
    use crate::scsi::{DataDirection, Result, ScsiError, ScsiResult, ScsiTransport};

    #[test]
    fn memory_vid_rejects_invalid_responses_and_propagates_dead_bus() {
        use crate::scsi::mock::{MockTransport, Reply};
        for reply in [
            Reply::zero_transfer(16),
            Reply::short(vec![0x25; 16], 15),
            Reply::good(vec![0; 16]),
            Reply::good(vec![0xff; 16]),
            Reply::illegal_request(),
            Reply::illegal_request_as_err(),
        ] {
            let mut t =
                MockTransport::scripted(vec![Reply::good(vec![2]), reply], Reply::TransportFault);
            assert_eq!(read_vid(&mut t).unwrap(), None);
        }
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(read_vid(&mut t).unwrap_err(), UnlockError::Transport);
    }

    #[test]
    fn memory_vid_rejects_failed_status_with_payload_and_impossible_length() {
        struct Response {
            status: u8,
            transferred: usize,
        }
        impl ScsiTransport for Response {
            fn execute(
                &mut self,
                _: &[u8],
                dir: DataDirection,
                data: &mut [u8],
                timeout: u32,
            ) -> Result<ScsiResult> {
                assert_eq!(dir, DataDirection::FromDevice);
                if data.len() == 1 {
                    data[0] = 2;
                    return Ok(ScsiResult {
                        status: 0,
                        bytes_transferred: 1,
                        sense: [0; 32],
                    });
                }
                assert_eq!(data.len(), 16);
                assert_eq!(timeout, 5_000);
                data.fill(0x25);
                Ok(ScsiResult {
                    status: self.status,
                    bytes_transferred: self.transferred,
                    sense: [0; 32],
                })
            }
        }
        for (status, transferred) in [(2, 16), (0, 17), (0, usize::MAX)] {
            assert_eq!(
                read_vid(&mut Response {
                    status,
                    transferred
                })
                .unwrap(),
                None
            );
        }
    }

    #[test]
    fn cancellation_after_identity_aborts_before_register_read() {
        use crate::scsi::mock::{MockTransport, Reply, StopFake};
        let mut t = StopFake::new(MockTransport::always(Reply::good(renesas_payload())));
        t.cancel_after = Some(|cdb| cdb == pioneer_optical::cdb::vendor_identity());
        let id = crate::DriveId::default();
        let _ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        assert_eq!(unlock(&mut t).unwrap_err(), UnlockError::Transport);
        assert_eq!(t.inner.calls(), 1);
    }

    #[test]
    fn vendor_cdbs_are_the_wire_bytes() {
        assert_eq!(
            pioneer_optical::cdb::vendor_identity(),
            [0x3C, 0x02, 0xF1, 0, 0, 0, 0, 0, 0x30, 0]
        );
        assert_eq!(
            pioneer_optical::cdb::read_memory(0x50_0000, 0x10),
            [0x3C, 0x02, 0xB0, 0x50, 0, 0, 0, 0, 0x10, 0]
        );
        assert_eq!(
            pioneer_optical::cdb::knock(),
            [0x3B, 0x02, 0x41, 0xA5, 0xAA, 0xAA, 0, 0, 0, 0]
        );
        assert_eq!(RB_F1_LEN, 48);
    }

    /// Serves a fixed READ_BUFFER payload (Renesas-like) with a Good status.
    struct RenesasTransport {
        payload: Vec<u8>,
    }
    impl ScsiTransport for RenesasTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            let n = self.payload.len().min(data.len());
            data[..n].copy_from_slice(&self.payload[..n]);
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }

    // Rejects like a MediaTek drive: ILLEGAL REQUEST with a sense, which is
    // what distinguishes this from a dead bus.
    struct RejectingTransport;
    impl ScsiTransport for RejectingTransport {
        fn execute(
            &mut self,
            _cdb: &[u8],
            _dir: DataDirection,
            _data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<ScsiResult> {
            let mut sense = [0u8; 32];
            sense[2] = 0x05; // ILLEGAL REQUEST
            sense[12] = 0x20; // invalid command operation code
            Err(ScsiError {
                status: crate::scsi::SCSI_STATUS_CHECK_CONDITION,
                sense: Some(sense),
            })
        }
    }

    fn renesas_payload() -> Vec<u8> {
        // 48-byte RB 0xF1 block with "SAT" at [16..19] (the real S13JX shape).
        let mut p = vec![0x20u8; 48];
        p[16..19].copy_from_slice(b"SAT");
        p
    }

    #[test]
    fn is_renesas_true_on_sat_marker() {
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        assert!(is_renesas(&mut t).expect("no transport fault"));
    }

    #[test]
    fn is_renesas_false_when_command_rejected() {
        let mut t = RejectingTransport;
        assert!(!is_renesas(&mut t).expect("a drive rejection is not a bus fault"));
    }

    #[test]
    fn is_renesas_false_on_missing_marker() {
        // Good status but no "SAT" at [16..19] (e.g. a stray buffer).
        let mut t = RenesasTransport {
            payload: vec![0u8; 48],
        };
        assert!(!is_renesas(&mut t).expect("no transport fault"));
    }

    #[test]
    fn is_renesas_false_on_short_response() {
        // Fewer than 19 bytes returned — can't carry the marker.
        let mut t = RenesasTransport {
            payload: vec![0x20u8; 8],
        };
        assert!(!is_renesas(&mut t).expect("no transport fault"));
    }

    #[test]
    fn identity_alone_no_longer_reports_unlocked() {
        let mut t = RenesasTransport {
            payload: renesas_payload(),
        };
        let id = crate::DriveId::default();
        let _ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        assert!(unlock(&mut t).unwrap().is_none());
    }

    /// A drive REJECTION (ILLEGAL REQUEST, with a sense) is "not a Renesas
    /// drive" → `Ok(false)`, fall through to the next unlocker.
    #[test]
    fn declines_non_renesas() {
        let mut t = RejectingTransport;
        let id = crate::DriveId::default();
        let _ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        assert!(unlock(&mut t).expect("non-renesas declines").is_none());
    }

    // Same rejection via a CONFORMING transport (`Ok` + CHECK CONDITION);
    // must reach the same answer.
    #[test]
    fn check_condition_is_not_a_renesas_drive() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::illegal_request());
        assert!(!is_renesas(&mut t).expect("a drive sense is not a bus fault"));
    }

    /// THE defect-8 test: a dead bus on the FIRST command the unlocker issues
    /// must abort the consumer, not be reported as "not a Renesas drive".
    /// Catches restoring the `Err(_) => false` arm.
    #[test]
    fn transport_fault_aborts_instead_of_declining() {
        use crate::scsi::mock::{MockTransport, Reply};
        let mut t = MockTransport::always(Reply::TransportFault);
        assert_eq!(is_renesas(&mut t).unwrap_err(), UnlockError::Transport);

        let mut t = MockTransport::always(Reply::TransportFault);
        let id = crate::DriveId::default();
        let _ctx = UnlockCtx::new(&id, DiscKind::Unknown);
        assert_eq!(unlock(&mut t).unwrap_err(), UnlockError::Transport);
    }
}

mod hardware_tests {
    use super::*;
    use crate::scsi::mock::{MockTransport, Reply};

    #[test]
    fn reads_fresh_vid_with_status_mask_and_exact_wire_commands() {
        let mut t = MockTransport::scripted(
            vec![
                Reply::good(vec![3]),
                Reply::good(vec![0x25; 16]),
                Reply::good(vec![7]),
                Reply::good(vec![0x42; 16]),
            ],
            Reply::TransportFault,
        );
        assert_eq!(read_vid(&mut t).unwrap(), Some([0x25; 16]));
        assert_eq!(read_vid(&mut t).unwrap(), Some([0x42; 16]));
        assert_eq!(
            t.cdbs,
            vec![
                vec![0x3c, 2, 0x92, 0, 0x0d, 0x3c, 0, 0, 1, 0],
                vec![0x3c, 2, 0x92, 0, 0x0d, 0x20, 0, 0, 16, 0],
                VID_STATUS_CDB.to_vec(),
                VID_CDB.to_vec(),
            ]
        );
    }

    #[test]
    fn invalid_status_stops_before_vid() {
        for reply in [
            Reply::good(vec![0]),
            Reply::good(vec![1]),
            Reply::zero_transfer(1),
            Reply::short(vec![2], 2),
            Reply::illegal_request(),
            Reply::illegal_request_as_err(),
        ] {
            let mut t = MockTransport::scripted(vec![reply], Reply::TransportFault);
            assert_eq!(read_vid(&mut t).unwrap(), None);
            assert_eq!(t.calls(), 1);
        }
    }

    #[test]
    fn preparation_rejection_declines_and_transport_failure_aborts() {
        let mut identity = vec![0; 48];
        identity[16..19].copy_from_slice(b"SAT");
        let id = crate::DriveId::default();
        let _ctx = UnlockCtx::new(&id, crate::DiscKind::Unknown);
        for reply in [
            Reply::illegal_request(),
            Reply::illegal_request_as_err(),
            Reply::TransportFault,
        ] {
            let fault = matches!(reply, Reply::TransportFault);
            let mut t = MockTransport::scripted(
                vec![Reply::good(identity.clone()), reply],
                Reply::TransportFault,
            );
            let result = unlock(&mut t);
            if fault {
                assert_eq!(result.unwrap_err(), UnlockError::Transport);
            } else {
                assert!(result.unwrap().is_none());
            }
            assert_eq!(t.calls(), 2);
        }
    }

    #[test]
    fn cancellation_after_status_prevents_vid_command() {
        use crate::scsi::mock::StopFake;
        let mut t = StopFake::new(MockTransport::always(Reply::good(vec![2])));
        t.cancel_after = Some(|cdb| cdb == VID_STATUS_CDB);
        assert_eq!(read_vid(&mut t).unwrap_err(), UnlockError::Transport);
        assert_eq!(t.inner.calls(), 1);
    }
}
