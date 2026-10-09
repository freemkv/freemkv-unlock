use super::*;
use crate::scsi::{ScsiError, ScsiResult};
use std::collections::BTreeMap;

#[derive(Default)]
struct Drive {
    ram: BTreeMap<u32, u8>,
    critical: bool,
    spans: usize,
    activations: usize,
    fail_activation: bool,
    bad_state: bool,
    bad_nested: bool,
    bad_policy: bool,
    fail_policy_restore: bool,
    partial_policy_restore: usize,
    partial_stage: bool,
    partial_pointer: bool,
    partial_vid_pointer: bool,
    fail_vid_detach: bool,
    cancel: bool,
    cancelled: bool,
}
impl Drive {
    fn put(&mut self, at: u32, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.ram.insert(at + i as u32, *b);
        }
    }
    fn get(&self, at: u32, n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| *self.ram.get(&(at + i as u32)).unwrap_or(&0))
            .collect()
    }
}
fn fault() -> ScsiError {
    ScsiError {
        status: 0xff,
        sense: None,
    }
}
impl ScsiTransport for Drive {
    fn execute(
        &mut self,
        cdb: &[u8],
        direction: DataDirection,
        data: &mut [u8],
        _: u32,
    ) -> crate::scsi::Result<ScsiResult> {
        assert!(self.critical);
        if cdb[1..4] == [0x0e, 0xc0, 0xde] {
            self.activations += 1;
            assert_eq!(self.get(0xe20, 4), 0xa01040u32.to_be_bytes());
            self.put(
                operations::SECURITY_SLOT,
                &operations::policy_table(0xa01000, 1024).to_be_bytes(),
            );
            if self.bad_policy {
                self.put(operations::SECURITY_SLOT, &0xdeadbeefu32.to_be_bytes());
            }
            self.cancelled = self.cancel;
            if self.bad_nested {
                self.put(0xa0a966, &0xa01060u32.to_be_bytes());
            }
            if self.fail_activation {
                return Err(fault());
            }
            if !self.bad_state {
                self.put(0x2f86, &[0, 1, 0]);
            }
            data.fill(0);
        } else {
            let offset = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]);
            let at = offset + if cdb[2] == 0x93 { 0xa00000 } else { 0 };
            if direction == DataDirection::ToDevice {
                if at == 0xe28 && self.partial_vid_pointer {
                    self.partial_vid_pointer = false;
                    self.put(at, &data[..2]);
                    return Err(fault());
                }
                if at == 0xe28 && self.fail_vid_detach && data == 0x5b7700u32.to_be_bytes() {
                    return Err(fault());
                }
                if at == operations::SECURITY_SLOT && self.partial_policy_restore != 0 {
                    self.put(at, &data[..self.partial_policy_restore]);
                    return Err(fault());
                }
                if at == operations::SECURITY_SLOT && self.fail_policy_restore {
                    return Err(fault());
                }
                if at == 0xa01000 && self.partial_stage {
                    self.partial_stage = false;
                    self.put(at, &data[..data.len() / 2]);
                    return Err(fault());
                }
                if at == 0xe20 && self.partial_pointer {
                    self.partial_pointer = false;
                    self.put(at, &data[..2]);
                    return Err(fault());
                }
                self.put(at, data);
            } else {
                let pointer = self.get(0xe20, 4);
                if pointer != 0x5b754au32.to_be_bytes() && pointer != 0xa01040u32.to_be_bytes() {
                    return Err(fault());
                }
                data.copy_from_slice(&self.get(at, data.len()));
            }
        }
        Ok(ScsiResult {
            status: 0,
            bytes_transferred: data.len(),
            sense: [0; 32],
        })
    }
    fn begin_critical(&mut self) -> crate::scsi::Result<()> {
        assert!(!self.critical);
        self.critical = true;
        self.spans += 1;
        Ok(())
    }
    fn end_critical(&mut self) {
        assert!(self.critical);
        self.critical = false;
    }
    fn pause(&mut self, _: std::time::Duration) -> crate::scsi::Result<()> {
        assert!(!self.critical);
        if self.cancelled { Err(fault()) } else { Ok(()) }
    }
}
fn fixture() -> (Drive, Prepared) {
    let profile = Profile {
        normal_address: 0x410000,
        normal_length: 1,
        normal_sha256: String::new(),
        controller_cpu_base: 0xa00000,
        pointer_address: 0xe20,
        original_table: 0x5b754a,
        write_pointer_address: 0xe24,
        write_original_table: 0x5b7600,
        table_length: 40,
        main_callback_offset: 0x24,
        reserved_windows: vec![],
        occupied: vec![],
        guards: vec![operations::Operation::Suppress.guard()],
        ownership_evidence: String::new(),
        write_path_evidence: String::new(),
    };
    let p = Prepared {
        sites: operations::Sites::fixture(),
        operation: operations::Operation::Suppress,
        profile,
        allocation: Range::new(0xa01000, 1024).unwrap(),
        original: vec![0xaa; 1024],
        payload: vec![0x55; 1024],
        installed_pointer: 0xa01040u32.to_be_bytes().to_vec(),
        vid_installed_pointer: 0xa01080u32.to_be_bytes().to_vec(),
    };
    let mut d = Drive::default();
    d.put(0xe20, &p.profile.original_table.to_be_bytes());
    d.put(0xe24, &p.profile.write_original_table.to_be_bytes());
    d.put(p.sites.vid.slot, &p.sites.vid.table.to_be_bytes());
    d.put(0xa0a966, &p.profile.guards[0].expected);
    d.put(
        operations::SECURITY_SLOT,
        &operations::SECURITY_TABLE.to_be_bytes(),
    );
    d.put(p.allocation.start(), &p.original);
    (d, p)
}
fn restored(d: &Drive, p: &Prepared) {
    assert!(!d.critical);
    assert_eq!(
        d.get(operations::SECURITY_SLOT, 4),
        operations::SECURITY_TABLE.to_be_bytes()
    );
    assert_eq!(d.spans, 1);
    assert_eq!(d.get(0xe20, 4), p.profile.original_table.to_be_bytes());
    assert_eq!(d.get(p.sites.vid.slot, 4), p.sites.vid.table.to_be_bytes());
    assert_eq!(d.get(p.allocation.start(), p.original.len()), p.original);
}

#[test]
fn partial_vid_installation_restores_both_hooks_before_freeing_payload() {
    let (mut d, p) = fixture();
    d.partial_vid_pointer = true;
    assert!(finish(&mut d, &p).is_err());
    assert_eq!(d.activations, 0);
    restored(&d, &p);
}

#[test]
fn failed_vid_detachment_keeps_referenced_payload() {
    let (mut d, p) = fixture();
    d.fail_vid_detach = true;
    assert!(finish(&mut d, &p).is_err());
    assert_eq!(
        d.get(p.profile.pointer_address, 4),
        p.profile.original_table.to_be_bytes()
    );
    assert_eq!(d.get(p.sites.vid.slot, 4), p.vid_installed_pointer);
    assert_eq!(d.get(p.allocation.start(), p.payload.len()), p.payload);
}

#[test]
fn foreign_vid_hook_before_installation_is_not_overwritten() {
    let (mut d, p) = fixture();
    d.put(p.sites.vid.slot, &0xdeadbeefu32.to_be_bytes());
    assert!(finish(&mut d, &p).is_err());
    assert_eq!(d.activations, 0);
    assert_eq!(d.get(p.sites.vid.slot, 4), 0xdeadbeefu32.to_be_bytes());
    assert_eq!(d.get(p.allocation.start(), p.original.len()), p.original);
}
#[test]
fn success_detaches_and_restores_scratch() {
    let (mut d, p) = fixture();
    assert_eq!(finish(&mut d, &p).unwrap(), vec![0; 64]);
    assert_eq!(d.activations, 1);
    restored(&d, &p);
}
#[test]
fn activation_failure_still_restores() {
    let (mut d, p) = fixture();
    d.fail_activation = true;
    assert!(matches!(
        finish(&mut d, &p),
        Err(crate::UnlockError::Transport)
    ));
    restored(&d, &p);
}
#[test]
fn eligibility_verification_failure_still_restores() {
    let (mut d, p) = fixture();
    d.bad_state = true;
    assert!(finish(&mut d, &p).is_err());
    restored(&d, &p);
}
#[test]
fn partial_upload_is_restored_without_activation() {
    let (mut d, p) = fixture();
    d.partial_stage = true;
    assert!(finish(&mut d, &p).is_err());
    assert_eq!(d.activations, 0);
    restored(&d, &p);
}
#[test]
fn cancellation_is_delivered_after_restoration() {
    let (mut d, p) = fixture();
    d.cancel = true;
    assert!(matches!(
        finish(&mut d, &p),
        Err(crate::UnlockError::Transport)
    ));
    restored(&d, &p);
}
#[test]
fn dangling_nested_callback_keeps_payload_allocated_and_aborts() {
    let (mut d, p) = fixture();
    d.bad_nested = true;
    assert!(finish(&mut d, &p).is_err());
    assert!(!d.critical);
    assert_eq!(d.get(0xe20, 4), p.profile.original_table.to_be_bytes());
    assert_eq!(d.get(p.allocation.start(), p.payload.len()), p.payload);
}
#[test]
fn ownership_change_aborts_before_writes() {
    let (mut d, p) = fixture();
    d.put(0xe20, &0x123456u32.to_be_bytes());
    assert!(finish(&mut d, &p).is_err());
    assert_eq!(d.activations, 0);
    assert_eq!(d.get(0xe20, 4), 0x123456u32.to_be_bytes());
    assert_eq!(d.get(p.allocation.start(), p.original.len()), p.original);
}

#[test]
#[ignore = "requires RENESAS_REFERENCE_DUMP pointing to the archived UD04 dump"]
fn archived_image_builds_runtime_and_discovers_allocation() {
    let dump =
        std::fs::read(std::env::var_os("RENESAS_REFERENCE_DUMP").expect("reference dump path"))
            .unwrap();
    let image = &dump[0x410000..0x5d7500];
    let profile = discovery::profile(image).unwrap();
    {
        let op = operations::Operation::Suppress;
        let (payload, _) = operations::build(image, op).unwrap();
        assert_eq!(payload.source_sha256, profile.normal_sha256);
        let gaps = layout::free_ranges(
            &profile.reserved_windows,
            &profile.occupied,
            payload.alignment,
        )
        .unwrap();
        assert!(
            gaps.iter()
                .any(|g| g.length() >= payload.bytes.len() as u32)
        );
    }
}

#[test]
#[ignore = "requires RENESAS_REFERENCE_DUMP pointing to the archived UD04 dump"]
fn archived_fresh_backend_recognizes_resident_payload_without_upload() {
    use crate::freemkv::Backend as _;
    struct Snapshot {
        bytes: Vec<u8>,
        uploads: usize,
    }
    impl ScsiTransport for Snapshot {
        fn execute(
            &mut self,
            cdb: &[u8],
            direction: DataDirection,
            data: &mut [u8],
            _: u32,
        ) -> crate::scsi::Result<ScsiResult> {
            if cdb == pioneer_optical::cdb::knock() {
                assert_eq!(direction, DataDirection::None);
            } else {
                assert_eq!(cdb[1], 2);
                let offset = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]) as usize;
                let at = match cdb[2] {
                    0xb0 => offset,
                    0x93 => 0x800000 + offset,
                    _ => panic!("unexpected selector"),
                };
                match direction {
                    DataDirection::FromDevice => {
                        data.copy_from_slice(&self.bytes[at..at + data.len()])
                    }
                    DataDirection::ToDevice => {
                        self.uploads += 1;
                        self.bytes[at..at + data.len()].copy_from_slice(data);
                    }
                    DataDirection::None => panic!("unexpected no-data command"),
                }
            }
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: data.len(),
                sense: [0; 32],
            })
        }
    }
    let mut drive = Snapshot {
        bytes: std::fs::read(
            std::env::var_os("RENESAS_REFERENCE_DUMP").expect("reference dump path"),
        )
        .unwrap(),
        uploads: 0,
    };
    let prepared = prepare(&mut drive, operations::Operation::Suppress, false).unwrap();
    if let Some(path) = std::env::var_os("RENESAS_PAYLOAD_PLAN") {
        let plan = serde_json::json!({
            "base": prepared.allocation.start(),
            "payload": prepared.payload,
            "security_slot": prepared.sites.security_slot,
            "security_table": prepared.sites.security_table,
            "policy_table": prepared.sites.policy_table(prepared.allocation.start(), prepared.payload.len()),
            "acquisition_slot": prepared.sites.acquisition.cpu_address,
            "acquisition_table": u32::from_be_bytes(prepared.sites.acquisition.expected[..].try_into().unwrap()),
            "read_engine_state": prepared.sites.read_engine_state,
            "scheduler_delay": prepared.sites.scheduler_delay,
            "vid_slot": prepared.sites.vid.slot,
            "vid_table": prepared.sites.vid.table,
            "vid_installed_table": u32::from_be_bytes(prepared.vid_installed_pointer[..].try_into().unwrap()),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    }
    stage(&mut drive, &prepared).unwrap();
    let uploads = drive.uploads;
    for policy in [
        prepared.sites.security_table,
        prepared
            .sites
            .policy_table(prepared.allocation.start(), prepared.payload.len()),
    ] {
        let at = prepared.sites.security_slot as usize;
        drive.bytes[at..at + 4].copy_from_slice(&policy.to_be_bytes());
        let mut backend = crate::freemkv::renesas::Backend::new();
        backend.prepare(&mut drive, true).unwrap();
        backend.install(&mut drive, true).unwrap();
        assert_eq!(
            drive.uploads, uploads,
            "resident preparation must not upload again"
        );
        assert_eq!(backend.prepared.as_ref().unwrap().payload, prepared.payload);
    }
}

#[test]
fn partial_pointer_write_detaches_without_using_broken_read_path() {
    let (mut d, p) = fixture();
    d.partial_pointer = true;
    assert!(finish(&mut d, &p).is_err());
    assert_eq!(d.activations, 0);
    restored(&d, &p);
}

#[test]
fn resident_success_retains_code_and_reactivation_does_not_reinstall() {
    use crate::freemkv::Backend as _;
    let (mut d, p) = fixture();
    d.begin_critical().unwrap();
    check_prepared(&mut d, &p, false).unwrap();
    stage(&mut d, &p).unwrap();
    let mut backend = crate::freemkv::renesas::Backend {
        prepared: Some(p),
        existing: false,
        touched: true,
    };
    for _ in 0..2 {
        generic_cdb(
            &mut d,
            &operations::Operation::Suppress.cdb(),
            DataDirection::FromDevice,
            vec![0; 64],
        )
        .unwrap();
        backend.verify(&mut d).unwrap();
        backend.finish(&mut d, true).unwrap();
        let p = backend.prepared.as_ref().unwrap();
        assert_eq!(d.get(0xe20, 4), p.installed_pointer);
        assert_eq!(d.get(p.allocation.start(), p.payload.len()), p.payload);
    }
    assert_eq!(d.activations, 2);
    d.end_critical();
}

#[test]
fn final_verification_failure_detaches_new_installation() {
    use crate::freemkv::Backend as _;
    let (mut d, p) = fixture();
    d.begin_critical().unwrap();
    stage(&mut d, &p).unwrap();
    d.put(0x2f86, &[0, 1, 0]);
    d.put(
        operations::SECURITY_SLOT,
        &operations::policy_table(p.allocation.start(), p.payload.len()).to_be_bytes(),
    );
    let mut backend = crate::freemkv::renesas::Backend {
        prepared: Some(p),
        existing: false,
        touched: true,
    };
    backend.verify(&mut d).unwrap();
    d.put(0xa01000, &[0x99]);
    assert!(backend.finish(&mut d, true).is_err());
    d.end_critical();
    restored(&d, backend.prepared.as_ref().unwrap());
}
#[test]
fn pioneer_requires_exact_activation_reply_even_if_already_eligible() {
    use crate::freemkv::Backend as _;
    let backend = crate::freemkv::renesas::Backend::new();
    for n in [0, 1, 63, 65] {
        let r = ScsiResult {
            status: 0,
            bytes_transferred: n,
            sense: [0; 32],
        };
        assert!(backend.validate_set_reply(&r, &[0; 64]).is_err());
    }
    let r = ScsiResult {
        status: 0,
        bytes_transferred: 64,
        sense: [0; 32],
    };
    assert!(backend.validate_set_reply(&r, &[1; 64]).is_err());
    assert!(backend.validate_set_reply(&r, &[0; 64]).is_ok());
}

#[test]
fn policy_restoration_failure_keeps_referenced_payload() {
    for foreign in [false, true] {
        let (mut d, p) = fixture();
        d.fail_policy_restore = !foreign;
        d.bad_policy = foreign;
        assert!(finish(&mut d, &p).is_err());
        assert_eq!(d.get(0xe20, 4), p.profile.original_table.to_be_bytes());
        assert_eq!(d.get(p.allocation.start(), p.payload.len()), p.payload);
        assert_eq!(
            d.get(operations::SECURITY_SLOT, 4),
            if foreign {
                0xdeadbeef
            } else {
                operations::policy_table(p.allocation.start(), p.payload.len())
            }
            .to_be_bytes()
        );
    }
}

#[test]
fn partially_restored_security_pointer_never_reclaims_payload() {
    for prefix in 1..4 {
        let (mut d, p) = fixture();
        d.partial_policy_restore = prefix;
        assert!(finish(&mut d, &p).is_err());
        assert!(!d.critical);
        assert_eq!(d.get(0xe20, 4), p.profile.original_table.to_be_bytes());
        assert_eq!(d.get(p.allocation.start(), p.payload.len()), p.payload);
        let mut expected = p
            .sites
            .policy_table(p.allocation.start(), p.payload.len())
            .to_be_bytes();
        expected[..prefix].copy_from_slice(&p.sites.security_table.to_be_bytes()[..prefix]);
        assert_eq!(d.get(p.sites.security_slot, 4), expected);
    }
}

#[test]
fn foreign_policy_before_installation_is_not_overwritten() {
    let (mut d, p) = fixture();
    d.put(operations::SECURITY_SLOT, &0xdeadbeefu32.to_be_bytes());
    assert!(finish(&mut d, &p).is_err());
    assert_eq!(d.activations, 0);
    assert_eq!(
        d.get(operations::SECURITY_SLOT, 4),
        0xdeadbeefu32.to_be_bytes()
    );
    assert_eq!(d.get(p.allocation.start(), p.original.len()), p.original);
}
