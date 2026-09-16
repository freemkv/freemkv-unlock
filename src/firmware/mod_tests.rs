//! Tests for the firmware vendor-command mirror + [`FirmwareControl`].

use super::*;
use crate::scsi::mock::{MockTransport, Reply};
use crate::scsi::{DataDirection, Result as ScsiTResult, ScsiResult, ScsiTransport};

// ── Pinned-value drift guards (vs. freemkv-fw/src/abi.rs) ────────────────────

#[test]
fn verb_values_match_abi() {
    assert_eq!(Verb::Identity as u8, 0x01);
    assert_eq!(Verb::Set as u8, 0x02);
    assert_eq!(Verb::Get as u8, 0x03);
    assert_eq!(Verb::Reset as u8, 0x04);
    assert_eq!(Verb::DumpAll as u8, 0x09);
}

#[test]
fn feature_values_match_abi() {
    assert_eq!(Feature::Speed as u8, 0x01);
    assert_eq!(Feature::Region as u8, 0x02);
    assert_eq!(Feature::Uhd as u8, 0x03);
    assert_eq!(Feature::Bd as u8, 0x04);
    assert_eq!(Feature::Hrl as u8, 0x05);
    assert_eq!(Feature::Ake as u8, 0x06);
    assert_eq!(Feature::Bus as u8, 0x07);
}

#[test]
fn state_and_frame_constants_match_abi() {
    assert_eq!(READ_BUFFER_OPCODE, 0x3C);
    assert_eq!(KNOCK_MODE, 0x0E);
    assert_eq!(KNOCK, [0xC0, 0xDE]);
    assert_eq!(RESP_MAGIC, b"freemkv");
    assert_eq!(CDB_LEN, 10);
    assert_eq!(MEMREAD_LEN, 64);
    assert_eq!(STATE_PASSTHROUGH, 0xFF);
    assert_eq!(STATE_OFF, 0x00);
    assert_eq!(STATE_ON, 0x01);
    assert_eq!(SPEED_MAX, 0x01);
    assert_eq!(STATE_BD_DISABLE, 0x02);
    assert_eq!([REGION_BD_A, REGION_BD_B, REGION_BD_C], [0x2A, 0x2B, 0x2C]);
    assert_eq!(REGION_DVD_BASE, 0x10);
}

// ── CDB builders ─────────────────────────────────────────────────────────────

#[test]
fn build_set_cdb_exact_bytes() {
    // SET Ake = ON: verb 02, feature 06, state 01, no alloc.
    assert_eq!(
        build_set_cdb(Feature::Ake, STATE_ON),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x06, 0x01, 0x00, 0x00, 0x00]
    );
}

#[test]
fn build_get_cdb_exact_bytes() {
    // GET Bus: verb 03, feature 07, alloc 1 at cdb[7..9] big-endian.
    assert_eq!(
        build_get_cdb(Feature::Bus),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x03, 0x07, 0x00, 0x00, 0x01, 0x00]
    );
}

#[test]
fn build_reset_and_identity_cdb_exact_bytes() {
    assert_eq!(
        build_reset_cdb(),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    // IDENTITY with a 64-byte allocation (0x0040 big-endian at cdb[7..9]).
    assert_eq!(
        build_identity_cdb(MEMREAD_LEN as u16),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00]
    );
}

#[test]
fn build_cdb_encodes_alloc_len_16bit_big_endian() {
    let cdb = build_cdb(Verb::Identity, None, None, 0x1234);
    assert_eq!([cdb[CDB_ALLOC_LEN], cdb[CDB_ALLOC_LEN + 1]], [0x12, 0x34]);
}

#[test]
fn build_memread_cdb_packs_address_big_endian_at_5_to_9() {
    let cdb = build_memread_cdb(0xDEAD_BEEF);
    assert_eq!(cdb[CDB_VERB], Verb::DumpAll as u8);
    assert_eq!([cdb[5], cdb[6], cdb[7], cdb[8]], [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(cdb[9], 0x00);
}

#[test]
fn region_state_bytes() {
    assert_eq!(BdRegion::A.state(), 0x2A);
    assert_eq!(BdRegion::B.state(), 0x2B);
    assert_eq!(BdRegion::C.state(), 0x2C);
}

// ── Identity / states parsing ────────────────────────────────────────────────

#[test]
fn identity_parse_reads_version_and_table() {
    let mut payload = Vec::new();
    payload.extend_from_slice(RESP_MAGIC);
    payload.push(0x17); // version
    // table in ALL_FEATURES order: Speed, Region, Uhd, Bd, Hrl, Ake, Bus
    payload.extend_from_slice(&[
        SPEED_MAX,
        STATE_ON,
        STATE_ON,
        STATE_PASSTHROUGH,
        STATE_ON,
        STATE_OFF,
        STATE_ON,
    ]);
    let id = FirmwareIdentity::parse(&payload).expect("has magic");
    assert_eq!(id.version, 0x17);
    assert_eq!(id.states.speed, SPEED_MAX);
    assert_eq!(id.states.region, STATE_ON);
    assert_eq!(id.states.uhd, STATE_ON);
    assert_eq!(id.states.bd, STATE_PASSTHROUGH);
    assert_eq!(id.states.hrl, STATE_ON);
    assert_eq!(id.states.ake, STATE_OFF);
    assert_eq!(id.states.bus, STATE_ON);
}

#[test]
fn identity_parse_none_without_magic() {
    assert!(FirmwareIdentity::parse(&[0u8; 64]).is_none());
}

#[test]
fn identity_parse_short_table_defaults_to_passthrough() {
    let mut payload = Vec::new();
    payload.extend_from_slice(RESP_MAGIC);
    payload.push(0x01);
    // no table bytes at all
    let id = FirmwareIdentity::parse(&payload).expect("has magic");
    assert_eq!(id.states, FeatureStates::all_passthrough());
}

// ── A stateful firmware mock ─────────────────────────────────────────────────

/// A mock freemkv drive: answers IDENTITY with magic+version+table, GET with the
/// requested feature's state, applies SET, and RESET → all-passthrough. Records
/// every CDB so tests can assert the exact command order.
struct FwMock {
    version: u8,
    states: FeatureStates,
    is_freemkv: bool,
    cdbs: Vec<Vec<u8>>,
}

impl FwMock {
    fn new() -> Self {
        FwMock {
            version: 0x42,
            states: FeatureStates::all_passthrough(),
            is_freemkv: true,
            cdbs: Vec::new(),
        }
    }
    fn feature_of(id: u8) -> Feature {
        *ALL_FEATURES
            .iter()
            .find(|f| **f as u8 == id)
            .expect("known feature id")
    }
    /// The verbs issued, in order (cdb[4] of each recorded CDB).
    fn verbs(&self) -> Vec<u8> {
        self.cdbs.iter().map(|c| c[CDB_VERB]).collect()
    }
}

impl ScsiTransport for FwMock {
    fn execute(
        &mut self,
        cdb: &[u8],
        _dir: DataDirection,
        data: &mut [u8],
        _timeout_ms: u32,
    ) -> ScsiTResult<ScsiResult> {
        self.cdbs.push(cdb.to_vec());
        let mut transferred = 0usize;
        match cdb[CDB_VERB] {
            v if v == Verb::Identity as u8 => {
                if self.is_freemkv {
                    let mut resp = Vec::new();
                    resp.extend_from_slice(RESP_MAGIC);
                    resp.push(self.version);
                    for f in ALL_FEATURES {
                        resp.push(self.states.get(f));
                    }
                    let n = resp.len().min(data.len());
                    data[..n].copy_from_slice(&resp[..n]);
                    transferred = n;
                }
                // non-freemkv: GOOD status but no magic (buffer stays zero)
                if !self.is_freemkv {
                    transferred = data.len();
                }
            }
            v if v == Verb::Get as u8 => {
                let f = Self::feature_of(cdb[CDB_FEATURE]);
                if !data.is_empty() {
                    data[0] = self.states.get(f);
                    transferred = 1;
                }
            }
            v if v == Verb::Set as u8 => {
                let f = Self::feature_of(cdb[CDB_FEATURE]);
                self.states.set(f, cdb[CDB_STATE]);
            }
            v if v == Verb::Reset as u8 => {
                self.states = FeatureStates::all_passthrough();
            }
            v if v == Verb::DumpAll as u8 => {
                for (i, b) in data.iter_mut().enumerate() {
                    *b = i as u8;
                }
                transferred = data.len();
            }
            _ => {}
        }
        Ok(ScsiResult {
            status: 0,
            bytes_transferred: transferred,
            sense: [0u8; 32],
        })
    }
}

// ── FirmwareControl behaviour ────────────────────────────────────────────────

#[test]
fn identity_detects_freemkv_and_issues_identity_cdb() {
    let mut m = FwMock::new();
    m.states.ake = STATE_ON;
    {
        let mut fw = FirmwareControl::new(&mut m);
        let id = fw.identity().expect("no fault").expect("is freemkv");
        assert_eq!(id.version, 0x42);
        assert_eq!(id.states.ake, STATE_ON);
        assert!(fw.is_freemkv().expect("no fault"));
    }
    assert_eq!(m.cdbs[0], build_identity_cdb(MEMREAD_LEN as u16));
}

#[test]
fn identity_none_on_non_freemkv() {
    let mut m = FwMock::new();
    m.is_freemkv = false;
    let mut fw = FirmwareControl::new(&mut m);
    assert!(fw.identity().expect("no fault").is_none());
    assert!(!fw.is_freemkv().expect("no fault"));
}

#[test]
fn identity_none_when_drive_rejects() {
    let mut t = MockTransport::always(Reply::illegal_request());
    let mut fw = FirmwareControl::new(&mut t);
    assert!(fw.identity().expect("rejection is not a fault").is_none());
}

#[test]
fn identity_transport_fault_propagates() {
    let mut t = MockTransport::always(Reply::TransportFault);
    let mut fw = FirmwareControl::new(&mut t);
    assert_eq!(fw.identity().unwrap_err(), FirmwareError::Transport);
}

#[test]
fn get_and_set_roundtrip_issue_the_right_cdbs() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        assert_eq!(fw.get(Feature::Bus).expect("get"), STATE_PASSTHROUGH);
        fw.set(Feature::Bus, STATE_ON).expect("set");
        assert_eq!(fw.get(Feature::Bus).expect("get"), STATE_ON);
    }
    assert_eq!(m.cdbs[0], build_get_cdb(Feature::Bus));
    assert_eq!(m.cdbs[1], build_set_cdb(Feature::Bus, STATE_ON));
    assert_eq!(m.cdbs[2], build_get_cdb(Feature::Bus));
}

#[test]
fn reset_sends_reset_cdb_and_clears_state() {
    let mut m = FwMock::new();
    m.states.ake = STATE_ON;
    m.states.bus = STATE_ON;
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.reset().expect("reset");
    }
    assert_eq!(m.cdbs[0], build_reset_cdb());
    assert_eq!(m.states, FeatureStates::all_passthrough());
}

#[test]
fn states_probes_every_feature_in_order() {
    let mut m = FwMock::new();
    m.states.speed = SPEED_MAX;
    m.states.hrl = STATE_ON;
    let states;
    {
        let mut fw = FirmwareControl::new(&mut m);
        states = fw.states().expect("states");
    }
    assert_eq!(states.speed, SPEED_MAX);
    assert_eq!(states.hrl, STATE_ON);
    // Seven GETs, one per feature, in ALL_FEATURES order.
    assert_eq!(m.cdbs.len(), 7);
    let features: Vec<u8> = m.cdbs.iter().map(|c| c[CDB_FEATURE]).collect();
    assert_eq!(features, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    assert!(m.verbs().iter().all(|&v| v == Verb::Get as u8));
}

#[test]
fn dump_issues_memread_and_returns_the_window() {
    let mut m = FwMock::new();
    let got;
    {
        let mut fw = FirmwareControl::new(&mut m);
        got = fw.dump(0x0102_0304).expect("dump");
    }
    assert_eq!(got[0], 0x00);
    assert_eq!(got[63], 63);
    assert_eq!(m.cdbs[0], build_memread_cdb(0x0102_0304));
}

// ── Typed setters ────────────────────────────────────────────────────────────

#[test]
fn typed_setters_issue_expected_set_cdbs() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.enable_uhd().unwrap();
        fw.disable_bd().unwrap();
        fw.skip_hrl().unwrap();
        fw.null_ake().unwrap();
        fw.bus_off().unwrap();
        fw.region_free().unwrap();
        fw.force_region_bd(BdRegion::B).unwrap();
        fw.force_region_dvd(2).unwrap();
        fw.unlock_speed().unwrap();
    }
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Uhd, STATE_ON));
    assert_eq!(m.cdbs[1], build_set_cdb(Feature::Bd, STATE_BD_DISABLE));
    assert_eq!(m.cdbs[2], build_set_cdb(Feature::Hrl, STATE_ON));
    assert_eq!(m.cdbs[3], build_set_cdb(Feature::Ake, STATE_ON));
    assert_eq!(m.cdbs[4], build_set_cdb(Feature::Bus, STATE_ON));
    assert_eq!(m.cdbs[5], build_set_cdb(Feature::Region, STATE_ON));
    assert_eq!(m.cdbs[6], build_set_cdb(Feature::Region, REGION_BD_B));
    assert_eq!(m.cdbs[7], build_set_cdb(Feature::Region, 0x12));
    assert_eq!(m.cdbs[8], build_set_cdb(Feature::Speed, SPEED_MAX));
}

#[test]
fn force_region_dvd_rejects_out_of_range() {
    let mut m = FwMock::new();
    let mut fw = FirmwareControl::new(&mut m);
    assert_eq!(fw.force_region_dvd(0).unwrap_err(), FirmwareError::Rejected);
    assert_eq!(fw.force_region_dvd(9).unwrap_err(), FirmwareError::Rejected);
}

// ── Recipes ──────────────────────────────────────────────────────────────────

#[test]
fn arm_oem_bd_sets_and_verifies_hrl_skip() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_oem_bd().expect("armed");
    }
    // SET Hrl=ON, then GET Hrl to verify.
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Hrl, STATE_ON));
    assert_eq!(m.cdbs[1], build_get_cdb(Feature::Hrl));
    assert_eq!(m.states.hrl, STATE_ON);
}

#[test]
fn arm_oem_uhd_sets_uhd_hrl_bus_each_verified() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_oem_uhd().expect("armed");
    }
    let verbs = m.verbs();
    // set,get, set,get, set,get
    assert_eq!(
        verbs,
        vec![0x02, 0x03, 0x02, 0x03, 0x02, 0x03],
        "each set is verified by a get"
    );
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Uhd, STATE_ON));
    assert_eq!(m.cdbs[2], build_set_cdb(Feature::Hrl, STATE_ON));
    assert_eq!(m.cdbs[4], build_set_cdb(Feature::Bus, STATE_ON));
    assert_eq!(m.states.uhd, STATE_ON);
    assert_eq!(m.states.hrl, STATE_ON);
    assert_eq!(m.states.bus, STATE_ON);
}

#[test]
fn arm_bypass_bd_nulls_ake() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_bypass_bd().expect("armed");
    }
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Ake, STATE_ON));
    assert_eq!(m.cdbs[1], build_get_cdb(Feature::Ake));
    assert_eq!(m.states.ake, STATE_ON);
}

#[test]
fn arm_bypass_uhd_sets_uhd_ake_bus() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_bypass_uhd().expect("armed");
    }
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Uhd, STATE_ON));
    assert_eq!(m.cdbs[2], build_set_cdb(Feature::Ake, STATE_ON));
    assert_eq!(m.cdbs[4], build_set_cdb(Feature::Bus, STATE_ON));
    assert_eq!(m.states.uhd, STATE_ON);
    assert_eq!(m.states.ake, STATE_ON);
    assert_eq!(m.states.bus, STATE_ON);
}

#[test]
fn arm_stealth_oem_resets_then_verifies_all_passthrough() {
    let mut m = FwMock::new();
    m.states.ake = STATE_ON;
    m.states.uhd = STATE_ON;
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_stealth_oem().expect("disarmed");
    }
    assert_eq!(m.cdbs[0], build_reset_cdb());
    // then a GET of every feature
    assert_eq!(m.cdbs.len(), 1 + ALL_FEATURES.len());
    assert!(m.cdbs[1..].iter().all(|c| c[CDB_VERB] == Verb::Get as u8));
    assert_eq!(m.states, FeatureStates::all_passthrough());
}

#[test]
fn arm_by_recipe_enum_dispatches() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm(ArmRecipe::BypassBd).expect("armed");
    }
    assert_eq!(m.states.ake, STATE_ON);
}

#[test]
fn set_verify_reports_mismatch() {
    // A drive that ACKs the SET but never actually changes the state: GET reads
    // back the old value, so the verify fails.
    struct StuckDrive;
    impl ScsiTransport for StuckDrive {
        fn execute(
            &mut self,
            cdb: &[u8],
            _dir: DataDirection,
            data: &mut [u8],
            _timeout_ms: u32,
        ) -> ScsiTResult<ScsiResult> {
            let mut n = 0;
            if cdb[CDB_VERB] == Verb::Get as u8 && !data.is_empty() {
                data[0] = STATE_PASSTHROUGH; // never changes
                n = 1;
            }
            Ok(ScsiResult {
                status: 0,
                bytes_transferred: n,
                sense: [0u8; 32],
            })
        }
    }
    let mut d = StuckDrive;
    let mut fw = FirmwareControl::new(&mut d);
    let err = fw.arm_bypass_bd().unwrap_err();
    assert_eq!(
        err,
        FirmwareError::VerifyFailed {
            feature: Feature::Ake,
            wanted: STATE_ON,
            got: STATE_PASSTHROUGH,
        }
    );
}

#[test]
fn recipe_transport_fault_propagates() {
    let mut t = MockTransport::always(Reply::TransportFault);
    let mut fw = FirmwareControl::new(&mut t);
    assert_eq!(fw.arm_oem_bd().unwrap_err(), FirmwareError::Transport);
}
