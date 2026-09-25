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
    assert_eq!(Verb::FlashWrite as u8, 0x0A);
    assert_eq!(Verb::Save as u8, 0x0B);
    assert_eq!(Verb::Call as u8, 0x0C);
    assert_eq!(Verb::Poke as u8, 0x0D);
    assert_eq!(Verb::Reboot as u8, 0x0F);
}

#[test]
fn feature_values_match_abi() {
    assert_eq!(Feature::Speed as u8, 0x01);
    assert_eq!(Feature::Region as u8, 0x02);
    assert_eq!(Feature::Unrestricted as u8, 0x03);
    assert_eq!(Feature::Hrl as u8, 0x05);
    assert_eq!(Feature::Encryption as u8, 0x06);
    // Wire id 0x04 (was `Bd`) is retired — fw 0.9.2 unified BD+UHD into
    // Unrestricted; the BD slot is now unused/reserved (fw no-ops it).
    // Wire id 0x07 (was `Bus`) is retired — proven inert on BU40N/MT1959.
    assert_eq!(ALL_FEATURES.len(), 5);
}

#[test]
fn debug_knock_distinct_from_safe_knock() {
    // The fw dispatches Call/Poke ONLY under DEBUG_KNOCK; a typo of a safe verb
    // vs a debug verb under the wrong knock never crosses the line.
    assert_ne!(KNOCK, DEBUG_KNOCK);
    assert_eq!(DEBUG_KNOCK, [0xDE, 0xB9]);
}

#[test]
fn state_and_frame_constants_match_abi() {
    assert_eq!(READ_BUFFER_OPCODE, 0x3C);
    assert_eq!(KNOCK_MODE, 0x0E);
    assert_eq!(KNOCK, [0xC0, 0xDE]);
    assert_eq!(RESP_MAGIC, b"freemkv");
    assert_eq!(CDB_LEN, 10);
    assert_eq!(MEMREAD_LEN, 64);
    assert_eq!(MIN_ALLOC_LEN, 64);
    assert_eq!(STATE_PASSTHROUGH, 0xFF);
    assert_eq!(STATE_OFF, 0x00);
    assert_eq!(STATE_ON, 0x01);
    assert_eq!(SPEED_MAX, 0x00);
    assert_eq!([REGION_BD_A, REGION_BD_B, REGION_BD_C], [0x0A, 0x0B, 0x0C]);
    assert_eq!(REGION_DVD_BASE, 0x00);
    assert_eq!(REGION_FREE, 0x0F);
    assert_eq!(RESET_TO_FLASH, 0x00);
    assert_eq!(RESET_TO_DEFAULTS, 0x01);
    assert_eq!(RESET_TO_OEM, 0xFF);
}

// ── CDB builders ─────────────────────────────────────────────────────────────

#[test]
fn build_set_cdb_exact_bytes() {
    // SET Encryption = ON: verb 02, feature 06, state 01, alloc MIN_ALLOC_LEN
    // (0x0040) at cdb[7..9] big-endian — the drive aborts a sub-16-byte data-in.
    assert_eq!(
        build_set_cdb(Feature::Encryption, STATE_ON),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x02, 0x06, 0x01, 0x00, 0x40, 0x00]
    );
}

#[test]
fn build_get_cdb_exact_bytes() {
    // GET Encryption: verb 03, feature 06, alloc MIN_ALLOC_LEN (0x0040) at
    // cdb[7..9] big-endian — the drive aborts a 1-byte data-in; state read
    // from offset 0.
    assert_eq!(
        build_get_cdb(Feature::Encryption),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x03, 0x06, 0x00, 0x00, 0x40, 0x00]
    );
}

#[test]
fn vendor_commands_floor_alloc_len_at_min_for_hw() {
    // HW-confirmed: the drive aborts a vendor command with a sub-16-byte data-in
    // allocation, so SET/GET/RESET all request at least MIN_ALLOC_LEN (= 64,
    // comfortably above the ~16-byte hardware floor).
    assert_eq!(MIN_ALLOC_LEN, 64);
    let alloc =
        |cdb: &[u8; CDB_LEN]| u16::from_be_bytes([cdb[CDB_ALLOC_LEN], cdb[CDB_ALLOC_LEN + 1]]);
    assert_eq!(
        alloc(&build_set_cdb(Feature::Encryption, STATE_ON)),
        MIN_ALLOC_LEN
    );
    assert_eq!(alloc(&build_get_cdb(Feature::Encryption)), MIN_ALLOC_LEN);
    assert_eq!(alloc(&build_reset_cdb(RESET_TO_OEM)), MIN_ALLOC_LEN);
    assert_eq!(alloc(&build_save_cdb()), MIN_ALLOC_LEN);
}

#[test]
fn build_call_and_poke_cdb_exact_bytes() {
    // Call: verb 0x0C at cdb[4], DEBUG_KNOCK at cdb[2..4], target big-endian
    // in cdb[5..9], r0 in cdb[9].
    assert_eq!(
        build_call_cdb(0x0102_0304, 0xAB),
        [0x3C, 0x0E, 0xDE, 0xB9, 0x0C, 0x01, 0x02, 0x03, 0x04, 0xAB]
    );
    // Poke: verb 0x0D at cdb[4], DEBUG_KNOCK at cdb[2..4], target big-endian
    // in cdb[5..9], value in cdb[9].
    assert_eq!(
        build_poke_cdb(0x0200_0E40, 0xAA),
        [0x3C, 0x0E, 0xDE, 0xB9, 0x0D, 0x02, 0x00, 0x0E, 0x40, 0xAA]
    );
    // Reboot: verb 0x0F at cdb[4], DEBUG_KNOCK at cdb[2..4], no on-wire target
    // (the boot-entry VA is baked into the handler at build time). Alloc floors
    // at MIN_ALLOC_LEN (0x0040 at cdb[7..9]) so the data-in is not aborted.
    assert_eq!(
        build_reboot_cdb(),
        [0x3C, 0x0E, 0xDE, 0xB9, 0x0F, 0x00, 0x00, 0x00, 0x40, 0x00]
    );
}

#[test]
fn build_reset_and_identity_cdb_exact_bytes() {
    // RESET carries its mode in the state slot (cdb[6]) and floors its data-in at
    // MIN_ALLOC_LEN (0x0040) for the same HW reason: to-OEM = 0xFF, to-flash = 0x00.
    assert_eq!(
        build_reset_cdb(RESET_TO_OEM),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x00, 0xFF, 0x00, 0x40, 0x00]
    );
    assert_eq!(
        build_reset_cdb(RESET_TO_FLASH),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00]
    );
    // SAVE takes no feature/state and floors its data-in at MIN_ALLOC_LEN.
    assert_eq!(
        build_save_cdb(),
        [0x3C, 0x0E, 0xC0, 0xDE, 0x0B, 0x00, 0x00, 0x00, 0x40, 0x00]
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
    assert_eq!(BdRegion::A.state(), 0x0A);
    assert_eq!(BdRegion::B.state(), 0x0B);
    assert_eq!(BdRegion::C.state(), 0x0C);
}

// ── Identity / states parsing ────────────────────────────────────────────────

#[test]
fn identity_parse_reads_version_banner() {
    // The firmware answers IDENTITY with the ASCII banner `freemkv <ver>`,
    // NUL-padded — there is no binary state table.
    let mut payload = Vec::new();
    payload.extend_from_slice(RESP_MAGIC);
    payload.extend_from_slice(b" 0.7.1\0");
    payload.resize(64, 0); // NUL-pad to the allocation window
    let id = FirmwareIdentity::parse(&payload).expect("has magic");
    assert_eq!(id.version, "0.7.1");
}

#[test]
fn identity_parse_none_without_magic() {
    assert!(FirmwareIdentity::parse(&[0u8; 64]).is_none());
}

// ── A stateful firmware mock ─────────────────────────────────────────────────

/// A mock freemkv drive: answers IDENTITY with the `freemkv <ver>` banner, GET
/// with the requested feature's state, applies SET, and RESET → all-passthrough.
/// Records every CDB so tests can assert the exact command order.
///
/// It also models the real hardware constraint: any vendor verb executed with
/// [`DataDirection::None`] (no data-in phase) is REJECTED with a non-zero
/// status, exactly as the drive's READ BUFFER hijack aborts a no-data verb.
struct FwMock {
    version: &'static str,
    states: FeatureStates,
    /// The saved flash config block: SAVE snapshots `states` into it, RESET
    /// with RESET_TO_FLASH reloads it, RESET_TO_OEM forces all-passthrough.
    saved: FeatureStates,
    is_freemkv: bool,
    cdbs: Vec<Vec<u8>>,
}

impl FwMock {
    fn new() -> Self {
        FwMock {
            version: "0.6.6",
            states: FeatureStates::all_passthrough(),
            saved: FeatureStates::all_passthrough(),
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
        dir: DataDirection,
        data: &mut [u8],
        _timeout_ms: u32,
    ) -> ScsiTResult<ScsiResult> {
        self.cdbs.push(cdb.to_vec());
        // Model the hardware: a vendor verb with no data-in phase is aborted.
        // This is what makes the old `exec_none` SET/RESET path a test failure.
        let is_vendor = cdb[CDB_OPCODE] == READ_BUFFER_OPCODE && cdb[CDB_MODE] == KNOCK_MODE;
        if is_vendor && matches!(dir, DataDirection::None) {
            return Ok(ScsiResult {
                status: 0x02, // CHECK CONDITION — rejected
                bytes_transferred: 0,
                sense: [0u8; 32],
            });
        }
        let mut transferred = 0usize;
        match cdb[CDB_VERB] {
            v if v == Verb::Identity as u8 => {
                if self.is_freemkv {
                    // The `freemkv <ver>` banner, NUL-terminated.
                    let mut resp = Vec::new();
                    resp.extend_from_slice(RESP_MAGIC);
                    resp.push(b' ');
                    resp.extend_from_slice(self.version.as_bytes());
                    resp.push(0);
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
                // The mode rides in the state slot (cdb[6]): to-OEM forces
                // all-passthrough, to-flash reloads the saved config block.
                self.states = if cdb[CDB_STATE] == RESET_TO_FLASH {
                    self.saved
                } else {
                    FeatureStates::all_passthrough()
                };
            }
            v if v == Verb::Save as u8 => {
                self.saved = self.states;
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
    m.states.encryption = STATE_ON;
    {
        let mut fw = FirmwareControl::new(&mut m);
        let id = fw.identity().expect("no fault").expect("is freemkv");
        assert_eq!(id.version, "0.6.6");
        // States no longer ride in IDENTITY — read them via GET.
        assert_eq!(fw.get(Feature::Encryption).expect("get"), STATE_ON);
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
        assert_eq!(fw.get(Feature::Encryption).expect("get"), STATE_PASSTHROUGH);
        fw.set(Feature::Encryption, STATE_ON).expect("set");
        assert_eq!(fw.get(Feature::Encryption).expect("get"), STATE_ON);
    }
    assert_eq!(m.cdbs[0], build_get_cdb(Feature::Encryption));
    assert_eq!(m.cdbs[1], build_set_cdb(Feature::Encryption, STATE_ON));
    assert_eq!(m.cdbs[2], build_get_cdb(Feature::Encryption));
}

#[test]
fn reset_sends_reset_cdb_and_clears_state() {
    let mut m = FwMock::new();
    m.states.encryption = STATE_ON;
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.reset().expect("reset");
    }
    assert_eq!(m.cdbs[0], build_reset_cdb(RESET_TO_OEM));
    assert_eq!(m.states, FeatureStates::all_passthrough());
}

#[test]
fn reset_to_defaults_sends_the_defaults_mode_cdb() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.reset_to_defaults().expect("reset to defaults");
    }
    assert_eq!(m.cdbs[0], build_reset_cdb(RESET_TO_DEFAULTS));
}

#[test]
fn save_then_reset_to_flash_restores_the_saved_value() {
    // SET a feature, SAVE it, force all-passthrough with RESET(to-OEM), then
    // RESET(to-flash) must reload the saved value (not passthrough).
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.set(Feature::Encryption, STATE_OFF).expect("set");
        fw.save().expect("save");
        fw.reset().expect("reset to OEM");
        assert_eq!(fw.get(Feature::Encryption).expect("get"), STATE_PASSTHROUGH);
        fw.reset_to_flash().expect("reset to flash");
        assert_eq!(fw.get(Feature::Encryption).expect("get"), STATE_OFF);
    }
    // The verbs issued, in order: SET, SAVE, RESET, GET, RESET, GET.
    assert_eq!(
        m.verbs(),
        vec![
            Verb::Set as u8,
            Verb::Save as u8,
            Verb::Reset as u8,
            Verb::Get as u8,
            Verb::Reset as u8,
            Verb::Get as u8,
        ]
    );
    assert_eq!(m.cdbs[1], build_save_cdb());
    assert_eq!(m.cdbs[2], build_reset_cdb(RESET_TO_OEM));
    assert_eq!(m.cdbs[4], build_reset_cdb(RESET_TO_FLASH));
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
    // Five GETs, one per feature, in ALL_FEATURES order (Bd id 0x04 and Bus id
    // 0x07 both retired).
    assert_eq!(m.cdbs.len(), 5);
    let features: Vec<u8> = m.cdbs.iter().map(|c| c[CDB_FEATURE]).collect();
    assert_eq!(features, vec![0x01, 0x02, 0x03, 0x05, 0x06]);
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
        fw.enable_unrestricted().unwrap();
        fw.skip_hrl().unwrap();
        fw.disable_encryption().unwrap();
        fw.region_free().unwrap();
        fw.force_region_bd(BdRegion::B).unwrap();
        fw.force_region_dvd(2).unwrap();
        fw.unlock_speed().unwrap();
    }
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Unrestricted, STATE_ON));
    // The HRL/Encryption unlock direction is STATE_OFF (0x00), not STATE_ON.
    assert_eq!(m.cdbs[1], build_set_cdb(Feature::Hrl, STATE_OFF));
    assert_eq!(m.cdbs[2], build_set_cdb(Feature::Encryption, STATE_OFF));
    // Region-free is REGION_FREE (0x0F) — 0x01 now forces DVD region 1.
    assert_eq!(m.cdbs[3], build_set_cdb(Feature::Region, REGION_FREE));
    assert_eq!(m.cdbs[4], build_set_cdb(Feature::Region, REGION_BD_B));
    // force_region_dvd(2) = REGION_DVD_BASE + 2 = 0x02 under the new base.
    assert_eq!(m.cdbs[5], build_set_cdb(Feature::Region, 0x02));
    assert_eq!(m.cdbs[6], build_set_cdb(Feature::Speed, SPEED_MAX));
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
    // SET Hrl=OFF (the migrated skip direction), then GET Hrl to verify.
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Hrl, STATE_OFF));
    assert_eq!(m.cdbs[1], build_get_cdb(Feature::Hrl));
    assert_eq!(m.states.hrl, STATE_OFF);
}

#[test]
fn arm_oem_uhd_sets_uhd_hrl_encryption_each_verified() {
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
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Unrestricted, STATE_ON));
    assert_eq!(m.cdbs[2], build_set_cdb(Feature::Hrl, STATE_OFF));
    assert_eq!(m.cdbs[4], build_set_cdb(Feature::Encryption, STATE_OFF));
    assert_eq!(m.states.unrestricted, STATE_ON);
    assert_eq!(m.states.hrl, STATE_OFF);
    assert_eq!(m.states.encryption, STATE_OFF);
}

#[test]
fn arm_bypass_bd_disables_encryption() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_bypass_bd().expect("armed");
    }
    // Hrl=off (revocation skip) is set+verified FIRST, then Encryption=off.
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Hrl, STATE_OFF));
    assert_eq!(m.cdbs[1], build_get_cdb(Feature::Hrl));
    assert_eq!(m.cdbs[2], build_set_cdb(Feature::Encryption, STATE_OFF));
    assert_eq!(m.cdbs[3], build_get_cdb(Feature::Encryption));
    assert_eq!(m.states.hrl, STATE_OFF);
    assert_eq!(m.states.encryption, STATE_OFF);
}

#[test]
fn arm_bypass_uhd_sets_uhd_hrl_encryption() {
    let mut m = FwMock::new();
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_bypass_uhd().expect("armed");
    }
    // Recipe order: Unrestricted=on, Hrl=off, Encryption=off (each SET then verifying GET).
    assert_eq!(m.cdbs[0], build_set_cdb(Feature::Unrestricted, STATE_ON));
    assert_eq!(m.cdbs[2], build_set_cdb(Feature::Hrl, STATE_OFF));
    assert_eq!(m.cdbs[4], build_set_cdb(Feature::Encryption, STATE_OFF));
    assert_eq!(m.states.unrestricted, STATE_ON);
    assert_eq!(m.states.hrl, STATE_OFF);
    assert_eq!(m.states.encryption, STATE_OFF);
}

#[test]
fn arm_stealth_oem_resets_then_verifies_all_passthrough() {
    let mut m = FwMock::new();
    m.states.encryption = STATE_ON;
    m.states.unrestricted = STATE_ON;
    {
        let mut fw = FirmwareControl::new(&mut m);
        fw.arm_stealth_oem().expect("disarmed");
    }
    assert_eq!(m.cdbs[0], build_reset_cdb(RESET_TO_OEM));
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
    assert_eq!(m.states.encryption, STATE_OFF);
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
    // arm_bypass_bd now verifies Hrl=off FIRST, so the stuck drive trips on Hrl.
    assert_eq!(
        err,
        FirmwareError::VerifyFailed {
            feature: Feature::Hrl,
            wanted: STATE_OFF,
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
