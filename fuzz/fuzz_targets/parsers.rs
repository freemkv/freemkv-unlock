#![no_main]
use freemkv_unlock::protocol::{FirmwareIdentity, ProtocolIdentity, verify_response};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let _ = verify_response(data);
    if let Some(id) = FirmwareIdentity::parse(data) {
        let _ = id.is_supported();
    }
    let _ = ProtocolIdentity::parse(data);
});
