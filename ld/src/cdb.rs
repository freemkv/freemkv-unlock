//! Public unlock-CDB seam.
//!
//! These items expose the *minimum* an external consumer (e.g. the bdemu
//! drive emulator) needs to recognise and answer the LibreDrive unlock
//! READ_BUFFER handshake, without that consumer open-coding the
//! handshake internals. The concrete CDB shapes and the verification
//! marker are unlock-handshake details and must live ONLY in this crate.

/// The 4-byte marker the unlock READ_BUFFER response carries at bytes
/// `[12..16]`. A consumer answering the handshake writes this at that
/// offset; a verifier checks for it there. It is the universal
/// "this is a real unlock reply" tag, independent of the per-drive
/// signature at `[0..4]`.
pub const UNLOCK_MARKER: &[u8] = b"MMkv";

/// Returns `true` when a READ_BUFFER (`0x3C`) CDB with the given mode
/// (`cdb[1] & 0x1F`) and buffer id (`cdb[2]`) is an unlock-handshake
/// read — i.e. one of the LibreDrive unlock variants.
///
/// This is the single source of truth for the unlock READ_BUFFER CDB
/// shapes; consumers must call it rather than hardcoding the mode /
/// buffer-id pairs.
pub fn is_unlock_read_buffer(mode: u8, buf_id: u8) -> bool {
    matches!((mode, buf_id), (1, 0x44) | (2, 0x77))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_four_bytes() {
        assert_eq!(UNLOCK_MARKER, b"MMkv");
        assert_eq!(UNLOCK_MARKER.len(), 4);
    }

    #[test]
    fn unlock_variants_match() {
        // Variant A and variant B.
        assert!(is_unlock_read_buffer(1, 0x44));
        assert!(is_unlock_read_buffer(2, 0x77));
    }

    #[test]
    fn non_unlock_cdbs_do_not_match() {
        // Right mode, wrong buffer id.
        assert!(!is_unlock_read_buffer(1, 0x77));
        assert!(!is_unlock_read_buffer(2, 0x44));
        // Wrong mode, right buffer id.
        assert!(!is_unlock_read_buffer(0, 0x77));
        assert!(!is_unlock_read_buffer(0, 0x44));
        assert!(!is_unlock_read_buffer(3, 0x77));
        // Ordinary data reads.
        assert!(!is_unlock_read_buffer(2, 0x00));
        assert!(!is_unlock_read_buffer(0, 0x00));
    }
}
