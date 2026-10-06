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
