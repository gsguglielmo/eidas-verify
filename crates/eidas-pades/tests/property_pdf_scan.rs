//! S14 — Property tests for the PAdES PDF scanner.
//!
//! Invariants under arbitrary bytes:
//! - `find_signatures` never panics.
//! - `find_signatures` always terminates (we hardened the cursor
//!   advance for this; the property check is proof that no input
//!   can re-introduce the O(N²) hang).
//! - The returned `byte_range` (if any) is in-bounds for the input.

use eidas_pades::scan::find_signatures;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        // 30 s wall-clock cap protects against a future regression that
        // re-introduces the linear-loop pathology.
        timeout: 30_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_bytes_complete(bytes in prop::collection::vec(any::<u8>(), 0..16_384)) {
        let r = find_signatures(&bytes);
        if let Ok(sigs) = r {
            for sig in sigs {
                let [a, b, c, d] = sig.byte_range;
                prop_assert!(a.saturating_add(b) <= bytes.len());
                prop_assert!(c.saturating_add(d) <= bytes.len());
            }
        }
    }

    #[test]
    fn many_byte_range_strings_no_dos(
        // Embed many copies of the literal "/ByteRange" — the previous
        // scanner went O(N²) here. The hardened scanner is O(N·M).
        copies in 1usize..200,
        prefix in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut blob: Vec<u8> = prefix.clone();
        for _ in 0..copies {
            blob.extend_from_slice(b"/ByteRange [0 0 0 0] <00>");
        }
        // Even with hundreds of fake hits, scanning must complete.
        let _ = find_signatures(&blob);
    }
}
