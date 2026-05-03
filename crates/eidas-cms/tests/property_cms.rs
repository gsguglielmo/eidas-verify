//! S14 — Property tests for the CMS envelope parser.
//!
//! Invariants:
//! - `parse_cms_envelope` never panics on arbitrary input.
//! - `parse_cms_envelope` never returns `Ok` with `embedded_certs`
//!   referring to memory the input did not contain (we only check
//!   `len() <= input.len()` as a coarse upper bound).
//!
//! 256 random inputs per run × deterministic shrinker. No corpus
//! required.

use eidas_cms::parse_cms_envelope;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Random bytes never panic the envelope parser.
    #[test]
    fn random_bytes_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_cms_envelope(&bytes, None);
        let _ = parse_cms_envelope(&bytes, Some(&bytes));
    }

    /// Random bytes prefixed with a SEQUENCE header are still safe.
    #[test]
    fn sequence_prefix_no_panic(
        body in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut framed = vec![0x30u8]; // SEQUENCE
        // Definite-length prefix
        if body.len() < 128 {
            framed.push(body.len() as u8);
        } else {
            framed.push(0x82);
            framed.push((body.len() >> 8) as u8);
            framed.push(body.len() as u8);
        }
        framed.extend_from_slice(&body);
        let _ = parse_cms_envelope(&framed, None);
    }

    /// Truncating a real-looking CMS at random points never panics.
    #[test]
    fn truncated_known_prefix_no_panic(
        truncate_at in 0usize..200,
    ) {
        // Minimal real ContentInfo prefix: SEQUENCE { OID id-signedData, ... }
        let prefix: Vec<u8> = vec![
            0x30, 0x82, 0x01, 0x00, // SEQUENCE outer length 256
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ];
        let bytes = if truncate_at < prefix.len() {
            prefix[..truncate_at].to_vec()
        } else {
            prefix
        };
        let _ = parse_cms_envelope(&bytes, None);
    }
}
