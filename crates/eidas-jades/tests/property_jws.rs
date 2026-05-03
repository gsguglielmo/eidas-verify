//! S14 — Property tests for the JWS / JAdES parsers.

use eidas_jades::jws::JwsSignature;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_compact_no_panic(s in r"[A-Za-z0-9._-]{0,2048}") {
        let _ = JwsSignature::from_compact(&s);
    }

    #[test]
    fn random_flattened_json_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = JwsSignature::from_flattened_json(&bytes);
    }

    /// Random three-segment compact strings exercise the segment-split
    /// path even when the segments are nonsense base64url.
    #[test]
    fn random_three_segments_no_panic(
        h in r"[A-Za-z0-9_-]{0,64}",
        p in r"[A-Za-z0-9_-]{0,512}",
        s in r"[A-Za-z0-9_-]{0,128}",
    ) {
        let compact = format!("{h}.{p}.{s}");
        let _ = JwsSignature::from_compact(&compact);
    }
}
