//! S14 — Property tests for the TSL XML parser.
//!
//! Random / mutated XML inputs must never panic
//! `parse_trusted_list`.

use eidas_trust::parse_trusted_list;
use proptest::prelude::*;

const REAL_TSL_PREFIX: &str = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeTerritory>EU</SchemeTerritory>
"#;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_bytes_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = parse_trusted_list(&bytes);
    }

    #[test]
    fn random_xml_garbage_no_panic(s in r#"[<>/=" \t\n\r0-9a-zA-Z]{0,512}"#) {
        let _ = parse_trusted_list(s.as_bytes());
    }

    #[test]
    fn truncated_real_prefix_no_panic(truncate_at in 0usize..REAL_TSL_PREFIX.len()) {
        let bytes = REAL_TSL_PREFIX[..truncate_at].as_bytes();
        let _ = parse_trusted_list(bytes);
    }

    #[test]
    fn corrupt_real_prefix_no_panic(
        flips in prop::collection::vec(0usize..REAL_TSL_PREFIX.len(), 0..16),
    ) {
        let mut bytes = REAL_TSL_PREFIX.as_bytes().to_vec();
        for f in flips {
            bytes[f] ^= 0xff;
        }
        let _ = parse_trusted_list(&bytes);
    }
}
