//! S14 — Property tests for the TSTInfo parser.

use eidas_timestamp::tst::TstInfo;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_bytes_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = TstInfo::from_der(&bytes);
    }

    #[test]
    fn sequence_framed_no_panic(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut framed = vec![0x30u8];
        if body.len() < 128 {
            framed.push(body.len() as u8);
        } else {
            framed.push(0x82);
            framed.push((body.len() >> 8) as u8);
            framed.push(body.len() as u8);
        }
        framed.extend_from_slice(&body);
        let _ = TstInfo::from_der(&framed);
    }
}
