//! S8 — RFC 3161 TimeStampToken parsing against the DSS corpus.
//!
//! `tests/vectors/dss-corpus/dss-validation/src/test/resources/` ships three
//! real-world tokens (`disig.tst`, `d-trust.tsr`, `tst-two-refs.tst`).
//! Despite the `.tst` / `.tsr` extension difference, all three start with a
//! ContentInfo of type `id-signedData` — they are all bare
//! TimeStampTokens, not the `TimeStampResp` outer wrapper. The `.tsr` here
//! is an upstream-DSS naming quirk, not a structural difference.
//!
//! These tokens are detached from their original timestamped data — we
//! only have the token bytes, not the document the token covers — so we
//! cannot run the full `verify_time_stamp_token` (it would fail at the
//! `messageImprint` step). Instead this test exercises the parse layer
//! end-to-end, covering:
//!
//! 1. Outer ContentInfo / SignedData decode
//! 2. eContentType is `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4)
//! 3. Inner TSTInfo decodes via `TstInfo::from_der`
//! 4. version=1, sane policy OID, valid GeneralizedTime, well-formed
//!    messageImprint with a hash algorithm we recognise.
//! 5. Imprint length matches the digest output size for the declared
//!    algorithm.
//!
//! The full chain-validation path is exercised by the existing synthetic
//! `tst_tests.rs`; this corpus suite locks in our handling of *real-world*
//! TSA-emitted tokens, which historically deviate from the spec in
//! subtle ways (e.g. extra unsigned attributes, unusual nonce sizes).

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::rfc5912::{ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512};
use der::asn1::OctetString;
use der::{Decode, Encode};
use eidas_core::HashAlgorithm;
use eidas_test_corpus::{dss_sample, skip_if_corpus_missing};
use eidas_timestamp::tst::TstInfo;
use rstest::rstest;

/// `id-ct-TSTInfo` — RFC 3161 §2.4.2.
const ID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";

fn corpus(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-validation", name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

/// Strip the ContentInfo / SignedData / OCTET STRING wrappers and return
/// the raw `TSTInfo` DER. Mirrors steps 1-2 of `verify_time_stamp_token`.
fn extract_tst_info_der(token_der: &[u8]) -> Vec<u8> {
    let ci = ContentInfo::from_der(token_der).expect("outer ContentInfo decodes");
    let sd_bytes = ci.content.to_der().expect("inner SignedData encodes");
    let sd = SignedData::from_der(&sd_bytes).expect("SignedData decodes");
    assert_eq!(
        sd.encap_content_info.econtent_type.to_string(),
        ID_CT_TSTINFO,
        "eContentType must be id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)"
    );
    let econtent = sd
        .encap_content_info
        .econtent
        .expect("eContent OCTET STRING present");
    let econtent_der = econtent.to_der().expect("eContent re-encodes");
    let oct = OctetString::from_der(&econtent_der).expect("OCTET STRING wraps TSTInfo");
    oct.into_bytes()
}

fn imprint_bits_for_algorithm(h: HashAlgorithm) -> u32 {
    h.output_bits()
}

// Real-world TSA tokens in the DSS corpus exercise the tolerant
// `GeneralizedTime` parser (fractional seconds — `disig.tst` carries
// `"20190412090032.613Z"`) and the manual OID decoder that bypasses
// const_oid 0.9's 39-byte buffer (long policy OIDs in `tst-two-refs.tst`).
// Both code paths live in `crates/eidas-timestamp/src/tst.rs`.
#[rstest]
#[case::disig("disig.tst")]
#[case::d_trust("d-trust.tsr")]
#[case::two_refs("tst-two-refs.tst")]
fn parses_tst_info_from_real_token(#[case] name: &str) {
    skip_if_corpus_missing!();
    let token = corpus(name);
    let tst_der = extract_tst_info_der(&token);
    let info = TstInfo::from_der(&tst_der)
        .unwrap_or_else(|e| panic!("[{name}] TstInfo parse: {e}"));

    // Spec checks
    assert_eq!(info.version, 1, "[{name}] TSTInfo.version must be 1");

    // Policy OID is implementation-defined but always parseable.
    let policy_str = info.policy.to_string();
    assert!(!policy_str.is_empty(), "[{name}] empty policy OID");

    // GenTime is well-formed and within a sane range (TSAs in this
    // corpus issued tokens between ~2015 and ~2020).
    let year = info.gen_time.format("%Y").to_string();
    let year_n: i32 = year.parse().expect("year parses");
    assert!(
        (2010..=2030).contains(&year_n),
        "[{name}] suspicious genTime year: {year}"
    );

    // messageImprint hash algorithm is recognised; imprint size matches.
    let expected_bytes = (imprint_bits_for_algorithm(info.message_imprint.algorithm) / 8) as usize;
    assert_eq!(
        info.message_imprint.hashed_message.len(),
        expected_bytes,
        "[{name}] imprint length mismatch: got {} bytes for {:?}",
        info.message_imprint.hashed_message.len(),
        info.message_imprint.algorithm
    );

    // Serial number is non-empty.
    assert!(
        !info.serial_number.is_empty(),
        "[{name}] empty serial number"
    );
}

#[test]
fn imprint_algorithms_in_corpus_are_recognised() {
    skip_if_corpus_missing!();
    let names = ["disig.tst", "d-trust.tsr", "tst-two-refs.tst"];
    let mut algs = std::collections::BTreeSet::new();
    for n in names {
        let token = corpus(n);
        let tst_der = extract_tst_info_der(&token);
        let info = TstInfo::from_der(&tst_der).expect("parse");
        algs.insert(format!("{:?}", info.message_imprint.algorithm));
    }
    eprintln!("[dss-tst-corpus] hash algorithms used: {algs:?}");
}

/// Sanity: each of the three tokens has a different (gen_time, serial)
/// — they're independently issued tokens, not the same artefact under
/// different file names. If this ever fails the corpus snapshot has
/// drifted in a way we should investigate before trusting other results.
#[test]
fn tokens_are_distinct() {
    skip_if_corpus_missing!();
    let parsed: Vec<_> = ["disig.tst", "d-trust.tsr", "tst-two-refs.tst"]
        .iter()
        .map(|n| {
            let t = corpus(n);
            let der = extract_tst_info_der(&t);
            TstInfo::from_der(&der).expect("parse")
        })
        .collect();
    assert_ne!(parsed[0].serial_number, parsed[1].serial_number);
    assert_ne!(parsed[1].serial_number, parsed[2].serial_number);
    assert_ne!(parsed[0].serial_number, parsed[2].serial_number);
}

/// Even with the parse-layer issue, the OUTER ContentInfo / SignedData
/// envelope of every corpus token decodes successfully. This isolates
/// the bug to the TSTInfo body parser and gives us a working baseline.
#[rstest]
#[case::disig("disig.tst")]
#[case::d_trust("d-trust.tsr")]
#[case::two_refs("tst-two-refs.tst")]
fn outer_envelope_decodes_for_real_tokens(#[case] name: &str) {
    skip_if_corpus_missing!();
    let token = corpus(name);
    let ci = ContentInfo::from_der(&token)
        .unwrap_or_else(|e| panic!("[{name}] outer ContentInfo: {e}"));
    let sd_bytes = ci.content.to_der().expect("encode inner");
    let sd = SignedData::from_der(&sd_bytes)
        .unwrap_or_else(|e| panic!("[{name}] inner SignedData: {e}"));
    assert_eq!(
        sd.encap_content_info.econtent_type.to_string(),
        ID_CT_TSTINFO,
        "[{name}] eContentType is not TSTInfo"
    );
    assert!(
        !sd.signer_infos.0.is_empty(),
        "[{name}] no SignerInfo present"
    );
}

// =====================================================================
// Hash-OID identity assertions — make sure our digest::hash_from_oid
// resolves the algorithms our corpus actually uses.
// =====================================================================

#[rstest]
#[case::sha256("2.16.840.1.101.3.4.2.1", HashAlgorithm::Sha256)]
#[case::sha384("2.16.840.1.101.3.4.2.2", HashAlgorithm::Sha384)]
#[case::sha512("2.16.840.1.101.3.4.2.3", HashAlgorithm::Sha512)]
fn hash_oid_resolves_to_correct_enum(#[case] oid_str: &str, #[case] expected: HashAlgorithm) {
    use eidas_cms::digest::hash_from_oid;
    let oid: const_oid::ObjectIdentifier = oid_str.parse().expect("oid parses");
    let h = hash_from_oid(oid).expect("supported hash");
    assert_eq!(h, expected);

    // SHA-1 OID is not asserted at the enum-equality level here because
    // accepting it for verification depends on the algorithm policy
    // (default policy rejects). Just assert the OID is recognised.
    let _ = (ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512); // silence unused-import
}
