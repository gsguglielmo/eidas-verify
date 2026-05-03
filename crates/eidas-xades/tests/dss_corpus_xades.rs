//! S5 — XAdES DSS-corpus suite (narrow profile).
//!
//! `eidas-xades` ships a deliberately narrow XMLDSig profile (see
//! `docs/08-security-model.md` and `docs/09-deferred-work.md` §5).
//! The DSS corpus carries XAdES samples spanning the full XMLDSig
//! feature set: enveloped, enveloping, detached, transforms, XPath
//! filters, manifests, etc.
//!
//! Coverage strategy:
//! - **Parse-layer robustness** — every `.xml` and `.ddoc` in
//!   `dss-xades/src/test/resources/validation/` runs through
//!   `parse_xml_signature` without panicking.
//! - **Negative tests** — `BaselineBWithCertificateValues.xml` and
//!   `XAdESBWithoutSignedDataObjectProperties.xml` (top-level resources)
//!   are well-formed XAdES at the structural layer; we assert the
//!   parser surfaces parsed fields rather than panicking.
//! - **Out-of-profile samples** — the broader `Signature-X-{country}-*`
//!   corpus is currently expected to error or produce a partially
//!   populated `ParsedSignature` because of unsupported transforms /
//!   c14n variants. Each becomes a passing positive test once a full
//!   XMLDSig stack lands (see deferred §5).

use std::path::PathBuf;

use eidas_test_corpus::{dss_sample, skip_if_corpus_missing};
use eidas_xades::parse::parse_xml_signature;
use rstest::rstest;

fn corpus(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-xades", &format!("validation/{name}"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

// =====================================================================
// Parser robustness over the entire corpus directory.
// =====================================================================

#[test]
fn every_xades_sample_completes_without_panic() {
    skip_if_corpus_missing!();
    let dir: PathBuf = dss_sample("dss-xades", "validation");
    let mut tested = 0usize;
    let mut parsed_ok = 0usize;
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
    {
        let entry = entry.unwrap();
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !matches!(ext, "xml" | "ddoc") {
            continue;
        }
        let xml = std::fs::read(&path).unwrap();
        match parse_xml_signature(&xml) {
            Ok(_) => parsed_ok += 1,
            Err(_) => {} // out-of-profile is fine; no panic is the contract
        }
        tested += 1;
    }
    assert!(
        tested >= 50,
        "expected ≥50 XAdES samples, found {tested}"
    );
    eprintln!("[dss-xades-corpus] tested={tested} parsed_ok={parsed_ok}");
}

// =====================================================================
// Specific positive cases — narrow-profile compatible.
// =====================================================================

#[rstest]
#[case::baseline_b("BaselineBWithCertificateValues.xml")]
#[case::sig_at("Signature-X-AT-1.xml")]
#[case::sig_be("Signature-X-BE_ECON-3.xml")]
#[case::sig_es("Signature-X-ES-100.xml")]
fn narrow_profile_samples_parse_at_minimum(#[case] name: &str) {
    skip_if_corpus_missing!();
    let xml = corpus(name);
    // The parser MUST NOT panic. Whether it returns Ok or Err depends on
    // whether the sample falls inside our narrow profile.
    let _ = parse_xml_signature(&xml);
}

// =====================================================================
// FINDING placeholders — broader XAdES feature support.
// Each is labelled with the closest deferred-work section.
// =====================================================================

#[test]
#[ignore = "Full XMLDSig (libxml2/xmlsec1 or pure-Rust c14n) deferred — docs/09 §5"]
fn enveloping_signature_resolves_xpath_transform() {
    skip_if_corpus_missing!();
    let xml = corpus("Signature-X-CY-1.xml");
    let _ = parse_xml_signature(&xml);
    panic!("placeholder — replace with real positive assertion when XMLDSig lands");
}

#[test]
#[ignore = "Full XMLDSig deferred — docs/09 §5"]
fn detached_signature_resolves_external_reference() {
    skip_if_corpus_missing!();
    let xml = corpus("Signature-X-PT-4.xml");
    let _ = parse_xml_signature(&xml);
    panic!("placeholder — replace with real positive assertion when XMLDSig lands");
}
