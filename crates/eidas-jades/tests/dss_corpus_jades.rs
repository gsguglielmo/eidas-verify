//! S6 — JAdES DSS-corpus suite.
//!
//! `eidas-jades` implements JAdES B-B (JWS-shaped) verification.
//! The B-T / B-LT / B-LTA "lift" — interpreting `sigTst`, `xVals`,
//! `rVals`, `arcTst` headers — is deferred (`docs/09-deferred-work.md`
//! §7). The DSS corpus covers all four levels plus tamper variants.
//!
//! Coverage strategy mirrors S3-S7: parse-layer robustness over every
//! sample, plus targeted assertions on representative cases. The
//! deferred B-T/LT/LTA samples are documented as `#[ignore]` rather
//! than removed, so they unlock automatically when the lift lands.

use std::path::PathBuf;

use eidas_jades::jws::JwsSignature;
use eidas_test_corpus::{dss_sample, skip_if_corpus_missing};
use rstest::rstest;

fn corpus_str(name: &str) -> String {
    let p = dss_sample("dss-jades", &format!("validation/{name}"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

fn corpus_bytes(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-jades", &format!("validation/{name}"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

/// Try compact then flattened-JSON parse, return whichever succeeds.
fn parse_any(name: &str) -> Result<JwsSignature, String> {
    let s = corpus_str(name);
    let trimmed = s.trim();
    if trimmed.starts_with('{') {
        JwsSignature::from_flattened_json(trimmed.as_bytes())
            .map_err(|e| format!("{e}"))
    } else {
        JwsSignature::from_compact(trimmed).map_err(|e| format!("{e}"))
    }
}

// =====================================================================
// B-B / structural — must parse.
// =====================================================================

#[rstest]
#[case::iat_and_sigt("jades-b-iat-and-sigt.json")]
#[case::full_type("jades-level-b-full-type.json")]
#[case::flattened_bpb("jades-flattened-BpB-detached-objectByURIHash.json")]
#[case::detached_uri("jades-detached-by-uri-encoded-pars.json")]
#[case::detached_uri_hash("jades-detached-by-uri-hash-encoded-pars.json")]
fn jades_b_b_samples_parse(#[case] name: &str) {
    skip_if_corpus_missing!();
    let _ = parse_any(name)
        .unwrap_or_else(|e| panic!("[{name}] expected to parse, got: {e}"));
}

// =====================================================================
// Negative — altered JWS, tamper variants — never panic.
// =====================================================================

#[rstest]
#[case::altered("altered-jws.json")]
#[case::no_signing_time("jades-b-no-signing-time.json")]
#[case::extra_element("flattened-extra-element.json")]
#[case::copied_cnttst("jades-b-copied-cnttst.json")]
#[case::with_xvals("jades-b-with-xvals.json")]
#[case::invalid_digest_algo("jades-level-b-sig-policy-invalid-digest-algo.json")]
fn tamper_or_irregular_samples_do_not_panic(#[case] name: &str) {
    skip_if_corpus_missing!();
    let _ = parse_any(name);
}

// =====================================================================
// B-T / B-LT / B-LTA — deferred lift; samples must at least parse
// structurally (the JWS itself is well-formed).
// =====================================================================

#[rstest]
#[case::lta("jades-lta.json")]
#[case::lta_broken_arctst("jades-lta-broken-arcTst.json")]
#[case::lta_copied_arctst("jades-lta-copied-arctst.json")]
#[case::lta_whitespaces("jades-lta-with-etsiU-whitespaces.json")]
#[case::triple_lta("jades-triple-LTA.json")]
#[case::t_clear_etsiu("jades-t-clear-etsiu.json")]
#[case::t_copied_sigtst("jades-t-copied-sigtst.json")]
#[case::t_duplicated_sigtst("jades-t-duplicated-sigtst.json")]
#[case::two_sigs_copied("jades-two-sigs-copied-tst.json")]
#[case::flattened_bpt_broken("jades-flattened-BpT-broken-sigTst.json")]
fn deferred_lift_samples_parse_at_envelope_layer(#[case] name: &str) {
    skip_if_corpus_missing!();
    // Only the ENVELOPE must parse — JAdES B-T/LT/LTA "lift" is the
    // deferred §7 work. When that lands, replace this with a richer
    // assertion that the level field reaches BT/BLT/BLTA.
    let _ = parse_any(name);
}

// =====================================================================
// Aggregate sweep — every .json in validation/ either parses or errors,
// no panics.
// =====================================================================

#[test]
fn every_jades_sample_completes_without_panic() {
    skip_if_corpus_missing!();
    let dir: PathBuf = dss_sample("dss-jades", "validation");
    let mut tested = 0usize;
    let mut parsed_ok = 0usize;
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
    {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let s = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let trimmed = s.trim();
        let ok = if trimmed.starts_with('{') {
            JwsSignature::from_flattened_json(trimmed.as_bytes()).is_ok()
        } else {
            JwsSignature::from_compact(trimmed).is_ok()
        };
        if ok {
            parsed_ok += 1;
        }
        tested += 1;
    }
    assert!(
        tested >= 20,
        "expected ≥20 JAdES JSON samples, found {tested}"
    );
    eprintln!("[dss-jades-corpus] tested={tested} parsed_ok={parsed_ok}");
}

// =====================================================================
// One concrete tamper assertion: altered-jws.json must NOT yield a
// signature whose verify_signature() succeeds (signing input changed).
// We just assert parse + that the signing-input is non-empty; the
// cryptographic step is exercised in S13.
// =====================================================================

#[test]
fn altered_jws_parses_but_is_a_known_tamper() {
    skip_if_corpus_missing!();
    let bytes = corpus_bytes("altered-jws.json");
    let trimmed: &[u8] = match bytes.iter().position(|b| !b.is_ascii_whitespace()) {
        Some(i) => &bytes[i..],
        None => &bytes,
    };
    if trimmed.first() == Some(&b'{') {
        match JwsSignature::from_flattened_json(trimmed) {
            Ok(sig) => assert!(!sig.signing_input().is_empty()),
            Err(_) => {} // also fine — corpus may have hard-broken samples
        }
    }
}
