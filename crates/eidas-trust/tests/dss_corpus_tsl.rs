//! S10 — Trust list parsing against the full DSS TSL corpus.
//!
//! Exercises every `*.xml` file under
//! `tests/vectors/dss-corpus/dss-tsl-validation/src/test/resources/` and
//! drives them through `parse_trusted_list`. We verify three classes of
//! behaviour:
//!
//! 1. **Well-formed real TSLs parse and surface the expected territory /
//!    sequence number / provider count.** This is the core happy path.
//!    Examples: `eu-lotl.xml`, `eu-lotl-250.xml`, `fi-v6.xml`, `de-tl.xml`,
//!    `fr.xml`, `ie-tl.xml`.
//! 2. **Malformed XML returns a structured error rather than panicking.**
//!    Examples: `eu-lotl-not-parseable.xml`, `fi-v5-invalid.xml`.
//! 3. **TSLs with explicitly broken or absent XMLDSig parse the structural
//!    content unchanged.** Our parser does not (yet) verify the embedded
//!    XMLDSig (see `docs/08-security-model.md:100`), so `eu-lotl-broken-sig.xml`
//!    and `eu-lotl-no-sig.xml` must both succeed at the structural layer.
//!    A separate `#[ignore]` test documents the gap that will close when
//!    XMLDSig verification lands.
//!
//! Runs only when `tools/sync-corpus.sh` has populated the DSS corpus
//! into `tests/vectors/dss-corpus/` (the directory is gitignored and
//! fetched on demand, not vendored or submoduled).

use eidas_test_corpus::{dss_corpus_present, dss_sample, skip_if_corpus_missing};
use eidas_trust::parse_trusted_list;
use rstest::rstest;

fn corpus_xml(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-tsl-validation", name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

// =====================================================================
// Happy-path: real production TSLs parse cleanly.
// =====================================================================

#[rstest]
// LOTL files are PointerLists, not TSPs — expect zero providers.
#[case::eu_lotl_current("eu-lotl.xml", "EU", false)]
#[case::eu_lotl_v250("eu-lotl-250.xml", "EU", false)]
#[case::eu_lotl_pivot("eu-lotl-pivot.xml", "EU", false)]
// National TLs always carry providers.
#[case::de_tl("de-tl.xml", "DE", true)]
#[case::fr_tl("fr.xml", "FR", true)]
#[case::ie_tl("ie-tl.xml", "IE", true)]
#[case::dk_tl("dk_tl-sn21.xml", "DK", true)]
#[case::fi_v5("fi-v5.xml", "FI", true)]
#[case::fi_v6("fi-v6.xml", "FI", true)]
#[case::fi_v6_sig_cert("fi-v6-sig-cert.xml", "FI", true)]
#[case::fr_docusign("fr-65-docusign.xml", "FR", true)]
fn well_formed_tsl_parses(
    #[case] name: &str,
    #[case] expected_territory: &str,
    #[case] expect_providers: bool,
) {
    skip_if_corpus_missing!();
    let xml = corpus_xml(name);
    let tl = parse_trusted_list(&xml)
        .unwrap_or_else(|e| panic!("[{name}] expected to parse, got: {e}"));
    assert_eq!(
        tl.territory.as_deref(),
        Some(expected_territory),
        "[{name}] SchemeTerritory mismatch"
    );
    if expect_providers {
        assert!(
            !tl.providers.is_empty(),
            "[{name}] expected at least one TrustServiceProvider"
        );
    } else {
        // Conversely, a LOTL must not surface providers (it carries
        // OtherTSLPointer entries instead, which the structural parser
        // intentionally skips). If providers ever appear here, our model
        // is conflating pointer entries with TSP entries — a correctness
        // bug that this assertion catches.
        assert!(
            tl.providers.is_empty(),
            "[{name}] LOTL surprisingly surfaces {} providers — \
             pointer/TSP confusion in the parser?",
            tl.providers.len()
        );
    }
}

// =====================================================================
// Production EU LOTL: structural invariants we rely on.
// =====================================================================

#[test]
fn eu_lotl_has_pointers_to_member_state_tls() {
    skip_if_corpus_missing!();
    let xml = corpus_xml("eu-lotl.xml");
    let tl = parse_trusted_list(&xml).expect("eu-lotl.xml parses");
    // We don't surface OtherTSLPointer entries at the model layer yet;
    // verify instead that a substantive document came through (XML byte
    // count > 100 KB is a reasonable proxy — the real LOTL is several MB).
    assert!(
        tl.source_xml.len() > 100_000,
        "eu-lotl.xml unexpectedly small: {} bytes",
        tl.source_xml.len()
    );
    assert_eq!(tl.territory.as_deref(), Some("EU"));
}

#[test]
fn eu_lotl_v250_sequence_number_is_present() {
    skip_if_corpus_missing!();
    let xml = corpus_xml("eu-lotl-250.xml");
    let tl = parse_trusted_list(&xml).expect("eu-lotl-250.xml parses");
    assert!(tl.sequence_number.is_some(), "missing TSLSequenceNumber");
}

// =====================================================================
// TSLs without an XMLDSig signature still parse structurally. Our parser
// is documented to ignore the Signature element (docs/08-security-model.md).
// =====================================================================

#[rstest]
#[case::no_sig("eu-lotl-no-sig.xml")]
#[case::broken_sig("eu-lotl-broken-sig.xml")]
#[case::no_tl_version("eu-lotl-no-tl-version.xml")]
fn structurally_valid_with_signature_anomalies(#[case] name: &str) {
    skip_if_corpus_missing!();
    let xml = corpus_xml(name);
    // These are STRUCTURAL successes — the parser must not error out.
    let tl = parse_trusted_list(&xml)
        .unwrap_or_else(|e| panic!("[{name}] structural parse must succeed, got: {e}"));
    assert_eq!(tl.territory.as_deref(), Some("EU"));
}

// =====================================================================
// Malformed XML: returns structured error, never panics.
// =====================================================================

#[rstest]
#[case::not_parseable("eu-lotl-not-parseable.xml")]
fn malformed_xml_yields_error(#[case] name: &str) {
    skip_if_corpus_missing!();
    let xml = corpus_xml(name);
    let result = parse_trusted_list(&xml);
    // Either an `Err(...)` or a clearly-degraded `Ok(...)` is acceptable;
    // a panic is not. (`fi-v5-invalid.xml` is intentionally NOT in this
    // list — DSS labels it invalid for higher-layer reasons that don't
    // prevent structural parsing.)
    match result {
        Err(e) => eprintln!("[{name}] returned error as expected: {e}"),
        Ok(tl) => {
            assert!(
                tl.territory.is_none() || tl.providers.is_empty(),
                "[{name}] surprisingly parsed as a complete TSL — review parser tolerance"
            );
        }
    }
}

/// `fi-v5-invalid.xml` is in the corpus as an "invalid" sample but its
/// invalidity is at the trust-service-information level (e.g. missing
/// fields that DSS validates separately), not at the XML-parsing level.
/// Documenting this so the rationale survives a future refactor.
#[test]
fn fi_v5_invalid_parses_structurally_but_is_semantically_invalid() {
    skip_if_corpus_missing!();
    let xml = corpus_xml("fi-v5-invalid.xml");
    let tl = parse_trusted_list(&xml).expect("structural parse OK");
    assert_eq!(tl.territory.as_deref(), Some("FI"));
    // Any deeper "is this TSL semantically valid?" check would belong in
    // a separate `validate_trusted_list` API that does not yet exist.
}

// =====================================================================
// Negative: parser must not panic on adversarial-but-not-quite-broken
// member-state TSLs.
// =====================================================================

#[rstest]
#[case::fi_v6_no_service_information("fi-v6-no-service-information.xml")]
#[case::fi_v6_no_supply_points("fi-v6-no-supply-points-type.xml")]
#[case::fi_v6_no_tsp_information("fi-v6-no-tsp-information.xml")]
fn missing_optional_subelements_are_tolerated(#[case] name: &str) {
    skip_if_corpus_missing!();
    let xml = corpus_xml(name);
    // No assertion about completeness — only that parsing doesn't panic
    // and produces some structured result.
    let _ = parse_trusted_list(&xml);
}

// =====================================================================
// Smoke pass — every .xml in the directory must produce SOME outcome
// (Ok or Err) without panicking. Catches regressions where a new sample
// added upstream breaks our parser silently.
// =====================================================================

#[test]
fn every_corpus_tsl_completes_parse() {
    skip_if_corpus_missing!();
    // dss_sample with empty relative returns the resources directory itself.
    let dir = dss_sample("dss-tsl-validation", "");
    let mut tested = 0usize;
    let mut errored = 0usize;
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
    {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("xml") {
            continue;
        }
        let xml = std::fs::read(&path).unwrap();
        match parse_trusted_list(&xml) {
            Ok(_) => {}
            Err(_) => errored += 1,
        }
        tested += 1;
    }
    assert!(tested >= 20, "expected ≥20 corpus TSL samples, found {tested}");
    eprintln!("[dss-tsl-corpus] tested={tested} errored={errored}");
}

// =====================================================================
// Deferred: TSL XMLDSig signature verification.
// docs/08-security-model.md:100 lists this as a known gap. When the
// `eidas-trust` crate grows XMLDSig verification, unignore these tests.
// They are written now so they cannot bit-rot before that work begins.
// =====================================================================

#[test]
#[ignore = "TSL XMLDSig verification not implemented; see docs/08-security-model.md and docs/09-deferred-work.md"]
fn broken_lotl_signature_is_rejected() {
    skip_if_corpus_missing!();
    let xml = corpus_xml("eu-lotl-broken-sig.xml");
    // When implemented: the high-level "load + verify" entry point should
    // reject this file because the embedded ds:Signature does not verify
    // against the official EU signing certificate. The structural parse
    // (parse_trusted_list) is allowed to succeed; signature checking
    // belongs in a separate `verify_trusted_list` API that does not yet
    // exist.
    let _tl = parse_trusted_list(&xml).expect("structural parse still succeeds");
    panic!("placeholder — replace with `verify_trusted_list(&xml)` when API lands");
}

#[test]
#[ignore = "TSL XMLDSig verification not implemented; see docs/08-security-model.md and docs/09-deferred-work.md"]
fn unsigned_lotl_is_rejected_by_verify_api() {
    skip_if_corpus_missing!();
    let xml = corpus_xml("eu-lotl-no-sig.xml");
    let _tl = parse_trusted_list(&xml).expect("structural parse succeeds");
    panic!("placeholder — replace with `verify_trusted_list(&xml)` when API lands");
}
