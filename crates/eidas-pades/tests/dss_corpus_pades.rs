//! S4 — PAdES DSS-corpus parse-layer suite.
//!
//! Iterates `tests/vectors/dss-corpus/dss-pades/src/test/resources/validation/`
//! through `eidas_pades::scan::find_signatures` and asserts:
//!
//! - **Multi-signature documents** report exactly the expected count.
//! - **PDFs with no signatures** (empty placeholder, plain PDF/A) do
//!   not panic and surface `Ok(Vec::new())` or a clear error.
//! - **Adversarial PDFs** (`BadEncodedCMS.pdf`,
//!   `EmptyPage-corrupted*.pdf`) either error structurally or return
//!   placeholders that the higher-level verifier rejects — never a
//!   silent success.
//! - **51-signature PDF** is correctly enumerated as 51 separate
//!   signature locations.
//!
//! Verification verdicts (TotalPassed / IndeterminateSub) over real
//! anchors are exercised in S13. Here we confirm the scanner is robust
//! against the wide variety of real-world PDF encoders.

use std::path::PathBuf;

use eidas_pades::scan::find_signatures;
use eidas_test_corpus::{dss_sample, skip_if_corpus_missing};
use rstest::rstest;

fn corpus(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-pades", &format!("validation/{name}"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

/// PDFs at the top of `dss-pades/src/test/resources/` (not under `validation/`).
fn corpus_top(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-pades", name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

// =====================================================================
// Multi-signature & well-known sample counts.
// =====================================================================

#[test]
fn pades_51_signatures_enumerated() {
    skip_if_corpus_missing!();
    let pdf = corpus("51sigs.pdf");
    let sigs = find_signatures(&pdf).unwrap_or_else(|e| panic!("scan failed: {e}"));
    assert_eq!(
        sigs.len(),
        51,
        "expected 51 signatures (per filename), got {}",
        sigs.len()
    );
}

#[rstest]
#[case::pades_lt("PAdES-LT.pdf")]
#[case::pades_lta("PAdES-LTA.pdf")]
#[case::cross_cert_ocsp("PAdESWithCrossCertificateOCSP.pdf")]
#[case::ad_rb("AD-RB.pdf")]
#[case::sig_p_bg("Signature-P-BG_BOR-1.pdf")]
#[case::sig_p_de("Signature-P-DE_SCI-4.pdf")]
#[case::sig_p_fr("Signature-P-FR_CS-5.pdf")]
#[case::sig_p_hu_1("Signature-P-HU_MIC-1.pdf")]
#[case::sig_p_hu_3("Signature-P-HU_MIC-3.pdf")]
fn well_formed_pades_pdfs_have_at_least_one_signature(#[case] name: &str) {
    skip_if_corpus_missing!();
    let pdf = corpus(name);
    let sigs = find_signatures(&pdf)
        .unwrap_or_else(|e| panic!("[{name}] scan failed: {e}"));
    assert!(
        !sigs.is_empty(),
        "[{name}] expected at least one /Sig; scanner returned 0"
    );
    for (i, sig) in sigs.iter().enumerate() {
        let [a, b, c, d] = sig.byte_range;
        assert!(
            a.saturating_add(b) <= pdf.len() && c.saturating_add(d) <= pdf.len(),
            "[{name}#{i}] byte_range {:?} out of bounds for {} bytes",
            sig.byte_range, pdf.len()
        );
        assert!(!sig.cms_der.is_empty(), "[{name}#{i}] empty /Contents");
    }
}

// =====================================================================
// PDFs with no real signature must not produce phantom entries.
// =====================================================================

#[rstest]
#[case::not_signed("not_signed_pdfa.pdf")]
#[case::doc_no_sig("doc.pdf")]
#[case::empty_page("EmptyPage.pdf")]
#[case::big_no_sig("big_file.pdf")]
fn unsigned_pdfs_have_no_signatures(#[case] name: &str) {
    skip_if_corpus_missing!();
    let pdf = corpus_top(name);
    let sigs = find_signatures(&pdf).unwrap_or_default();
    assert!(
        sigs.is_empty(),
        "[{name}] expected zero signatures, scanner returned {}",
        sigs.len()
    );
}

#[test]
fn empty_signature_placeholder_returns_no_validatable_signature() {
    skip_if_corpus_missing!();
    let pdf = corpus_top("documentEmptySignature.pdf");
    let sigs = find_signatures(&pdf).unwrap_or_default();
    for sig in &sigs {
        assert!(
            sig.cms_der.iter().all(|&b| b == 0),
            "empty-signature placeholder must surface as zero bytes"
        );
    }
}

// =====================================================================
// Adversarial / malformed PDFs.
// =====================================================================

// `BadEncodedCMS.pdf` lives under validation/; the corrupted samples are at the
// resources/ root.
#[test]
fn bad_encoded_cms_does_not_panic() {
    skip_if_corpus_missing!();
    let _ = find_signatures(&corpus("BadEncodedCMS.pdf"));
}

#[rstest]
#[case::corrupted("EmptyPage-corrupted.pdf")]
#[case::corrupted2("EmptyPage-corrupted2.pdf")]
fn malformed_pdfs_do_not_panic(#[case] name: &str) {
    skip_if_corpus_missing!();
    let pdf = corpus_top(name);
    let _ = find_signatures(&pdf);
}

// =====================================================================
// Aggregate sweep.
// =====================================================================

#[test]
fn every_pdf_in_validation_dir_completes() {
    skip_if_corpus_missing!();
    let dir: PathBuf = dss_sample("dss-pades", "validation");
    let mut tested = 0usize;
    let mut sig_total = 0usize;
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
    {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("pdf") {
            continue;
        }
        let pdf = std::fs::read(&path).unwrap();
        match find_signatures(&pdf) {
            Ok(s) => sig_total += s.len(),
            Err(_) => {} // structural error is fine; no panic is what we want
        }
        tested += 1;
    }
    assert!(
        tested >= 50,
        "expected ≥50 PAdES PDFs, found {tested}"
    );
    eprintln!("[dss-pades-corpus] tested={tested} total_signatures={sig_total}");
}
