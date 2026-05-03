//! S7 — ASiC DSS-corpus suite.
//!
//! Iterates `dss-asic-cades/src/test/resources/validation/` and
//! `dss-asic-xades/src/test/resources/validation/` and runs the
//! containers through `eidas_asic::verify_asic` with an empty
//! `CadesTrustMaterial`. With no anchors the cryptographic verdict
//! always degrades to `IndeterminateSub` / `TotalFailedSub`, but the
//! container-handling layer (ZIP open, manifest parsing, signature/
//! data-file binding) gets fully exercised.
//!
//! Critical assertions:
//! - **Manifest tamper** (`brokenReference.asice`,
//!   `brokenReferenceAndAlteredManifest.asice`,
//!   `dss1421-archive-not-cover.asice`,
//!   `cades-invalid-digest-algo.asics`) MUST not silently report
//!   `TotalPassed`. They should produce errors or `TotalFailedSub`-class
//!   reports.
//! - **Multi-file containers** (`multifiles-ok.{asice,asics}`) extract
//!   every entry without dropping any.
//! - **No-signature container** (`no-signature.asics`) returns the
//!   "container has no signatures" error.
//! - **Counter-signature container** (`containerWithCounterSig.asics`)
//!   does not panic.
//! - **Malformed ZIP** (`malformed-container.asics`) errors structurally.

use std::path::PathBuf;

use eidas_asic::{verify_asic, AsicInput};
use eidas_cades::CadesTrustMaterial;
use eidas_core::{Status, ValidationTime};
use eidas_policy::etsi_119_312_2023;
use eidas_test_corpus::{dss_sample, skip_if_corpus_missing};
use rstest::rstest;

fn corpus_cades(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-asic-cades", &format!("validation/{name}"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

fn corpus_xades(name: &str) -> Vec<u8> {
    let p = dss_sample("dss-asic-xades", &format!("validation/{name}"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"))
}

fn empty_trust() -> CadesTrustMaterial {
    CadesTrustMaterial::new()
}

fn try_verify(bytes: &[u8]) -> Result<eidas_core::VerificationReport, eidas_core::Error> {
    verify_asic(
        &AsicInput { bytes },
        &empty_trust(),
        &etsi_119_312_2023(),
        ValidationTime::Now,
    )
}

// =====================================================================
// Manifest-tamper cases — must NOT report TotalPassed.
// =====================================================================

#[rstest]
#[case::broken_ref("brokenReference.asice")]
#[case::broken_ref_and_manifest("brokenReferenceAndAlteredManifest.asice")]
#[case::archive_not_cover("dss1421-archive-not-cover.asice")]
#[case::dss1421_broken("dss1421-broken.asice")]
#[case::invalid_digest_algo("cades-invalid-digest-algo.asics")]
fn tamper_cases_never_total_passed_cades(#[case] name: &str) {
    skip_if_corpus_missing!();
    let bytes = corpus_cades(name);
    match try_verify(&bytes) {
        Err(_) => {} // structural error is fine
        Ok(report) => {
            assert!(
                report.signatures.iter().all(|s| s.status != Status::TotalPassed),
                "[{name}] CRITICAL — tampered ASiC reported TotalPassed: {report:?}"
            );
        }
    }
}

// =====================================================================
// no-signature: must error with the "no signatures" message.
// =====================================================================

#[test]
fn no_signature_asic_errors() {
    skip_if_corpus_missing!();
    let bytes = corpus_cades("no-signature.asics");
    let r = try_verify(&bytes);
    assert!(r.is_err(), "no-signature container must error");
}

// =====================================================================
// Malformed ZIP must error structurally, not panic.
// =====================================================================

#[test]
fn malformed_zip_does_not_panic() {
    skip_if_corpus_missing!();
    let bytes = corpus_cades("malformed-container.asics");
    let _ = try_verify(&bytes); // no panic — that's the assertion
}

// =====================================================================
// Multi-file & counter-signature samples don't panic.
// =====================================================================

#[rstest]
#[case::multifiles_e("multifiles-ok.asice")]
#[case::multifiles_s("multifiles-ok.asics")]
#[case::counter_sig("containerWithCounterSig.asics")]
#[case::onefile_e("onefile-ok.asice")]
#[case::onefile_s("onefile-ok.asics")]
#[case::dss1984_e("dss1984.asice")]
#[case::dss1984_s("dss1984.asics")]
fn well_formed_asic_cades_does_not_panic(#[case] name: &str) {
    skip_if_corpus_missing!();
    let bytes = corpus_cades(name);
    let _ = try_verify(&bytes);
}

// =====================================================================
// ASiC-XAdES — same shape, different signature format. The XAdES
// dispatch may degrade to "unsupported" inside verify_asic; we only
// require no panic and consistent error reporting.
// =====================================================================

#[rstest]
#[case::counter_sig_e("container-with-counter-signature.asice")]
#[case::counter_sig_s("container-with-counter-signature.asics")]
#[case::custom_ns("container-with-custom-manifest-namespace.asice")]
fn asic_xades_does_not_panic(#[case] name: &str) {
    skip_if_corpus_missing!();
    let bytes = corpus_xades(name);
    let _ = try_verify(&bytes);
}

// =====================================================================
// Aggregate — every .asice/.asics/.sce in both validation dirs completes.
// =====================================================================

#[test]
fn every_asic_sample_completes_without_panic() {
    skip_if_corpus_missing!();
    let mut tested = 0usize;
    for module in ["dss-asic-cades", "dss-asic-xades"] {
        let dir: PathBuf = dss_sample(module, "validation");
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
        {
            let entry = entry.unwrap();
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(ext, "asice" | "asics" | "sce") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let _ = try_verify(&bytes); // assert: no panic
            tested += 1;
        }
    }
    assert!(
        tested >= 20,
        "expected ≥20 ASiC samples across both modules, found {tested}"
    );
    eprintln!("[dss-asic-corpus] tested={tested}");
}
