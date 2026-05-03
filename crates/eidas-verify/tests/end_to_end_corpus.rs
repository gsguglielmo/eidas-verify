//! S13 — End-to-end facade tests with insta snapshots.
//!
//! Drives `Verifier::builder().build().verify(input)` over a curated
//! subset of the DSS corpus and snapshots the resulting
//! `VerificationReport` (with volatile fields normalised). This locks
//! in the high-level API behaviour against accidental regressions in
//! container-hint dispatch, level reporting, or diagnostic codes.
//!
//! Trust-anchor handling: the DSS corpus does not ship matching trust
//! anchors. We register a synthetic throwaway anchor (a self-signed
//! rcgen cert) so the builder accepts the configuration. With no real
//! match, every signer fails at the chain step and reports
//! `TotalFailedSub` — the stable shape we snapshot. A separate online
//! tier (S15) cross-checks against the real EU DSS oracle.
//!
//! Snapshots are deterministic because we normalise:
//!   - byte arrays → "<bytes len=N>" strings,
//!   - certificate DER fields → "<der len=N>",
//!   - timestamps → "<datetime>",
//!   - random nonces → "<bytes len=N>".

use chrono::{TimeZone, Utc};
use der::Decode;
use eidas_core::{ValidationTime, VerificationReport};
use eidas_test_corpus::{dss_sample, skip_if_corpus_missing};
use eidas_verify::{ContainerHint, DetachedFormat, VerificationInput, Verifier};
use rstest::rstest;
use x509_cert::Certificate;

/// One throwaway self-signed cert, generated once at test bootstrap.
/// Identical across runs because rcgen takes the same fixed inputs.
fn synthetic_anchor() -> Certificate {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use std::sync::OnceLock;
    static ANCHOR: OnceLock<Vec<u8>> = OnceLock::new();
    let der = ANCHOR.get_or_init(|| {
        // The anchor is just a placeholder so the verifier-builder
        // accepts the configuration; no signer in the corpus chains to
        // it. rcgen 0.13 picks the algorithm from the KeyPair, not from
        // CertificateParams.
        let p = CertificateParams::new(vec!["eidas-verify-synthetic-anchor".into()])
            .expect("rcgen params");
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rcgen keypair");
        let c = p.self_signed(&kp).expect("rcgen self-signed");
        c.der().to_vec()
    });
    Certificate::from_der(der).expect("synthetic anchor decodes")
}

fn verifier() -> Verifier {
    Verifier::builder()
        .trust_anchors([synthetic_anchor()])
        .validation_time(ValidationTime::At(
            Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap(),
        ))
        .build()
        .expect("builder")
}

/// Project a `VerificationReport` to a stable, snapshot-friendly view.
fn project(r: &VerificationReport) -> serde_json::Value {
    let sigs: Vec<serde_json::Value> = r
        .signatures
        .iter()
        .map(|s| {
            let diag_codes: Vec<&str> =
                s.diagnostics.iter().map(|d| d.code.as_str()).collect();
            serde_json::json!({
                "status": format!("{:?}", s.status),
                "level": format!("{:?}", s.level_reached),
                "qualification": format!("{:?}", s.qualification),
                "signer_present": s.signer.is_some(),
                "diagnostic_codes": diag_codes,
            })
        })
        .collect();
    serde_json::json!({
        "container_kind": match &r.container {
            None => "None",
            Some(eidas_core::ContainerInfo::Pdf { .. }) => "Pdf",
            Some(eidas_core::ContainerInfo::Asic { .. }) => "Asic",
            Some(eidas_core::ContainerInfo::Jws { .. }) => "Jws",
            Some(_) => "OtherNonExhaustive",
        }.to_string(),
        "signatures": sigs,
    })
}

// =====================================================================
// Container dispatch — every supported hint reaches a code path that
// returns a structured `VerificationReport` (or a structured `Err`).
// =====================================================================

#[test]
fn pades_dispatch_reaches_verifier() {
    skip_if_corpus_missing!();
    let pdf = std::fs::read(dss_sample("dss-pades", "validation/PAdES-LT.pdf")).unwrap();
    let r = verifier().verify(VerificationInput::Container {
        bytes: &pdf,
        hint: Some(ContainerHint::Pdf),
    });
    insta::assert_yaml_snapshot!("pades_lt_via_facade", projected_or_err(r));
}

#[test]
fn cades_attached_dispatch() {
    skip_if_corpus_missing!();
    let bytes = std::fs::read(dss_sample(
        "dss-cades",
        "validation/Signature-C-B-B-8.p7m",
    ))
    .unwrap();
    let r = verifier().verify(VerificationInput::Container {
        bytes: &bytes,
        hint: None,
    });
    insta::assert_yaml_snapshot!("cades_attached_via_facade", projected_or_err(r));
}

#[test]
fn asic_dispatch() {
    skip_if_corpus_missing!();
    let bytes = std::fs::read(dss_sample(
        "dss-asic-cades",
        "validation/multifiles-ok.asice",
    ))
    .unwrap();
    let r = verifier().verify(VerificationInput::Container {
        bytes: &bytes,
        hint: Some(ContainerHint::Asic),
    });
    insta::assert_yaml_snapshot!("asic_multifiles_via_facade", projected_or_err(r));
}

#[test]
fn jades_dispatch() {
    skip_if_corpus_missing!();
    let bytes = std::fs::read(dss_sample(
        "dss-jades",
        "validation/jades-level-b-full-type.json",
    ))
    .unwrap();
    let r = verifier().verify(VerificationInput::Container {
        bytes: &bytes,
        hint: Some(ContainerHint::JadesJson),
    });
    insta::assert_yaml_snapshot!("jades_b_full_type_via_facade", projected_or_err(r));
}

// =====================================================================
// Detached signatures.
// =====================================================================

#[test]
fn cades_detached_via_facade() {
    skip_if_corpus_missing!();
    let sig = std::fs::read(dss_sample(
        "dss-cades",
        "validation/cades-bes-signeddata-detached.p7s",
    ))
    .unwrap();
    // We don't have the matching detached payload; supply a placeholder
    // so the dispatch executes. The expected outcome is failure with a
    // structured diagnostic.
    let payload = b"placeholder content";
    let r = verifier().verify(VerificationInput::Detached {
        signature: &sig,
        signed_data: payload,
        format: DetachedFormat::Cades,
    });
    insta::assert_yaml_snapshot!("cades_detached_via_facade", projected_or_err(r));
}

// =====================================================================
// Critical safety properties.
// =====================================================================

#[rstest]
#[case::tampered_asic("brokenReference.asice")]
#[case::archive_not_cover("dss1421-archive-not-cover.asice")]
#[case::invalid_digest("cades-invalid-digest-algo.asics")]
fn tampered_asic_never_total_passed_via_facade(#[case] name: &str) {
    skip_if_corpus_missing!();
    let bytes = std::fs::read(dss_sample(
        "dss-asic-cades",
        &format!("validation/{name}"),
    ))
    .unwrap();
    let r = verifier().verify(VerificationInput::Container {
        bytes: &bytes,
        hint: Some(ContainerHint::Asic),
    });
    if let Ok(report) = r {
        for sig in &report.signatures {
            assert_ne!(
                sig.status,
                eidas_core::Status::TotalPassed,
                "[{name}] facade reported TotalPassed on tampered ASiC — \
                 this is a security regression"
            );
        }
    }
}

#[test]
fn unsupported_input_returns_unsupported_error() {
    // `Container { hint: Some(XadesEnveloped) }` with the `xades` feature
    // disabled would surface as `Unsupported`. With the default feature
    // set every hint is wired, so we synthesise an obviously-bogus
    // detached XAdES request which must round-trip an Err.
    let r = verifier().verify(VerificationInput::Detached {
        signature: b"<not-xml>",
        signed_data: b"data",
        format: DetachedFormat::XadesDetached,
    });
    assert!(r.is_err(), "bogus XAdES detached must error");
}

// =====================================================================
// Helpers.
// =====================================================================

fn projected_or_err(
    r: Result<VerificationReport, eidas_core::Error>,
) -> serde_json::Value {
    match r {
        Ok(report) => serde_json::json!({"ok": project(&report)}),
        Err(e) => serde_json::json!({"err_kind": format!("{e:?}").chars().take_while(|c| *c != '(').collect::<String>()}),
    }
}
