//! S11 — Qualification (TS 119 615) extensions with the DSS corpus.
//!
//! Drives `qualify_signer` against:
//!   - the real EU LOTL parsed by `eidas_trust::parse_trusted_list`,
//!   - real signer certificates from
//!     `dss-validation/src/test/resources/{certificates,qwac}/`.
//!
//! With only the LOTL (a list of pointers to MS TLs) and not the
//! per-Member-State TLs themselves, no signer chain will match a
//! TSP service entry. The expected result is
//! `Qualification = baseline` plus a `QUALIFY_NO_TSL_MATCH` diagnostic.
//! That degenerate path is itself worth locking in: it confirms the
//! engine never returns AdES-QC / QES on a chain it cannot match.

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{TimeZone, Utc};
use der::Decode;
use eidas_core::Qualification;
use eidas_qualify::{qualify_signer, QualificationInput};
use eidas_test_corpus::{dss_sample, skip_if_corpus_missing};
use eidas_trust::{parse_trusted_list, TrustedLists};
use rstest::rstest;
use x509_cert::Certificate;

/// Load either DER (bytes start with 0x30) or PEM (`-----BEGIN
/// CERTIFICATE-----`) — the DSS corpus mixes both, sometimes with
/// CRLF-only line breaks and the entire body on one line.
fn load_cert(path: &PathBuf) -> Certificate {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let der = if bytes.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(&bytes).expect("PEM is UTF-8");
        // Locate the BEGIN/END markers and grab whatever sits between.
        let begin_end = s.find("-----")
            .and_then(|_| s.find("CERTIFICATE-----"))
            .map(|i| i + "CERTIFICATE-----".len())
            .expect("missing BEGIN marker");
        let end_marker = s[begin_end..].find("-----END").expect("missing END marker");
        let body = &s[begin_end..begin_end + end_marker];
        // Strip every whitespace-class char (\r, \n, space, tab).
        let cleaned: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        STANDARD.decode(&cleaned).expect("PEM body is base64")
    } else {
        bytes
    };
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("decode {path:?}: {e}"))
}

fn cert(name: &str) -> Certificate {
    load_cert(&dss_sample("dss-validation", &format!("certificates/{name}")))
}

fn qwac_cert(name: &str) -> Certificate {
    load_cert(&dss_sample("dss-validation", &format!("qwac/{name}")))
}

fn eu_lotl_only() -> TrustedLists {
    let xml = std::fs::read(dss_sample("dss-tsl-validation", "eu-lotl.xml"))
        .expect("eu-lotl.xml");
    let tl = parse_trusted_list(&xml).expect("LOTL parses");
    TrustedLists { lists: vec![tl] }
}

fn ref_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap()
}

// =====================================================================
// LOTL-only qualification: no MS TL → no match → baseline preserved.
// =====================================================================

#[rstest]
#[case::ec1("ec.europa.eu.1.cer")]
#[case::ec2("ec.europa.eu.2.cer")]
#[case::ec3("ec.europa.eu.3.cer")]
#[case::cz("CZ.cer")]
#[case::charlie("charlie_doe_tc.crt")]
fn lotl_only_yields_no_match_diagnostic(#[case] name: &str) {
    skip_if_corpus_missing!();
    let signer = cert(name);
    let chain = [signer.clone()];
    let tls = eu_lotl_only();
    let out = qualify_signer(&QualificationInput {
        signer: &signer,
        chain: &chain,
        trusted_lists: &tls,
        at: ref_time(),
        baseline: Qualification::AdES,
    });

    assert_eq!(
        out.qualification,
        Qualification::AdES,
        "[{name}] no MS TL → must preserve baseline AdES"
    );
    assert!(
        out.diagnostics
            .iter()
            .any(|d| d.code == "QUALIFY_NO_TSL_MATCH"),
        "[{name}] expected QUALIFY_NO_TSL_MATCH; got: {:?}",
        out.diagnostics
    );
    assert!(
        out.territory.is_none(),
        "[{name}] no match must also yield no territory"
    );
}

// =====================================================================
// QWAC certificates — the qwac/ folder ships QWAC samples that DSS
// uses to exercise QcForWSA / QcForESig disambiguation. Same LOTL-only
// expectation applies.
// =====================================================================

#[rstest]
#[case::harica("harica.cer")]
#[case::harica_ca("harica_ca.cer")]
fn qwac_certs_qualify_layer_does_not_panic(#[case] name: &str) {
    skip_if_corpus_missing!();
    let signer = qwac_cert(name);
    let chain = [signer.clone()];
    let tls = eu_lotl_only();
    let out = qualify_signer(&QualificationInput {
        signer: &signer,
        chain: &chain,
        trusted_lists: &tls,
        at: ref_time(),
        baseline: Qualification::AdES,
    });
    // qcStatements parsing must not panic — that's the contract.
    let _ = out.qc_statements;
}

// =====================================================================
// Empty trust-list set: the engine must still return baseline + a
// no-match diagnostic, never elevate to AdES-QC / QES.
// =====================================================================

#[test]
fn empty_trust_list_set_returns_baseline_with_no_match() {
    skip_if_corpus_missing!();
    let signer = cert("ec.europa.eu.1.cer");
    let chain = [signer.clone()];
    let tls = TrustedLists { lists: Vec::new() };
    let out = qualify_signer(&QualificationInput {
        signer: &signer,
        chain: &chain,
        trusted_lists: &tls,
        at: ref_time(),
        baseline: Qualification::AdES,
    });
    assert_eq!(out.qualification, Qualification::AdES);
    assert!(
        out.diagnostics
            .iter()
            .any(|d| d.code == "QUALIFY_NO_TSL_MATCH")
    );
}

// =====================================================================
// Critical safety property: WITHOUT a matching TL service, the engine
// MUST NOT promote the qualification to AdES-QC or QES. This is the
// exact case where a misimplementation could green-light forged signed
// content as "QES" when no legal authority backs it.
// =====================================================================

#[test]
fn no_match_never_promotes_to_qes() {
    skip_if_corpus_missing!();
    let signer = cert("ec.europa.eu.1.cer");
    let chain = [signer.clone()];
    let tls = eu_lotl_only();
    for baseline in [
        Qualification::NotAdES,
        Qualification::AdES,
        Qualification::AdESqc,
        Qualification::QES,
    ] {
        let out = qualify_signer(&QualificationInput {
            signer: &signer,
            chain: &chain,
            trusted_lists: &tls,
            at: ref_time(),
            baseline,
        });
        // baseline is preserved exactly when there's no match.
        assert_eq!(
            out.qualification, baseline,
            "with no TL match the engine must preserve baseline ({baseline:?})"
        );
    }
}
