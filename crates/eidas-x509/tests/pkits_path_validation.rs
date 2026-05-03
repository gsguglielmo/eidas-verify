//! S2 — NIST PKITS X.509 path-validation conformance tests.
//!
//! NIST's Public Key Interoperability Test Suite (CSRC PKITS, public
//! domain) ships ~250 named test cases that exercise every clause of
//! RFC 5280's certification path validation. The corpus is bootstrapped
//! by `tools/sync-corpus.sh` into `tests/vectors/pkits/`.
//!
//! Scope of this suite: only the categories `eidas-x509::chain::ChainBuilder`
//! actually implements. The chain builder today does:
//!   - DN-based issuer matching with optional AKI/SKI tightening,
//!   - validity-window enforcement (notBefore / notAfter at `at`),
//!   - basicConstraints CA-flag + keyUsage.keyCertSign on issuers.
//!
//! It does NOT do:
//!   - cryptographic verification of the issuer's signature over the
//!     subject (signatures are checked by `eidas-cms::signature_verify`
//!     for the leaf, but not over each intermediate),
//!   - certificate-policy processing (anyPolicy, requireExplicitPolicy,
//!     inhibitPolicyMapping, …),
//!   - name constraints,
//!   - CRL/OCSP — covered separately by `eidas-revocation`,
//!   - delta-CRL processing.
//!
//! PKITS sub-sections in scope: §4.1 (Signature Verification — partial),
//! §4.2 (Validity Periods), §4.3 (Name Chaining), §4.6 (basicConstraints),
//! §4.7 (Key Usage). The other sections are exercised at the chain
//! level only insofar as their fixtures conform — many are marked
//! `#[ignore]` because they probe features we deliberately do not
//! implement, with a doc comment naming which clause and where the
//! upgrade lands.
//!
//! Each PKITS test fixture below is a triple: (anchor cert, intermediate
//! certs, end-entity cert). The anchor is always
//! `TrustAnchorRootCertificate.crt`. Test cases live in arrays grouped
//! by spec section.

use std::path::PathBuf;

use chrono::{TimeZone, Utc};
use der::Decode;
use eidas_test_corpus::{pkits_present, pkits_root, skip_if_pkits_missing};
use eidas_x509::chain::{ChainBuilder, TrustAnchor};
use rstest::rstest;
use x509_cert::Certificate;

/// PKITS reference time. The whole suite's certificates are built around
/// 2010-01-01 — `at = 2011-04-15 12:00 UTC` lands inside every "valid"
/// window and outside every "InvalidNotBefore" / "InvalidNotAfter" one,
/// matching the spec's recommended validation date.
fn pkits_reference_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2011, 4, 15, 12, 0, 0).unwrap()
}

fn pkits_cert(name: &str) -> Certificate {
    let path: PathBuf = pkits_root().join("certs").join(name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    Certificate::from_der(&bytes)
        .unwrap_or_else(|e| panic!("decode {name}: {e}"))
}

fn pkits_anchor() -> TrustAnchor {
    TrustAnchor::new(pkits_cert("TrustAnchorRootCertificate.crt"))
}

fn build_with(intermediates: &[&str], ee: &str) -> Result<(), eidas_core::Error> {
    let anchor = pkits_anchor();
    let inters: Vec<Certificate> = intermediates.iter().map(|n| pkits_cert(n)).collect();
    let ee_cert = pkits_cert(ee);
    let bldr = ChainBuilder::new()
        .with_anchors([anchor])
        .with_intermediates(inters);
    bldr.build(ee_cert, pkits_reference_time()).map(|_| ())
}

/// Helper for asserting expected pass/fail with rich error context.
fn assert_chain(
    intermediates: &[&str],
    ee: &str,
    expect_ok: bool,
    pkits_id: &str,
    rationale: &str,
) {
    skip_if_pkits_missing!();
    let outcome = build_with(intermediates, ee);
    match (outcome, expect_ok) {
        (Ok(()), true) => {}
        (Err(e), true) => panic!(
            "PKITS {pkits_id} expected to PASS but failed: {e}\n  rationale: {rationale}"
        ),
        (Err(_), false) => {}
        (Ok(()), false) => panic!(
            "PKITS {pkits_id} expected to FAIL but chain built successfully.\n  \
             rationale: {rationale}\n  \
             This is likely a coverage gap in `eidas-x509::chain::ChainBuilder` \
             (no signature/policy/name-constraint enforcement at this layer)."
        ),
    }
}

// =====================================================================
// §4.1 Signature Verification
// =====================================================================
//
// The plain "Valid path" case ensures the chain builder accepts a
// well-formed two-step path. The signature-tampering cases (§4.1.2,
// §4.1.3) are NOT enforced by `ChainBuilder` today — it does not verify
// the issuer's signature over the child cert. We mark those `#[ignore]`
// pointing at the future enhancement.

#[test]
fn valid_certificate_path_test_1() {
    skip_if_pkits_missing!();
    assert_chain(
        &["GoodCACert.crt"],
        "ValidCertificatePathTest1EE.crt",
        true,
        "4.1.1",
        "Two-step chain (TrustAnchor → GoodCA → EE) must validate.",
    );
}

#[test]
#[ignore = "ChainBuilder does not verify issuer signatures over intermediates; \
            see crates/eidas-x509/src/chain.rs::build — would catch §4.1.2."]
fn invalid_ca_signature_test_2() {
    skip_if_pkits_missing!();
    assert_chain(
        &["BadSignedCACert.crt"],
        "InvalidCASignatureTest2EE.crt",
        false,
        "4.1.2",
        "BadSignedCA's signature does not verify under TrustAnchor's key.",
    );
}

#[test]
#[ignore = "ChainBuilder does not verify EE signatures; that's done by \
            eidas-cms::signature_verify which runs on the data not the chain. \
            §4.1.3 thus needs an integration-level test."]
fn invalid_ee_signature_test_3() {
    skip_if_pkits_missing!();
    assert_chain(
        &["GoodCACert.crt"],
        "InvalidEESignatureTest3EE.crt",
        false,
        "4.1.3",
        "EE's signature does not verify under GoodCA's key.",
    );
}

// =====================================================================
// §4.2 Validity Periods
// =====================================================================

#[rstest]
#[case::ca_not_before("BadnotBeforeDateCACert.crt", "InvalidCAnotBeforeDateTest1EE.crt", false, "4.2.1")]
#[case::ee_not_before("GoodCACert.crt", "InvalidEEnotBeforeDateTest2EE.crt", false, "4.2.2")]
#[case::valid_gentime_nb("GoodCACert.crt", "ValidGeneralizedTimenotBeforeDateTest4EE.crt", true, "4.2.4")]
#[case::ca_not_after("BadnotAfterDateCACert.crt", "InvalidCAnotAfterDateTest5EE.crt", false, "4.2.5")]
#[case::ee_not_after("GoodCACert.crt", "InvalidEEnotAfterDateTest6EE.crt", false, "4.2.6")]
#[case::valid_gentime_na("GoodCACert.crt", "ValidGeneralizedTimenotAfterDateTest8EE.crt", true, "4.2.8")]
fn validity_periods(
    #[case] intermediate: &str,
    #[case] ee: &str,
    #[case] expect_ok: bool,
    #[case] pkits_id: &str,
) {
    assert_chain(&[intermediate], ee, expect_ok, pkits_id, "Validity-period §4.2");
}

// PKITS §4.2.3 / §4.2.7 use UTCTime values from before the year 2000
// (encoded with the legacy 2-digit form). The `x509-cert` 0.2 crate's
// UTCTime decoder rejects these as "malformed ASN.1 DER value for
// UTCTime". The fixture is well-formed per RFC 5280 §4.1.2.5.1; this is
// an upstream limitation we'd have to work around with a pre-decoder
// patch or a fork. Documented as a deferred item.
#[test]
#[ignore = "x509-cert 0.2 cannot decode pre-2000 UTCTime; PKITS §4.2.3 / §4.2.7"]
fn validity_pre_2000_utctime_disabled() {
    skip_if_pkits_missing!();
    assert_chain(
        &["GoodCACert.crt"],
        "Validpre2000UTCnotBeforeDateTest3EE.crt",
        true,
        "4.2.3",
        "Pre-2000 UTCTime decoder limitation (upstream).",
    );
}

// =====================================================================
// §4.3 Name Chaining
// =====================================================================

// Two negative cases that ChainBuilder catches via byte-exact DN compare.
#[rstest]
#[case::name_chaining("GoodCACert.crt", "InvalidNameChainingTest1EE.crt", false, "4.3.1")]
#[case::ordering(    "NameOrderingCACert.crt", "InvalidNameChainingOrderTest2EE.crt", false, "4.3.2")]
fn name_chaining_negative(
    #[case] intermediate: &str,
    #[case] ee: &str,
    #[case] expect_ok: bool,
    #[case] pkits_id: &str,
) {
    assert_chain(&[intermediate], ee, expect_ok, pkits_id, "Name-chaining §4.3 (negative)");
}

// FINDING — RFC 5280 §7 name comparison rules require LDAP string-prep:
// whitespace collapsing, case folding, PrintableString↔UTF8String
// equivalence, and (where present) Unicode NFKC normalization. Our
// ChainBuilder uses byte-exact DN equality (`x509-cert::name::Name`'s
// derived `PartialEq`), so it rejects valid PKITS samples §4.3.3-§4.3.11
// where the issuer-DN-on-EE differs from subject-DN-on-CA only in
// whitespace, capitalization, or string encoding.
//
// Implementing §7 is a substantial undertaking (LDAP RFC 4518); listing
// each affected case here documents the gap. Each becomes a passing
// test once a normalizer lands.
#[rstest]
#[case::whitespace1( "GoodCACert.crt", "ValidNameChainingWhitespaceTest3EE.crt", true, "4.3.3")]
#[case::whitespace2( "GoodCACert.crt", "ValidNameChainingWhitespaceTest4EE.crt", true, "4.3.4")]
#[case::caps(        "GoodCACert.crt", "ValidNameChainingCapitalizationTest5EE.crt", true, "4.3.5")]
#[case::uids(        "UIDCACert.crt",  "ValidNameUIDsTest6EE.crt",                  true, "4.3.6")]
#[case::utf8(        "GoodCACert.crt", "ValidUTF8StringEncodedNamesTest9EE.crt",    true, "4.3.9")]
#[case::utf8_caseI(  "GoodCACert.crt", "ValidUTF8StringCaseInsensitiveMatchTest11EE.crt", true, "4.3.11")]
#[ignore = "ChainBuilder uses byte-exact DN equality; RFC 5280 §7 name-equivalence not implemented"]
fn name_chaining_normalized(
    #[case] intermediate: &str,
    #[case] ee: &str,
    #[case] expect_ok: bool,
    #[case] pkits_id: &str,
) {
    assert_chain(&[intermediate], ee, expect_ok, pkits_id,
        "Name-chaining §4.3 (RFC 5280 §7 normalization, deferred)");
}

// =====================================================================
// §4.6 basicConstraints
// =====================================================================
//
// CAs lacking `basicConstraints.cA = true` must NOT be accepted as
// issuers. Our `validate_issuer_ca_capability` enforces this.

#[rstest]
#[case::missing_bc(   "MissingbasicConstraintsCACert.crt",
                      "InvalidMissingbasicConstraintsTest1EE.crt", false, "4.6.1")]
#[case::ca_false(     "basicConstraintsCriticalcAFalseCACert.crt",
                      "InvalidcAFalseTest2EE.crt", false, "4.6.2")]
#[case::ca_false_nc(  "basicConstraintsNotCriticalcAFalseCACert.crt",
                      "InvalidcAFalseTest3EE.crt", false, "4.6.3")]
#[case::valid_nc(     "basicConstraintsNotCriticalCACert.crt",
                      "ValidbasicConstraintsNotCriticalTest4EE.crt", true, "4.6.4")]
fn basic_constraints_basics(
    #[case] intermediate: &str,
    #[case] ee: &str,
    #[case] expect_ok: bool,
    #[case] pkits_id: &str,
) {
    assert_chain(&[intermediate], ee, expect_ok, pkits_id,
        "basicConstraints §4.6 (CA-flag enforcement)");
}

// pathLenConstraint cases — `eidas-x509::chain` does NOT track path length.
// These document the gap.
#[test]
#[ignore = "ChainBuilder does not enforce pathLenConstraint; §4.6.5+ is a \
            future RFC 5280 §6.1.4(o) implementation."]
fn path_len_constraint_violation_caught() {
    skip_if_pkits_missing!();
    assert_chain(
        &["pathLenConstraint0CACert.crt", "pathLenConstraint0subCA2Cert.crt"],
        "InvalidpathLenConstraintTest5EE.crt",
        false,
        "4.6.5",
        "pathLenConstraint=0 disallows any sub-CA.",
    );
}

// =====================================================================
// §4.7 Key Usage
// =====================================================================
//
// Issuer keyUsage MUST include keyCertSign when validating an issuer-leaf
// link. Our implementation enforces this via `validate_issuer_ca_capability`.

#[rstest]
#[case::no_keycertsign_critical(
    "keyUsageCriticalkeyCertSignFalseCACert.crt",
    "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt", false, "4.7.1")]
#[case::no_keycertsign_noncritical(
    "keyUsageNotCriticalkeyCertSignFalseCACert.crt",
    "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt", false, "4.7.2")]
#[case::keyusage_not_critical(
    "keyUsageNotCriticalCACert.crt",
    "ValidkeyUsageNotCriticalTest3EE.crt", true, "4.7.3")]
fn key_usage(
    #[case] intermediate: &str,
    #[case] ee: &str,
    #[case] expect_ok: bool,
    #[case] pkits_id: &str,
) {
    assert_chain(&[intermediate], ee, expect_ok, pkits_id,
        "Key-usage §4.7 (keyCertSign on intermediates)");
}

// =====================================================================
// §4.8 Certificate Policies — NOT IMPLEMENTED
// §4.13 Name Constraints — NOT IMPLEMENTED
// =====================================================================
//
// These sections probe path-validation features that lie outside our
// current scope. Each is captured below as an `#[ignore]` placeholder
// so the test exists and unlocks once the feature lands.

#[test]
#[ignore = "Certificate-policy processing not implemented; see RFC 5280 §6.1.5(g)"]
fn cert_policy_4_8_1() {
    skip_if_pkits_missing!();
    assert_chain(
        &["GoodCACert.crt"],
        "ValidCertificatePathTest1EE.crt", // placeholder; real §4.8 has its own EE
        true,
        "4.8.x",
        "Policy processing is a future enhancement.",
    );
}

#[test]
#[ignore = "Name-constraints processing not implemented; see RFC 5280 §6.1.4"]
fn name_constraints_4_13_1() {
    skip_if_pkits_missing!();
    assert_chain(
        &["nameConstraintsDN1CACert.crt"],
        "ValidDNnameConstraintsTest1EE.crt",
        true,
        "4.13.1",
        "Name-constraints processing is a future enhancement.",
    );
}

// =====================================================================
// Self-test — make sure the anchor itself loads and the basic harness works.
// =====================================================================

#[test]
fn anchor_and_good_ca_load() {
    skip_if_pkits_missing!();
    let _ = pkits_anchor();
    let _ = pkits_cert("GoodCACert.crt");
    assert!(pkits_present());
}
