//! Integration tests for the chain builder using rcgen-generated PKIs.

use chrono::{TimeZone, Utc};
use der::{Decode, Encode};
use eidas_core::Error;
use eidas_x509::chain::{parse_der, ChainBuilder, TrustAnchor};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use x509_cert::Certificate;

struct Pki {
    root_cert: Certificate,
    int_cert: Certificate,
    leaf_cert: Certificate,
}

fn to_x509(der: &[u8]) -> Certificate {
    Certificate::from_der(der).unwrap()
}

impl Pki {
    fn build() -> Self {
        // Validity window: 2024-01-01 → 2030-01-01 (well-bracketing `at_2025()`).
        let not_before = time::OffsetDateTime::from_unix_timestamp(1_704_067_200).unwrap();
        let not_after = time::OffsetDateTime::from_unix_timestamp(1_893_456_000).unwrap();

        // Root CA — self-signed
        let root_kp = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root_params
            .distinguished_name
            .push(DnType::CommonName, "eidas-verify test root");
        root_params.serial_number = Some(SerialNumber::from(1u64));
        root_params.not_before = not_before;
        root_params.not_after = not_after;
        let root = root_params.self_signed(&root_kp).unwrap();

        // Intermediate — signed by root
        let int_kp = KeyPair::generate().unwrap();
        let mut int_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        int_params
            .distinguished_name
            .push(DnType::CommonName, "eidas-verify test intermediate");
        int_params.serial_number = Some(SerialNumber::from(2u64));
        int_params.not_before = not_before;
        int_params.not_after = not_after;
        let int = int_params.signed_by(&int_kp, &root, &root_kp).unwrap();

        // Leaf — signed by intermediate
        let leaf_kp = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["signer.example.test".into()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "eidas-verify test signer");
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ];
        leaf_params.subject_alt_names =
            vec![SanType::DnsName("signer.example.test".try_into().unwrap())];
        leaf_params.serial_number = Some(SerialNumber::from(3u64));
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        let leaf = leaf_params.signed_by(&leaf_kp, &int, &int_kp).unwrap();

        Self {
            root_cert: to_x509(root.der()),
            int_cert: to_x509(int.der()),
            leaf_cert: to_x509(leaf.der()),
        }
    }
}

fn at_2025() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
}

#[test]
fn builds_two_tier_chain_with_intermediate() {
    let pki = Pki::build();
    let builder = ChainBuilder::new()
        .with_anchors([TrustAnchor::new(pki.root_cert.clone())])
        .with_intermediates([pki.int_cert.clone()]);
    let result = builder.build(pki.leaf_cert.clone(), at_2025()).unwrap();
    assert_eq!(result.chain.len(), 3, "leaf + intermediate + root");
    assert_eq!(
        result.anchor.subject_display(),
        "CN=eidas-verify test root"
    );
}

#[test]
fn self_signed_anchor_accepted_as_signer() {
    // Edge case: the signer IS the trust anchor (rare but legal).
    let pki = Pki::build();
    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root_cert.clone())]);
    let result = builder.build(pki.root_cert.clone(), at_2025()).unwrap();
    assert_eq!(result.chain.len(), 1);
}

#[test]
fn errors_when_no_anchors_configured() {
    let pki = Pki::build();
    let builder = ChainBuilder::new();
    let err = builder.build(pki.leaf_cert.clone(), at_2025()).unwrap_err();
    assert!(matches!(err, Error::Config(_)), "got {err:?}");
}

#[test]
fn errors_when_issuer_missing() {
    let pki = Pki::build();
    // Only the root anchor — no intermediate — should fail to find the
    // intermediate that signed the leaf.
    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root_cert.clone())]);
    let err = builder.build(pki.leaf_cert.clone(), at_2025()).unwrap_err();
    assert!(matches!(err, Error::Chain(_)), "got {err:?}");
}

#[test]
fn errors_when_evaluation_time_is_before_not_before() {
    let pki = Pki::build();
    let builder = ChainBuilder::new()
        .with_anchors([TrustAnchor::new(pki.root_cert.clone())])
        .with_intermediates([pki.int_cert.clone()]);
    let err = builder
        .build(
            pki.leaf_cert.clone(),
            Utc.with_ymd_and_hms(2010, 1, 1, 0, 0, 0).unwrap(),
        )
        .unwrap_err();
    assert!(matches!(err, Error::Chain(_)), "got {err:?}");
}

#[test]
fn errors_when_evaluation_time_is_after_not_after() {
    let pki = Pki::build();
    let builder = ChainBuilder::new()
        .with_anchors([TrustAnchor::new(pki.root_cert.clone())])
        .with_intermediates([pki.int_cert.clone()]);
    let err = builder
        .build(
            pki.leaf_cert.clone(),
            Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        )
        .unwrap_err();
    assert!(matches!(err, Error::Chain(_)), "got {err:?}");
}

#[test]
fn parse_der_roundtrip_preserves_subject() {
    let pki = Pki::build();
    let re = parse_der(&pki.leaf_cert.to_der().unwrap()).unwrap();
    assert_eq!(
        re.tbs_certificate.subject,
        pki.leaf_cert.tbs_certificate.subject
    );
}
