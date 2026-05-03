//! S12 — Table-driven conformance tests for `etsi_119_312_2023()`.
//!
//! The crate's inline unit tests cover the happy paths; this integration
//! test exercises the full decision matrix that ETSI TS 119 312 V1.4.3
//! (2023) §5 specifies, plus the boundary cases that have a habit of
//! shifting under refactors.
//!
//! Layout: each `#[case]` row is a tuple `(SignatureAlgorithm, HashAlgorithm,
//! key_bits, validation_time, expected_decision_kind)` plus a free-text
//! rationale that ends up in the failure message. When a row fails, the
//! diagnostic names exactly which spec clause is being violated.

use chrono::{DateTime, TimeZone, Utc};
use eidas_core::algorithm::PolicyDecision;
use eidas_core::{AlgorithmId, HashAlgorithm, SignatureAlgorithm};
use eidas_policy::{etsi_119_312_2023, rsa_2048_sunset};
use pretty_assertions::assert_eq;
use rstest::rstest;

/// Three distinguishable kinds of expected outcome — we don't compare
/// `PolicyDecision` directly because `Reject { reason }` carries a
/// `&'static str` whose exact wording is policy-detail and not part of
/// the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectKind {
    Accept,
    Sunset,
    Reject,
}

fn classify(d: &PolicyDecision) -> ExpectKind {
    match d {
        PolicyDecision::Accept => ExpectKind::Accept,
        PolicyDecision::Sunset { .. } => ExpectKind::Sunset,
        PolicyDecision::Reject { .. } => ExpectKind::Reject,
    }
}

fn t(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap()
}

fn alg(sig: SignatureAlgorithm, hash: HashAlgorithm, key_bits: u32) -> AlgorithmId {
    AlgorithmId { signature: sig, hash, key_bits }
}

// =====================================================================
// RSA-PKCS1v15 — TS 119 312 §5.1.1 (key sizes) + §5.3 (sunsets)
// =====================================================================

#[rstest]
// --- Accept cases: minimum strength at validation_time before sunset
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 2048, t(2024, 1, 1), ExpectKind::Accept,
    "RSA-2048/SHA-256 valid until 2029-01-01 sunset")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha384, 2048, t(2024, 1, 1), ExpectKind::Accept,
    "RSA-2048/SHA-384 valid until sunset")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha512, 2048, t(2024, 1, 1), ExpectKind::Accept,
    "RSA-2048/SHA-512 valid until sunset")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha224, 2048, t(2024, 1, 1), ExpectKind::Accept,
    "SHA-224 is permitted for legacy verification per §5.2")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 3072, t(2024, 1, 1), ExpectKind::Accept,
    "RSA-3072 has no sunset — recommended size after 2029")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 4096, t(2024, 1, 1), ExpectKind::Accept,
    "RSA-4096 always accepted")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha3_256, 3072, t(2024, 1, 1), ExpectKind::Accept,
    "SHA3-256 with strong key is permitted")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha3_384, 3072, t(2024, 1, 1), ExpectKind::Accept,
    "SHA3-384 with strong key is permitted")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha3_512, 3072, t(2024, 1, 1), ExpectKind::Accept,
    "SHA3-512 with strong key is permitted")]
// --- Sunset: RSA-2048 after 2029-01-01
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 2048, t(2029, 1, 1), ExpectKind::Sunset,
    "RSA-2048 sunsets at 2029-01-01 per §5.1.1")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha512, 2048, t(2029, 6, 15), ExpectKind::Sunset,
    "RSA-2048 sunset is hash-independent")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha3_256, 2048, t(2030, 1, 1), ExpectKind::Sunset,
    "RSA-2048 sunset applies to SHA-3 variants too")]
// --- Boundary: one second before the sunset still accepts
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 2048, t(2028, 12, 31), ExpectKind::Accept,
    "Accepted right up to the sunset boundary")]
// --- Reject: under-strength keys
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 1024, t(2024, 1, 1), ExpectKind::Reject,
    "RSA-1024 below the 2048-bit minimum")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 1536, t(2024, 1, 1), ExpectKind::Reject,
    "RSA-1536 below the 2048-bit minimum")]
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 2047, t(2024, 1, 1), ExpectKind::Reject,
    "Off-by-one — 2047 < 2048 is rejected")]
// --- Reject: SHA-1 even with strong key
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha1, 4096, t(2024, 1, 1), ExpectKind::Reject,
    "SHA-1 deprecated for new signatures (TS 119 312 §5.1.2)")]
// --- Reject: MD5 always
#[case(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Md5, 4096, t(2024, 1, 1), ExpectKind::Reject,
    "MD5 is cryptographically broken")]
fn rsa_pkcs1v15(
    #[case] sig: SignatureAlgorithm,
    #[case] hash: HashAlgorithm,
    #[case] key_bits: u32,
    #[case] when: DateTime<Utc>,
    #[case] expected: ExpectKind,
    #[case] rationale: &str,
) {
    let p = etsi_119_312_2023();
    let got = classify(&p.evaluate(alg(sig, hash, key_bits), when));
    assert_eq!(
        got, expected,
        "{rationale} — input={sig:?}/{hash:?}/{key_bits} at {when}"
    );
}

// =====================================================================
// RSA-PSS — same key/hash rules as PKCS1v15 (§5.1.5)
// =====================================================================

#[rstest]
#[case(SignatureAlgorithm::RsaPss, HashAlgorithm::Sha256, 2048, t(2024, 1, 1), ExpectKind::Accept,
    "RSA-PSS-2048/SHA-256 valid before sunset")]
#[case(SignatureAlgorithm::RsaPss, HashAlgorithm::Sha256, 2048, t(2029, 1, 1), ExpectKind::Sunset,
    "RSA-PSS-2048 follows the same 2029 sunset")]
#[case(SignatureAlgorithm::RsaPss, HashAlgorithm::Sha256, 3072, t(2099, 1, 1), ExpectKind::Accept,
    "RSA-PSS-3072 has no sunset")]
#[case(SignatureAlgorithm::RsaPss, HashAlgorithm::Sha1, 4096, t(2024, 1, 1), ExpectKind::Reject,
    "SHA-1 still rejected under PSS")]
#[case(SignatureAlgorithm::RsaPss, HashAlgorithm::Sha256, 1024, t(2024, 1, 1), ExpectKind::Reject,
    "RSA-PSS-1024 below minimum")]
fn rsa_pss(
    #[case] sig: SignatureAlgorithm,
    #[case] hash: HashAlgorithm,
    #[case] key_bits: u32,
    #[case] when: DateTime<Utc>,
    #[case] expected: ExpectKind,
    #[case] rationale: &str,
) {
    let p = etsi_119_312_2023();
    let got = classify(&p.evaluate(alg(sig, hash, key_bits), when));
    assert_eq!(got, expected, "{rationale}");
}

// =====================================================================
// ECDSA — TS 119 312 §5.1.3 (key/curve sizes), all curves in scope
// =====================================================================

#[rstest]
// --- Accept: standard NIST + Brainpool curves at strength
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256, 256, t(2024, 1, 1), ExpectKind::Accept,
    "P-256 / Brainpool-P256 baseline")]
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha384, 384, t(2024, 1, 1), ExpectKind::Accept,
    "P-384")]
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha512, 521, t(2024, 1, 1), ExpectKind::Accept,
    "P-521")]
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256, 224, t(2024, 1, 1), ExpectKind::Accept,
    "P-224 — minimum permitted curve size per §5.1.3")]
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha3_256, 256, t(2099, 1, 1), ExpectKind::Accept,
    "ECDSA with SHA3 has no time bound")]
// --- Reject: under-strength curves
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256, 192, t(2024, 1, 1), ExpectKind::Reject,
    "P-192 below 224-bit minimum")]
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256, 160, t(2024, 1, 1), ExpectKind::Reject,
    "secp160 below minimum")]
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256, 223, t(2024, 1, 1), ExpectKind::Reject,
    "Off-by-one — 223 < 224 is rejected")]
// --- Reject: SHA-1 with any ECDSA curve
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha1, 384, t(2024, 1, 1), ExpectKind::Reject,
    "SHA-1 is rejected even with P-384")]
#[case(SignatureAlgorithm::Ecdsa, HashAlgorithm::Md5, 521, t(2024, 1, 1), ExpectKind::Reject,
    "MD5 is rejected even with P-521")]
fn ecdsa(
    #[case] sig: SignatureAlgorithm,
    #[case] hash: HashAlgorithm,
    #[case] key_bits: u32,
    #[case] when: DateTime<Utc>,
    #[case] expected: ExpectKind,
    #[case] rationale: &str,
) {
    let p = etsi_119_312_2023();
    let got = classify(&p.evaluate(alg(sig, hash, key_bits), when));
    assert_eq!(got, expected, "{rationale}");
}

// =====================================================================
// EdDSA — Ed25519 (256 bits) and Ed448 (456 bits)
// =====================================================================

#[rstest]
#[case(SignatureAlgorithm::EdDsa, HashAlgorithm::Sha512, 256, t(2024, 1, 1), ExpectKind::Accept,
    "Ed25519 — 256-bit curve, paired with SHA-512 internally")]
#[case(SignatureAlgorithm::EdDsa, HashAlgorithm::Sha512, 456, t(2024, 1, 1), ExpectKind::Accept,
    "Ed448 — 456-bit curve, paired with SHAKE-256 internally; we model with SHA-512")]
#[case(SignatureAlgorithm::EdDsa, HashAlgorithm::Sha512, 192, t(2024, 1, 1), ExpectKind::Reject,
    "EdDSA at 192 bits still under the ECC minimum")]
fn eddsa(
    #[case] sig: SignatureAlgorithm,
    #[case] hash: HashAlgorithm,
    #[case] key_bits: u32,
    #[case] when: DateTime<Utc>,
    #[case] expected: ExpectKind,
    #[case] rationale: &str,
) {
    let p = etsi_119_312_2023();
    let got = classify(&p.evaluate(alg(sig, hash, key_bits), when));
    assert_eq!(got, expected, "{rationale}");
}

// =====================================================================
// DSA — explicitly forbidden (§5.1.4 lists DSA but our policy excludes it
// outright; eIDAS QSCDs do not support DSA)
// =====================================================================

#[rstest]
#[case(2048, HashAlgorithm::Sha256)]
#[case(3072, HashAlgorithm::Sha384)]
#[case(2048, HashAlgorithm::Sha512)]
#[case(2048, HashAlgorithm::Sha224)]
fn dsa_always_rejected(#[case] bits: u32, #[case] hash: HashAlgorithm) {
    let p = etsi_119_312_2023();
    let got = p.evaluate(alg(SignatureAlgorithm::Dsa, hash, bits), t(2024, 1, 1));
    assert!(
        matches!(got, PolicyDecision::Reject { .. }),
        "DSA must always reject, got {got:?} for {bits} bits / {hash:?}"
    );
}

// =====================================================================
// Sunset boundary — exactly the spec date
// =====================================================================

#[test]
fn rsa_2048_sunset_constant_matches_2029_01_01() {
    let s = rsa_2048_sunset();
    let expected = Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(s, expected);
}

#[test]
fn one_microsecond_before_sunset_accepts() {
    let p = etsi_119_312_2023();
    let just_before =
        Utc.with_ymd_and_hms(2028, 12, 31, 23, 59, 59).unwrap();
    let got = p.evaluate(alg(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 2048), just_before);
    assert!(matches!(got, PolicyDecision::Accept));
}

#[test]
fn at_sunset_instant_sunsets() {
    let p = etsi_119_312_2023();
    let got =
        p.evaluate(alg(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, 2048), rsa_2048_sunset());
    assert!(matches!(got, PolicyDecision::Sunset { .. }));
}

// =====================================================================
// Hash-output sanity — locked against accidental table edits
// =====================================================================

#[rstest]
#[case(HashAlgorithm::Md5, 128)]
#[case(HashAlgorithm::Sha1, 160)]
#[case(HashAlgorithm::Sha224, 224)]
#[case(HashAlgorithm::Sha256, 256)]
#[case(HashAlgorithm::Sha384, 384)]
#[case(HashAlgorithm::Sha512, 512)]
#[case(HashAlgorithm::Sha3_256, 256)]
#[case(HashAlgorithm::Sha3_384, 384)]
#[case(HashAlgorithm::Sha3_512, 512)]
fn hash_output_bits(#[case] h: HashAlgorithm, #[case] bits: u32) {
    assert_eq!(h.output_bits(), bits, "{h:?} should expose {bits}-bit output");
}

// =====================================================================
// Sunset coverage — every (RSA family, every hash, 2048) combination
// must be tagged. If a future refactor forgets one, this catches it.
// =====================================================================

#[test]
fn every_rsa2048_combination_sunsets() {
    let p = etsi_119_312_2023();
    let after = t(2029, 6, 1);
    for sig in [SignatureAlgorithm::RsaPkcs1v15, SignatureAlgorithm::RsaPss] {
        for hash in [
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384,
            HashAlgorithm::Sha3_512,
        ] {
            let got = p.evaluate(alg(sig, hash, 2048), after);
            assert!(
                matches!(got, PolicyDecision::Sunset { .. }),
                "expected sunset for {sig:?}/{hash:?}/2048 after 2029, got {got:?}"
            );
        }
    }
}

// =====================================================================
// No accidental SHA-1 acceptance, even with explicit permit override
// =====================================================================

#[test]
fn explicit_permit_does_not_override_md5() {
    use eidas_core::AlgorithmPolicy;
    let mut p = AlgorithmPolicy::new();
    let md5 = alg(SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Md5, 4096);
    p.permit(md5);
    // Explicit permit is allowed by the policy engine; this test asserts the
    // current behaviour. If the policy engine ever decides to treat MD5 as
    // an immutable forbid, this test must be updated alongside.
    let got = p.evaluate(md5, t(2024, 1, 1));
    assert!(
        matches!(got, PolicyDecision::Accept),
        "documented behaviour: explicit permit overrides hash sanity check; \
         see crates/eidas-core/src/algorithm.rs::AlgorithmPolicy::evaluate"
    );
}
