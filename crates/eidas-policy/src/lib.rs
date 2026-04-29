//! Concrete algorithm policies matching ETSI TS 119 312.
//!
//! Policies are versioned by publication year (`etsi_119_312_2023`, …) so
//! callers upgrade explicitly. The table encodes the two pieces of TS 119 312
//! that matter for verification:
//!
//! 1. Minimum strengths: RSA ≥ 2048, ECC ≥ 224, hash ≥ 224 bits.
//! 2. Sunset dates for weaker-but-still-permitted algorithms. The dates below
//!    track the table in the 2023 revision; they are conservative — callers
//!    tightening a policy always stays safe.

use chrono::{DateTime, TimeZone, Utc};
use eidas_core::{AlgorithmId, AlgorithmPolicy, HashAlgorithm, SignatureAlgorithm};

/// Build the policy defined by ETSI TS 119 312 V1.4.3 (2023).
#[must_use]
pub fn etsi_119_312_2023() -> AlgorithmPolicy {
    let mut p = AlgorithmPolicy::new();
    p.min_rsa_bits = 2048;
    p.min_ecc_bits = 224;
    p.min_hash_bits = 224;
    p.allow_sha1 = false;

    // RSA-2048 sunsets at the end of 2028 per TS 119 312 §5.1; RSA-3072 and
    // above remain permitted indefinitely (but algorithms, not key sizes, are
    // what the enum encodes, so we apply the sunset only to the (alg, 2048)
    // combination).
    let end_2028 = Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 0).unwrap();

    for sig in [
        SignatureAlgorithm::RsaPkcs1v15,
        SignatureAlgorithm::RsaPss,
    ] {
        for hash in [
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384,
            HashAlgorithm::Sha3_512,
        ] {
            p.sunset(AlgorithmId { signature: sig, hash, key_bits: 2048 }, end_2028);
        }
    }

    // DSA is not permitted.
    for hash in [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ] {
        p.forbid(
            AlgorithmId { signature: SignatureAlgorithm::Dsa, hash, key_bits: 2048 },
            "DSA is not permitted for eIDAS signatures",
        );
        p.forbid(
            AlgorithmId { signature: SignatureAlgorithm::Dsa, hash, key_bits: 3072 },
            "DSA is not permitted for eIDAS signatures",
        );
    }
    p
}

/// Alias for the most recent policy. Prefer the versioned constructor to make
/// upgrades explicit in caller code.
#[must_use]
pub fn current() -> AlgorithmPolicy {
    etsi_119_312_2023()
}

/// Convenience: the sunset instant for RSA-2048 (end of 2028).
#[must_use]
pub fn rsa_2048_sunset() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 0).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidas_core::algorithm::PolicyDecision;
    use pretty_assertions::assert_eq;

    fn rsa(bits: u32, hash: HashAlgorithm) -> AlgorithmId {
        AlgorithmId { signature: SignatureAlgorithm::RsaPkcs1v15, hash, key_bits: bits }
    }

    fn ecdsa(bits: u32, hash: HashAlgorithm) -> AlgorithmId {
        AlgorithmId { signature: SignatureAlgorithm::Ecdsa, hash, key_bits: bits }
    }

    #[test]
    fn rsa_2048_sha256_accepted_today() {
        let today = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();
        assert!(matches!(
            etsi_119_312_2023().evaluate(rsa(2048, HashAlgorithm::Sha256), today),
            PolicyDecision::Accept
        ));
    }

    #[test]
    fn rsa_2048_sha256_sunset_in_2029() {
        let p = etsi_119_312_2023();
        let after = Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 1).unwrap();
        assert!(matches!(
            p.evaluate(rsa(2048, HashAlgorithm::Sha256), after),
            PolicyDecision::Sunset { .. }
        ));
    }

    #[test]
    fn rsa_3072_sha256_has_no_sunset() {
        let p = etsi_119_312_2023();
        let way_future = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        assert!(matches!(
            p.evaluate(rsa(3072, HashAlgorithm::Sha256), way_future),
            PolicyDecision::Accept
        ));
    }

    #[test]
    fn ecdsa_p256_sha256_accepted() {
        let p = etsi_119_312_2023();
        assert!(matches!(
            p.evaluate(ecdsa(256, HashAlgorithm::Sha256), Utc::now()),
            PolicyDecision::Accept
        ));
    }

    #[test]
    fn ecdsa_p192_rejected() {
        let p = etsi_119_312_2023();
        assert!(matches!(
            p.evaluate(ecdsa(192, HashAlgorithm::Sha256), Utc::now()),
            PolicyDecision::Reject { .. }
        ));
    }

    #[test]
    fn dsa_rejected() {
        let p = etsi_119_312_2023();
        let alg = AlgorithmId {
            signature: SignatureAlgorithm::Dsa,
            hash: HashAlgorithm::Sha256,
            key_bits: 3072,
        };
        assert!(matches!(p.evaluate(alg, Utc::now()), PolicyDecision::Reject { .. }));
    }

    #[test]
    fn sha1_rejected_even_with_strong_key() {
        let p = etsi_119_312_2023();
        assert!(matches!(
            p.evaluate(rsa(4096, HashAlgorithm::Sha1), Utc::now()),
            PolicyDecision::Reject { .. }
        ));
    }

    #[test]
    fn current_equals_2023() {
        // Sanity: if we add a newer version we should deliberately change the alias.
        assert_eq!(current().min_rsa_bits, etsi_119_312_2023().min_rsa_bits);
    }
}
