//! Algorithm identifiers and the policy that accepts or rejects them.
//!
//! The concrete default policy (per ETSI TS 119 312) lives in the
//! `eidas-policy` crate; here we only provide the types and the evaluation
//! logic. Keeping policy data out of `eidas-core` lets callers depend on the
//! types without pulling in the (more volatile) policy tables.

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

/// Hash algorithms recognised by eIDAS / ETSI TS 119 312.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// MD5 — broken, only decoded for diagnostics.
    Md5,
    /// SHA-1 — deprecated for new signatures.
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    /// Minimum output size in bits. Used by the policy engine to enforce
    /// the "at least 224 bits" rule of TS 119 312.
    #[must_use]
    pub const fn output_bits(self) -> u32 {
        match self {
            Self::Md5 => 128,
            Self::Sha1 => 160,
            Self::Sha224 => 224,
            Self::Sha256 | Self::Sha3_256 => 256,
            Self::Sha384 | Self::Sha3_384 => 384,
            Self::Sha512 | Self::Sha3_512 => 512,
        }
    }
}

/// Signature algorithm families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5.
    RsaPkcs1v15,
    /// RSASSA-PSS.
    RsaPss,
    /// ECDSA over any curve.
    Ecdsa,
    /// EdDSA (Ed25519 / Ed448).
    EdDsa,
    /// DSA — legacy, flagged by default policies.
    Dsa,
}

/// A single (hash, signature-family, key-bits) triple.
///
/// This is the atomic unit the policy engine reasons about: every signer-info,
/// every digest attribute, every timestamp imprint distils down to an
/// `AlgorithmId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AlgorithmId {
    pub signature: SignatureAlgorithm,
    pub hash: HashAlgorithm,
    /// Key strength in bits (modulus size for RSA, curve size for ECDSA/EdDSA).
    pub key_bits: u32,
}

/// Outcome of policy evaluation for one algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Algorithm is permitted at the evaluation time.
    Accept,
    /// Algorithm was once permitted but passed its sunset date.
    Sunset {
        sunset: DateTime<Utc>,
    },
    /// Algorithm is forbidden outright.
    Reject {
        reason: &'static str,
    },
}

impl PolicyDecision {
    /// True if the decision permits continued use at `at`.
    #[must_use]
    pub fn is_accepted_at(&self, at: DateTime<Utc>) -> bool {
        match self {
            Self::Accept => true,
            Self::Sunset { sunset } => at < *sunset,
            Self::Reject { .. } => false,
        }
    }
}

/// Caller-configurable algorithm policy.
///
/// The default constructors in `eidas-policy` build a `AlgorithmPolicy` that
/// matches ETSI TS 119 312; this crate does not ship any table.
#[derive(Debug, Clone, Default)]
pub struct AlgorithmPolicy {
    /// Explicit permits. Anything present here overrides `forbidden` and sunsets.
    permitted: BTreeMap<AlgorithmId, ()>,
    /// Explicit forbids with a human-readable reason.
    forbidden: BTreeMap<AlgorithmId, &'static str>,
    /// Sunset dates — algorithm becomes rejected at and after `sunset`.
    sunsets: BTreeMap<AlgorithmId, DateTime<Utc>>,
    /// If no explicit rule matches, fall back to these blanket rules.
    pub min_rsa_bits: u32,
    pub min_ecc_bits: u32,
    pub min_hash_bits: u32,
    pub allow_sha1: bool,
}

impl AlgorithmPolicy {
    /// Empty policy that only enforces the minimum-strength fallbacks.
    #[must_use]
    pub fn new() -> Self {
        Self {
            permitted: BTreeMap::new(),
            forbidden: BTreeMap::new(),
            sunsets: BTreeMap::new(),
            min_rsa_bits: 2048,
            min_ecc_bits: 224,
            min_hash_bits: 224,
            allow_sha1: false,
        }
    }

    /// Explicitly permit `alg`.
    pub fn permit(&mut self, alg: AlgorithmId) -> &mut Self {
        self.forbidden.remove(&alg);
        self.sunsets.remove(&alg);
        self.permitted.insert(alg, ());
        self
    }

    /// Explicitly forbid `alg` with a reason.
    pub fn forbid(&mut self, alg: AlgorithmId, reason: &'static str) -> &mut Self {
        self.permitted.remove(&alg);
        self.forbidden.insert(alg, reason);
        self
    }

    /// Schedule `alg` to be rejected at and after `sunset`.
    pub fn sunset(&mut self, alg: AlgorithmId, sunset: DateTime<Utc>) -> &mut Self {
        self.sunsets.insert(alg, sunset);
        self
    }

    /// Evaluate `alg` at reference time `at`.
    #[must_use]
    pub fn evaluate(&self, alg: AlgorithmId, at: DateTime<Utc>) -> PolicyDecision {
        if let Some(reason) = self.forbidden.get(&alg) {
            return PolicyDecision::Reject { reason };
        }
        if self.permitted.contains_key(&alg) {
            // Explicit permits still honour their sunset if one was set afterwards.
            if let Some(&sunset) = self.sunsets.get(&alg) {
                if at >= sunset {
                    return PolicyDecision::Sunset { sunset };
                }
            }
            return PolicyDecision::Accept;
        }
        if let Some(&sunset) = self.sunsets.get(&alg) {
            if at >= sunset {
                return PolicyDecision::Sunset { sunset };
            }
        }
        self.evaluate_fallback(alg)
    }

    fn evaluate_fallback(&self, alg: AlgorithmId) -> PolicyDecision {
        if matches!(alg.hash, HashAlgorithm::Md5) {
            return PolicyDecision::Reject {
                reason: "MD5 is cryptographically broken",
            };
        }
        if matches!(alg.hash, HashAlgorithm::Sha1) && !self.allow_sha1 {
            return PolicyDecision::Reject {
                reason: "SHA-1 is deprecated for digital signatures",
            };
        }
        if alg.hash.output_bits() < self.min_hash_bits {
            return PolicyDecision::Reject {
                reason: "hash output below minimum strength",
            };
        }
        let min_for_family = match alg.signature {
            SignatureAlgorithm::RsaPkcs1v15 | SignatureAlgorithm::RsaPss => self.min_rsa_bits,
            SignatureAlgorithm::Ecdsa | SignatureAlgorithm::EdDsa => self.min_ecc_bits,
            SignatureAlgorithm::Dsa => {
                return PolicyDecision::Reject {
                    reason: "DSA is not permitted for eIDAS signatures",
                };
            }
        };
        if alg.key_bits < min_for_family {
            return PolicyDecision::Reject {
                reason: "key size below minimum strength",
            };
        }
        PolicyDecision::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn rsa_sha256(bits: u32) -> AlgorithmId {
        AlgorithmId {
            signature: SignatureAlgorithm::RsaPkcs1v15,
            hash: HashAlgorithm::Sha256,
            key_bits: bits,
        }
    }

    #[test]
    fn default_rejects_rsa_1024() {
        let p = AlgorithmPolicy::new();
        let d = p.evaluate(rsa_sha256(1024), Utc::now());
        assert!(matches!(d, PolicyDecision::Reject { .. }));
    }

    #[test]
    fn default_accepts_rsa_2048_sha256() {
        let p = AlgorithmPolicy::new();
        assert!(matches!(
            p.evaluate(rsa_sha256(2048), Utc::now()),
            PolicyDecision::Accept
        ));
    }

    #[test]
    fn sha1_rejected_by_default() {
        let p = AlgorithmPolicy::new();
        let alg = AlgorithmId {
            signature: SignatureAlgorithm::RsaPkcs1v15,
            hash: HashAlgorithm::Sha1,
            key_bits: 4096,
        };
        assert!(matches!(p.evaluate(alg, Utc::now()), PolicyDecision::Reject { .. }));
    }

    #[test]
    fn sunset_kicks_in_at_date() {
        let mut p = AlgorithmPolicy::new();
        let alg = rsa_sha256(2048);
        let sunset = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        p.sunset(alg, sunset);
        assert!(matches!(
            p.evaluate(alg, Utc.with_ymd_and_hms(2029, 12, 31, 0, 0, 0).unwrap()),
            PolicyDecision::Accept
        ));
        assert!(matches!(
            p.evaluate(alg, sunset),
            PolicyDecision::Sunset { .. }
        ));
    }

    #[test]
    fn explicit_forbid_overrides_fallback_accept() {
        let mut p = AlgorithmPolicy::new();
        let alg = rsa_sha256(4096);
        assert!(matches!(p.evaluate(alg, Utc::now()), PolicyDecision::Accept));
        p.forbid(alg, "corporate override");
        assert!(matches!(p.evaluate(alg, Utc::now()), PolicyDecision::Reject { .. }));
    }

    #[test]
    fn md5_always_rejected() {
        let mut p = AlgorithmPolicy::new();
        p.allow_sha1 = true; // even with relaxed SHA-1 policy
        let alg = AlgorithmId {
            signature: SignatureAlgorithm::RsaPkcs1v15,
            hash: HashAlgorithm::Md5,
            key_bits: 4096,
        };
        assert!(matches!(p.evaluate(alg, Utc::now()), PolicyDecision::Reject { .. }));
    }

    #[test]
    fn hash_output_bits_matches_expected() {
        assert_eq!(HashAlgorithm::Sha256.output_bits(), 256);
        assert_eq!(HashAlgorithm::Sha512.output_bits(), 512);
        assert_eq!(HashAlgorithm::Sha3_384.output_bits(), 384);
    }

    #[test]
    fn decision_is_accepted_at_respects_sunset() {
        let sunset = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        let d = PolicyDecision::Sunset { sunset };
        assert!(d.is_accepted_at(Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 0).unwrap()));
        assert!(!d.is_accepted_at(sunset));
    }
}
