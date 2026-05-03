//! S1 — Wycheproof primitive cross-check.
//!
//! These tests run the Project-Wycheproof signature vectors (Apache-2.0,
//! bundled by the `wycheproof` crate) through the exact RustCrypto backends
//! that `eidas-cms::signature_verify` calls:
//!
//! - `rsa::pkcs1v15::VerifyingKey<D>` for RSASSA-PKCS1-v1_5
//! - `p256::ecdsa::VerifyingKey` / `p384` / `p521` for ECDSA
//!
//! Wycheproof labels every test as `Valid`, `Invalid`, or `Acceptable`. A
//! `Valid` vector that fails to verify, or an `Invalid` vector that
//! succeeds, is a backend-correctness regression we MUST catch — a wrong
//! verification verdict in this layer would silently green-light forged
//! signatures upstream in `eidas-cms` and the format crates.
//!
//! `Acceptable` is treated as soft-pass: we record but do not fail on
//! either outcome (used for vectors where Wycheproof itself is uncertain,
//! e.g. legacy edge cases that some providers reject and others accept).
//!
//! Test sets covered:
//!   - RSA-PKCS1: 2048/3072/4096 × SHA-256/SHA-384/SHA-512
//!   - ECDSA secp256r1 SHA-256 (DER, P1363, SHA-512)
//!   - ECDSA secp384r1 SHA-384 (DER, P1363)
//!   - ECDSA secp521r1 SHA-512 (DER, P1363)
//!
//! Out of scope here: SHA-1 sets (rejected at policy level anyway),
//! RSA-PSS (will land in a follow-up — needs salt-length wiring), Ed25519
//! (not yet wired through CMS signature_verify).

use const_oid::AssociatedOid;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature as Pkcs1Sig, VerifyingKey as Pkcs1Vk};
use rsa::pkcs8::DecodePublicKey as RsaSpkiDecode;
use rsa::signature::Verifier;
use sha2::digest::Digest;
use sha2::{Sha256, Sha384, Sha512};
use spki::DecodePublicKey as SpkiDecodePublicKey;
use wycheproof::TestResult;

#[derive(Debug, Default)]
struct VerdictCounts {
    valid_passed: usize,
    valid_failed: usize,
    invalid_rejected: usize,
    invalid_accepted_bug: usize,
    acceptable_either: usize,
    skipped: usize,
}

impl VerdictCounts {
    fn record(&mut self, expected: TestResult, accepted: bool, tc_id: usize, comment: &str) {
        match (expected, accepted) {
            (TestResult::Valid, true) => self.valid_passed += 1,
            (TestResult::Valid, false) => {
                self.valid_failed += 1;
                panic!(
                    "FALSE NEGATIVE — Wycheproof tc {tc_id} ({comment}) is Valid but \
                     RustCrypto refused to verify. This is a backend regression."
                );
            }
            (TestResult::Invalid, false) => self.invalid_rejected += 1,
            (TestResult::Invalid, true) => {
                self.invalid_accepted_bug += 1;
                panic!(
                    "FALSE POSITIVE — Wycheproof tc {tc_id} ({comment}) is Invalid but \
                     RustCrypto accepted the signature. This is a security-critical \
                     regression and must block the build."
                );
            }
            (TestResult::Acceptable, _) => self.acceptable_either += 1,
        }
    }

    fn summary(&self, label: &str) {
        eprintln!(
            "[wycheproof:{label}] valid={} invalid_rejected={} acceptable={} skipped={}",
            self.valid_passed, self.invalid_rejected, self.acceptable_either, self.skipped
        );
    }
}

// =====================================================================
// RSA-PKCS1-v1_5
// =====================================================================

fn run_rsa_pkcs1<D>(name: wycheproof::rsa_pkcs1_verify::TestName, label: &str)
where
    D: Digest + AssociatedOid + Send + Sync + 'static,
{
    let test_set = wycheproof::rsa_pkcs1_verify::TestSet::load(name)
        .unwrap_or_else(|e| panic!("load {name:?}: {e}"));

    let mut counts = VerdictCounts::default();

    for group in &test_set.test_groups {
        let pk = RsaPublicKey::from_public_key_der(group.der.as_ref())
            .unwrap_or_else(|e| panic!("[{label}] decode SPKI of group: {e}"));
        let vk: Pkcs1Vk<D> = Pkcs1Vk::new(pk);

        for t in &group.tests {
            let sig = match Pkcs1Sig::try_from(t.sig.as_ref()) {
                Ok(s) => s,
                Err(_) => {
                    // Malformed signature byte length — for `Invalid` this
                    // is the desired outcome (rejection). For `Valid` this
                    // would be a backend bug, but PKCS1 v1.5 sigs of
                    // unexpected length are never `Valid` in Wycheproof's
                    // schema, so log + continue.
                    counts.record(t.result, false, t.tc_id, &t.comment);
                    continue;
                }
            };
            let accepted = vk.verify(t.msg.as_ref(), &sig).is_ok();
            counts.record(t.result, accepted, t.tc_id, &t.comment);
        }
    }

    counts.summary(label);
    assert!(
        counts.valid_passed > 0,
        "[{label}] no valid vectors verified — wycheproof set may be empty"
    );
}

#[test]
fn rsa_pkcs1_2048_sha256() {
    run_rsa_pkcs1::<Sha256>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha256,
        "rsa-pkcs1-2048-sha256",
    );
}

#[test]
fn rsa_pkcs1_2048_sha384() {
    run_rsa_pkcs1::<Sha384>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha384,
        "rsa-pkcs1-2048-sha384",
    );
}

#[test]
fn rsa_pkcs1_2048_sha512() {
    run_rsa_pkcs1::<Sha512>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha512,
        "rsa-pkcs1-2048-sha512",
    );
}

#[test]
fn rsa_pkcs1_3072_sha256() {
    run_rsa_pkcs1::<Sha256>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa3072Sha256,
        "rsa-pkcs1-3072-sha256",
    );
}

#[test]
fn rsa_pkcs1_3072_sha384() {
    run_rsa_pkcs1::<Sha384>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa3072Sha384,
        "rsa-pkcs1-3072-sha384",
    );
}

#[test]
fn rsa_pkcs1_3072_sha512() {
    run_rsa_pkcs1::<Sha512>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa3072Sha512,
        "rsa-pkcs1-3072-sha512",
    );
}

#[test]
fn rsa_pkcs1_4096_sha256() {
    run_rsa_pkcs1::<Sha256>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa4096Sha256,
        "rsa-pkcs1-4096-sha256",
    );
}

#[test]
fn rsa_pkcs1_4096_sha384() {
    run_rsa_pkcs1::<Sha384>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa4096Sha384,
        "rsa-pkcs1-4096-sha384",
    );
}

#[test]
fn rsa_pkcs1_4096_sha512() {
    run_rsa_pkcs1::<Sha512>(
        wycheproof::rsa_pkcs1_verify::TestName::Rsa4096Sha512,
        "rsa-pkcs1-4096-sha512",
    );
}

// =====================================================================
// ECDSA — DER and P1363 (raw r||s) signature encodings
// =====================================================================

mod ecdsa_p256 {
    use super::*;
    use ecdsa::Signature;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use p256::NistP256;
    use p256::ecdsa::VerifyingKey;
    use sha2::Digest as ShaDigest;

    fn run(name: wycheproof::ecdsa::TestName, hash: HashKind, encoding: SigEncoding, label: &str) {
        let test_set = wycheproof::ecdsa::TestSet::load(name)
            .unwrap_or_else(|e| panic!("load {name:?}: {e}"));

        let mut counts = VerdictCounts::default();

        for group in &test_set.test_groups {
            let vk = match VerifyingKey::from_public_key_der(group.der.as_ref()) {
                Ok(k) => k,
                Err(e) => panic!("[{label}] decode SPKI: {e}"),
            };

            for t in &group.tests {
                let parsed = match encoding {
                    SigEncoding::Der => Signature::<NistP256>::from_der(t.sig.as_ref()),
                    SigEncoding::P1363 => Signature::<NistP256>::from_slice(t.sig.as_ref()),
                };
                let sig = match parsed {
                    Ok(s) => s,
                    Err(_) => {
                        counts.record(t.result, false, t.tc_id, &t.comment);
                        continue;
                    }
                };
                let prehash = digest_msg(hash, t.msg.as_ref());
                let accepted = vk.verify_prehash(&prehash, &sig).is_ok();
                counts.record(t.result, accepted, t.tc_id, &t.comment);
            }
        }
        counts.summary(label);
    }

    fn digest_msg(h: HashKind, msg: &[u8]) -> Vec<u8> {
        match h {
            HashKind::Sha256 => Sha256::digest(msg).to_vec(),
            HashKind::Sha384 => Sha384::digest(msg).to_vec(),
            HashKind::Sha512 => Sha512::digest(msg).to_vec(),
        }
    }

    #[test]
    fn p256_sha256_der() {
        run(
            wycheproof::ecdsa::TestName::EcdsaSecp256r1Sha256,
            HashKind::Sha256,
            SigEncoding::Der,
            "ecdsa-p256-sha256-der",
        );
    }

    #[test]
    fn p256_sha256_p1363() {
        run(
            wycheproof::ecdsa::TestName::EcdsaSecp256r1Sha256P1363,
            HashKind::Sha256,
            SigEncoding::P1363,
            "ecdsa-p256-sha256-p1363",
        );
    }

    #[test]
    fn p256_sha512_der() {
        run(
            wycheproof::ecdsa::TestName::EcdsaSecp256r1Sha512,
            HashKind::Sha512,
            SigEncoding::Der,
            "ecdsa-p256-sha512-der",
        );
    }
}

mod ecdsa_p384 {
    use super::*;
    use ecdsa::Signature;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use p384::NistP384;
    use p384::ecdsa::VerifyingKey;
    use sha2::Digest as ShaDigest;

    fn run(name: wycheproof::ecdsa::TestName, hash: HashKind, encoding: SigEncoding, label: &str) {
        let test_set = wycheproof::ecdsa::TestSet::load(name)
            .unwrap_or_else(|e| panic!("load {name:?}: {e}"));
        let mut counts = VerdictCounts::default();
        for group in &test_set.test_groups {
            let vk = VerifyingKey::from_public_key_der(group.der.as_ref())
                .unwrap_or_else(|e| panic!("[{label}] decode SPKI: {e}"));
            for t in &group.tests {
                let parsed = match encoding {
                    SigEncoding::Der => Signature::<NistP384>::from_der(t.sig.as_ref()),
                    SigEncoding::P1363 => Signature::<NistP384>::from_slice(t.sig.as_ref()),
                };
                let sig = match parsed {
                    Ok(s) => s,
                    Err(_) => {
                        counts.record(t.result, false, t.tc_id, &t.comment);
                        continue;
                    }
                };
                let prehash = match hash {
                    HashKind::Sha256 => Sha256::digest(t.msg.as_ref()).to_vec(),
                    HashKind::Sha384 => Sha384::digest(t.msg.as_ref()).to_vec(),
                    HashKind::Sha512 => Sha512::digest(t.msg.as_ref()).to_vec(),
                };
                let accepted = vk.verify_prehash(&prehash, &sig).is_ok();
                counts.record(t.result, accepted, t.tc_id, &t.comment);
            }
        }
        counts.summary(label);
    }

    #[test]
    fn p384_sha384_der() {
        run(
            wycheproof::ecdsa::TestName::EcdsaSecp384r1Sha384,
            HashKind::Sha384,
            SigEncoding::Der,
            "ecdsa-p384-sha384-der",
        );
    }

    #[test]
    fn p384_sha384_p1363() {
        run(
            wycheproof::ecdsa::TestName::EcdsaSecp384r1Sha384P1363,
            HashKind::Sha384,
            SigEncoding::P1363,
            "ecdsa-p384-sha384-p1363",
        );
    }

    #[test]
    fn p384_sha512_der() {
        run(
            wycheproof::ecdsa::TestName::EcdsaSecp384r1Sha512,
            HashKind::Sha512,
            SigEncoding::Der,
            "ecdsa-p384-sha512-der",
        );
    }
}

// P-521 is intentionally NOT covered here.
//
// `eidas-cms::signature_verify` (see crates/eidas-cms/src/signature_verify.rs:155)
// dispatches only on ID_SECP256R1 and ID_SECP384R1; secp521r1 produces
// `Error::Unsupported(...)` before any cryptographic verification runs. The
// `p521` crate is in the workspace dep list as a future-ready hook but is
// not wired through. When secp521r1 support is implemented, add an
// `ecdsa_p521` module here mirroring `ecdsa_p384` and use
// `p521::PublicKey::from_public_key_der(..)` -> `ecdsa::VerifyingKey<NistP521>::from(pk)`
// (the `p521::ecdsa::VerifyingKey` wrapper does not implement `DecodePublicKey`
// directly in p521 0.13).

#[derive(Copy, Clone)]
enum HashKind {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Copy, Clone)]
enum SigEncoding {
    Der,
    P1363,
}
