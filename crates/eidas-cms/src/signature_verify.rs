//! Cryptographic signature verification: map algorithm OIDs to the right
//! RustCrypto verifier, and dispatch.
//!
//! Supported in Phase 2:
//! - RSA PKCS#1 v1.5 over SHA-224/256/384/512
//! - ECDSA over P-256 / P-384 with SHA-256/384/512 (P-521 requires an
//!   external ecdsa impl and lands in a later phase)
//!
//! Not yet supported (will fail with `Error::Unsupported`):
//! - RSASSA-PSS
//! - Ed25519 / Ed448
//! - SHA-3 hashes
//! - ECDSA P-521

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use eidas_core::{Error, Result};
use signature::{hazmat::PrehashVerifier, Verifier as SigVerifier};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::oids;

/// Verify `signature` against `data` using the signer certificate's public key.
///
/// The digest algorithm is determined by:
/// - the signature algorithm OID when it bundles the hash (e.g.
///   `sha256WithRSAEncryption`, `ecdsa-with-SHA256`), or
/// - the supplied `digest_hint` (from `SignerInfo.digest_alg`) when the
///   signature algorithm is generic (`rsaEncryption`, RSASSA-PSS).
pub fn verify_cms_signature(
    signer_cert: &Certificate,
    sig_alg: &AlgorithmIdentifierOwned,
    digest_hint: &AlgorithmIdentifierOwned,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let (family, hash_oid) = resolve_sig_alg(sig_alg, digest_hint)?;

    match family {
        SigFamily::RsaPkcs1V15 => rsa_pkcs1v15_verify(signer_cert, hash_oid, data, signature),
        SigFamily::Ecdsa => ecdsa_dispatch(signer_cert, hash_oid, data, signature),
        SigFamily::RsaPss => Err(Error::Unsupported(
            "RSASSA-PSS not yet implemented (phase 2 scope: PKCS#1v1.5 + ECDSA)".into(),
        )),
    }
}

#[derive(Debug, Clone, Copy)]
enum SigFamily {
    RsaPkcs1V15,
    RsaPss,
    Ecdsa,
}

fn resolve_sig_alg(
    sig_alg: &AlgorithmIdentifierOwned,
    digest_hint: &AlgorithmIdentifierOwned,
) -> Result<(SigFamily, ObjectIdentifier)> {
    match sig_alg.oid {
        oids::ID_RSA_ENCRYPTION => Ok((SigFamily::RsaPkcs1V15, digest_hint.oid)),
        oids::ID_SHA1_WITH_RSA => Ok((SigFamily::RsaPkcs1V15, oids::ID_SHA1)),
        oids::ID_SHA224_WITH_RSA => Ok((SigFamily::RsaPkcs1V15, oids::ID_SHA224)),
        oids::ID_SHA256_WITH_RSA => Ok((SigFamily::RsaPkcs1V15, oids::ID_SHA256)),
        oids::ID_SHA384_WITH_RSA => Ok((SigFamily::RsaPkcs1V15, oids::ID_SHA384)),
        oids::ID_SHA512_WITH_RSA => Ok((SigFamily::RsaPkcs1V15, oids::ID_SHA512)),
        oids::ID_RSA_PSS => Ok((SigFamily::RsaPss, digest_hint.oid)),
        oids::ID_ECDSA_SHA1 => Ok((SigFamily::Ecdsa, oids::ID_SHA1)),
        oids::ID_ECDSA_SHA224 => Ok((SigFamily::Ecdsa, oids::ID_SHA224)),
        oids::ID_ECDSA_SHA256 => Ok((SigFamily::Ecdsa, oids::ID_SHA256)),
        oids::ID_ECDSA_SHA384 => Ok((SigFamily::Ecdsa, oids::ID_SHA384)),
        oids::ID_ECDSA_SHA512 => Ok((SigFamily::Ecdsa, oids::ID_SHA512)),
        other => Err(Error::Unsupported(format!(
            "signature algorithm OID {other} not supported"
        ))),
    }
}

// ---- RSA PKCS#1 v1.5 ----

fn rsa_pkcs1v15_verify(
    cert: &Certificate,
    hash_oid: ObjectIdentifier,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;
    use sha2::{Sha224, Sha256, Sha384, Sha512};

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI encode: {e}")))?;
    let pk = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| Error::Crypto(format!("decoding RSA public key: {e}")))?;
    let sig = RsaSig::try_from(signature)
        .map_err(|e| Error::Crypto(format!("parsing RSA signature: {e}")))?;

    match hash_oid {
        oids::ID_SHA224 => VerifyingKey::<Sha224>::new(pk)
            .verify(data, &sig)
            .map_err(rsa_verify_err),
        oids::ID_SHA256 => VerifyingKey::<Sha256>::new(pk)
            .verify(data, &sig)
            .map_err(rsa_verify_err),
        oids::ID_SHA384 => VerifyingKey::<Sha384>::new(pk)
            .verify(data, &sig)
            .map_err(rsa_verify_err),
        oids::ID_SHA512 => VerifyingKey::<Sha512>::new(pk)
            .verify(data, &sig)
            .map_err(rsa_verify_err),
        oids::ID_SHA1 => Err(Error::Crypto(
            "SHA-1 signatures are not permitted for AdES verification".into(),
        )),
        other => Err(Error::Unsupported(format!(
            "unsupported RSA hash OID {other}"
        ))),
    }
}

fn rsa_verify_err(e: signature::Error) -> Error {
    Error::Crypto(format!("RSA signature verification failed: {e}"))
}

// ---- ECDSA ----

fn ecdsa_dispatch(
    cert: &Certificate,
    hash_oid: ObjectIdentifier,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != oids::ID_EC_PUBLIC_KEY {
        return Err(Error::Crypto(format!(
            "certificate SPKI does not carry id-ecPublicKey (got {})",
            spki.algorithm.oid
        )));
    }
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::Crypto("EC SPKI parameters are absent".into()))?;
    let param_der = params
        .to_der()
        .map_err(|e| Error::Asn1(format!("EC parameters encode: {e}")))?;
    let curve_oid = ObjectIdentifier::from_der(&param_der)
        .map_err(|e| Error::Asn1(format!("EC curve OID: {e}")))?;

    match curve_oid {
        oids::ID_SECP256R1 => ecdsa_p256_verify(cert, hash_oid, data, signature),
        oids::ID_SECP384R1 => ecdsa_p384_verify(cert, hash_oid, data, signature),
        oids::ID_SECP521R1 => Err(Error::Unsupported(
            "ECDSA P-521 not yet implemented (phase 2 covers P-256 / P-384)".into(),
        )),
        other => Err(Error::Unsupported(format!(
            "ECDSA curve OID {other} not supported"
        ))),
    }
}

fn ecdsa_p256_verify(
    cert: &Certificate,
    hash_oid: ObjectIdentifier,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk};
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
    use spki::SubjectPublicKeyInfoRef;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI encode: {e}")))?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| Error::Asn1(format!("SPKI parse: {e}")))?;
    let vk = P256Vk::try_from(spki_ref)
        .map_err(|e| Error::Crypto(format!("decoding P-256 public key: {e}")))?;
    let sig = P256Sig::from_der(signature)
        .map_err(|e| Error::Crypto(format!("parsing P-256 signature (DER): {e}")))?;

    let prehash = match hash_oid {
        oids::ID_SHA224 => Sha224::digest(data).to_vec(),
        oids::ID_SHA256 => Sha256::digest(data).to_vec(),
        oids::ID_SHA384 => Sha384::digest(data).to_vec(),
        oids::ID_SHA512 => Sha512::digest(data).to_vec(),
        oids::ID_SHA1 => {
            return Err(Error::Crypto(
                "SHA-1 not permitted for AdES verification".into(),
            ))
        }
        other => return Err(Error::Unsupported(format!("hash OID {other}"))),
    };
    PrehashVerifier::verify_prehash(&vk, &prehash, &sig)
        .map_err(|e| Error::Crypto(format!("ECDSA P-256 verification failed: {e}")))
}

fn ecdsa_p384_verify(
    cert: &Certificate,
    hash_oid: ObjectIdentifier,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Vk};
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
    use spki::SubjectPublicKeyInfoRef;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI encode: {e}")))?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| Error::Asn1(format!("SPKI parse: {e}")))?;
    let vk = P384Vk::try_from(spki_ref)
        .map_err(|e| Error::Crypto(format!("decoding P-384 public key: {e}")))?;
    let sig = P384Sig::from_der(signature)
        .map_err(|e| Error::Crypto(format!("parsing P-384 signature (DER): {e}")))?;

    let prehash = match hash_oid {
        oids::ID_SHA224 => Sha224::digest(data).to_vec(),
        oids::ID_SHA256 => Sha256::digest(data).to_vec(),
        oids::ID_SHA384 => Sha384::digest(data).to_vec(),
        oids::ID_SHA512 => Sha512::digest(data).to_vec(),
        oids::ID_SHA1 => {
            return Err(Error::Crypto(
                "SHA-1 not permitted for AdES verification".into(),
            ))
        }
        other => return Err(Error::Unsupported(format!("hash OID {other}"))),
    };
    PrehashVerifier::verify_prehash(&vk, &prehash, &sig)
        .map_err(|e| Error::Crypto(format!("ECDSA P-384 verification failed: {e}")))
}

// Keep the trait imports around for future extension (PSS verification
// routes through `signature::Verifier` in a similar shape).
#[doc(hidden)]
pub use signature::hazmat::PrehashVerifier as _ReExportPrehashVerifier;
#[doc(hidden)]
pub use signature::Verifier as _ReExportVerifier;
