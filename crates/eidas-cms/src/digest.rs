//! Mapping digest-algorithm OIDs to concrete hashers and computing digests.

use const_oid::ObjectIdentifier;
use eidas_core::{Error, HashAlgorithm, Result};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::oids;

/// Resolve a digest-algorithm OID to the corresponding `HashAlgorithm` enum.
pub fn hash_from_oid(oid: ObjectIdentifier) -> Result<HashAlgorithm> {
    Ok(match oid {
        o if o == oids::ID_SHA1 => HashAlgorithm::Sha1,
        o if o == oids::ID_SHA224 => HashAlgorithm::Sha224,
        o if o == oids::ID_SHA256 => HashAlgorithm::Sha256,
        o if o == oids::ID_SHA384 => HashAlgorithm::Sha384,
        o if o == oids::ID_SHA512 => HashAlgorithm::Sha512,
        other => {
            return Err(Error::Unsupported(format!(
                "unknown digest-algorithm OID {other}"
            )))
        }
    })
}

/// Compute the digest of `data` using the given hash algorithm.
///
/// SHA-1 is allowed at the primitive layer (OCSP CertID still uses it per
/// RFC 6960) — the signature-level policy is the appropriate place to
/// reject SHA-1 *signatures*. MD5 and SHA-3 are unsupported.
pub fn digest(alg: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match alg {
        HashAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
        HashAlgorithm::Sha224 => Sha224::digest(data).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        HashAlgorithm::Md5 => {
            return Err(Error::Crypto(
                "MD5 is cryptographically broken and not supported".into(),
            ));
        }
        HashAlgorithm::Sha3_256 | HashAlgorithm::Sha3_384 | HashAlgorithm::Sha3_512 => {
            return Err(Error::Unsupported(format!(
                "SHA-3 family not yet implemented (alg={alg:?})"
            )));
        }
        _ => {
            return Err(Error::Unsupported(format!("hash algorithm {alg:?} not supported")));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_matches_known_vector() {
        // Well-known: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let d = digest(HashAlgorithm::Sha256, b"").unwrap();
        assert_eq!(
            hex::encode(&d),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_from_oid_maps_standard_oids() {
        assert_eq!(
            hash_from_oid(oids::ID_SHA256).unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            hash_from_oid(oids::ID_SHA384).unwrap(),
            HashAlgorithm::Sha384
        );
    }

    #[test]
    fn md5_refused_for_digest() {
        let err = digest(HashAlgorithm::Md5, b"anything").unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn sha1_is_permitted_at_primitive_layer() {
        // SHA-1 remains necessary for OCSP CertID (RFC 6960) and other
        // legacy protocol hashes. Policy enforcement happens at the
        // signature-algorithm level, not here.
        let d = digest(HashAlgorithm::Sha1, b"abc").unwrap();
        // Known: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        assert_eq!(hex::encode(&d), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn unknown_oid_is_error() {
        let oid = ObjectIdentifier::new_unwrap("1.2.3.4");
        let err = hash_from_oid(oid).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }
}
