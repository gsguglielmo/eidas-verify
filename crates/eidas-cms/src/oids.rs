//! OID constants used by CMS / CAdES.
//!
//! `const_oid::db::rfc5911` covers core CMS OIDs; CAdES-specific OIDs for
//! `signingCertificate` / `signingCertificateV2` are declared explicitly here
//! because their registration lives in ETSI documents, not the IETF DB.

use const_oid::ObjectIdentifier;

// ---- Content types ----
/// `id-data` — RFC 5652 §4.
pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// `id-signedData`.
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

// ---- PKCS#9 signed attributes ----
/// `id-contentType`.
pub const ID_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// `id-messageDigest`.
pub const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// `id-signingTime`.
pub const ID_SIGNING_TIME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

// ---- CAdES signed attributes (ETSI EN 319 122-1) ----
/// `id-aa-signingCertificate` (SHA-1 based — deprecated, still seen in the wild).
pub const ID_AA_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
/// `id-aa-signingCertificateV2` (mandatory for CAdES per ETSI TS 101 733 / EN 319 122-1).
pub const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

// ---- CAdES unsigned attributes (ETSI EN 319 122-1) ----
/// `id-aa-signatureTimeStampToken` — CAdES-T signature timestamp (B-T).
pub const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// `id-aa-ets-certValues` — long-term cert values (B-LT).
pub const ID_AA_ETS_CERT_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.23");
/// `id-aa-ets-revocationValues` — long-term revocation values (B-LT).
pub const ID_AA_ETS_REVOCATION_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");
/// `id-aa-ets-contentTimestamp` — pre-signing content timestamp (optional).
pub const ID_AA_ETS_CONTENT_TIMESTAMP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.20");
/// `id-aa-ets-archiveTimestampV3` — CAdES-A archive timestamp (B-LTA, ETSI OID).
pub const ID_AA_ETS_ARCHIVE_TIMESTAMP_V3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");

// ---- Digest algorithms (RFC 8017 / RFC 5754 / RFC 6931) ----
/// `id-sha1`.
pub const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
/// `id-sha224`.
pub const ID_SHA224: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.4");
/// `id-sha256`.
pub const ID_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// `id-sha384`.
pub const ID_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// `id-sha512`.
pub const ID_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// ---- Signature algorithms ----
/// `rsaEncryption` — generic RSA where the SignerInfo.digestAlgorithm carries the hash.
pub const ID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `sha1WithRSAEncryption`.
pub const ID_SHA1_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
/// `sha224WithRSAEncryption`.
pub const ID_SHA224_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");
/// `sha256WithRSAEncryption`.
pub const ID_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// `sha384WithRSAEncryption`.
pub const ID_SHA384_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
/// `sha512WithRSAEncryption`.
pub const ID_SHA512_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
/// `id-RSASSA-PSS`.
pub const ID_RSA_PSS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// `ecdsa-with-SHA1`.
pub const ID_ECDSA_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
/// `ecdsa-with-SHA224`.
pub const ID_ECDSA_SHA224: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.1");
/// `ecdsa-with-SHA256`.
pub const ID_ECDSA_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384`.
pub const ID_ECDSA_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// `ecdsa-with-SHA512`.
pub const ID_ECDSA_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

/// Named curves.
pub const ID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub const ID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub const ID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// EC public key.
pub const ID_EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
