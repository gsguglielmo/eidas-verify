//! OID constants specific to RFC 3161 timestamping.

use const_oid::ObjectIdentifier;

/// `id-ct-TSTInfo` — eContentType for RFC 3161 timestamp tokens.
pub const ID_CT_TSTINFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// `id-kp-timeStamping` — required EKU on the TSA signing certificate.
pub const ID_KP_TIME_STAMPING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// `id-aa-signatureTimeStampToken` — CAdES-T unsigned attribute (phase 5).
pub const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// `id-aa-ets-contentTimestamp` — CAdES content timestamp attribute.
pub const ID_AA_ETS_CONTENT_TIMESTAMP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.20");

/// `id-aa-ets-archiveTimestampV3` — CAdES-A archive timestamp.
pub const ID_AA_ETS_ARCHIVE_TIMESTAMP_V3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");
