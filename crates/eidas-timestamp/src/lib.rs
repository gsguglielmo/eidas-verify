//! RFC 3161 TimeStampToken parsing and verification.
//!
//! A TimeStampToken is a CMS SignedData wrapping a `TSTInfo` structure.
//! Verification entails:
//!
//! 1. Parse `ContentInfo` → `SignedData`; `encapContentInfo.eContentType`
//!    must be `id-ct-TSTInfo`.
//! 2. Parse `TSTInfo` from the eContent.
//! 3. Compare the `MessageImprint` to a caller-supplied hash of the signed
//!    data (typically the signer-info signature bytes, for a
//!    `signature-time-stamp` attribute).
//! 4. Verify the TSA's CMS signature using the standard CAdES verification
//!    machinery.
//! 5. Build + validate the TSA's X.509 chain to a caller-supplied trust
//!    anchor set. The TSA leaf cert must carry the `id-kp-timeStamping`
//!    extended key usage (RFC 3161 §2.3).

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod oids;
pub mod tst;

pub use tst::{verify_time_stamp_token, TimestampKind, TstVerification};
