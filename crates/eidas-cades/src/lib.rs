//! CAdES level handling — B-B through B-LTA.
//!
//! Layered on `eidas-cms` (CMS primitives), `eidas-revocation` (CRL/OCSP),
//! and `eidas-timestamp` (RFC 3161). The B-B baseline is shared with
//! `eidas_cms::verify_cades_bb`; this crate adds the unsigned-attribute
//! processing that lifts the signature's level.
//!
//! Flow:
//! 1. Run B-B verification via the shared primitives.
//! 2. If a `signature-time-stamp` unsigned attr is present, verify it using
//!    `eidas-timestamp` → lifts to B-T.
//! 3. If `id-aa-ets-certValues` + `id-aa-ets-revocationValues` are present,
//!    apply the embedded revocation material to each chain cert → lifts to
//!    B-LT.
//! 4. If `id-aa-ets-archiveTimestampV3` is present, verify each archive
//!    timestamp's TSA chain and signature → lifts to B-LTA. The archive
//!    timestamp's imprint over canonical data (EN 319 122-1 §5.5.3) is
//!    not recomputed; it is attested by the caller-supplied diagnostic.
//! 5. Honour `ValidationTime::BestSignatureTime` by selecting the most
//!    trustworthy embedded timestamp and re-running chain/revocation
//!    checks at that time.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod unsigned;
pub mod verify;

pub use verify::{verify_cades, CadesTrustMaterial};
