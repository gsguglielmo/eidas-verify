//! ETSI TS 119 612 TrustedList parsing.
//!
//! Phase 7 scope:
//! - Parse a TrustedList XML (LOTL or MS TL) into typed Rust structs:
//!   scheme information, trust-service providers, services with status
//!   history and qualifiers.
//! - Extract per-service certificates (X.509 DER decoded via `x509-cert`).
//! - Offer `TrustedLists::qualification_for(cert, at)` that returns the
//!   AdES / AdES-QC / QES status per ETSI TS 119 615 based on service type
//!   + status + qualifiers at a given reference time.
//!
//! **NOT in scope for phase 7:** verifying the TSL's own enveloped XMLDSig
//! signature. A correct Exclusive C14N + XMLDSig verifier requires a full
//! XML DOM and many hundreds of LoC of canonicalisation code; that lands
//! in phase 11 alongside the libxml2-backed XAdES verifier and can reuse
//! its machinery. Until then, the parser accepts the TSL bytes as-is and
//! emits a prominent diagnostic:
//!
//!   `TRUSTLIST_SIGNATURE_NOT_VERIFIED` — caller is responsible for out-of-band
//!   validation (e.g. fetching the TSL over a trusted channel, or running the
//!   phase-11 XMLDSig verifier when it ships).

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod model;
pub mod parse;
pub mod qualify;

pub use model::{
    ServiceStatus, TrustService, TrustServiceProvider, TrustedList, TrustedLists,
};
pub use parse::parse_trusted_list;
pub use qualify::qualification_for;
