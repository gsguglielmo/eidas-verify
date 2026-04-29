//! Certificate chain building and validation.
//!
//! The path-building algorithm is a deliberately small subset of RFC 5280:
//!
//! 1. Start from `signer_cert`.
//! 2. Walk upward by matching AKI→SKI first, then Issuer→Subject DN.
//! 3. Stop when we reach a certificate whose Subject matches a caller-supplied
//!    trust anchor (by DN + public-key equality).
//! 4. Validate every link: validity window, basicConstraints, keyUsage /
//!    extendedKeyUsage, and (if AKI is present) AKI→SKI consistency.
//!
//! Explicit non-goals (deferred to phase 8+):
//! - Policy constraints / policy mapping
//! - Name constraints
//! - CRL distribution points & AIA fetching (revocation lives in `eidas-revocation`)
//! - Cross-certificates and path discovery (we assume a linear chain)

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod chain;
pub mod cert_info;

pub use chain::{ChainBuilder, ChainValidationResult, TrustAnchor};
pub use cert_info::{aki, issuer_display, ski, subject_display, validity_window};
