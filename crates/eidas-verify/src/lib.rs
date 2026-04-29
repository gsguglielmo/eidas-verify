//! Pure-Rust verifier for EU electronic signatures.
//!
//! **Phase 1** exposes only the foundational types and builder: full signature
//! verification (CAdES, PAdES, XAdES, JAdES, ASiC) lands in phases 2–11.
//!
//! ## Scope
//! - Verifies AdES signatures at levels B-B / B-T / B-LT / B-LTA.
//! - Accepts caller-supplied trust anchors and (later) TrustedList XML.
//! - Never performs network I/O. Revocation is offline-only.
//!
//! ## Out of scope
//! - Signature creation.
//! - Trust list downloading.
//!
//! See the plan at `plans/serialized-roaming-tiger.md` for the full roadmap.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub use eidas_core::{
    AlgorithmId, AlgorithmPolicy, CertificateInfo, ContainerInfo, DiagnosticMessage,
    DiagnosticSeverity, Error, HashAlgorithm, Level, Qualification, QualificationQualifier,
    Result, RevocationInfo, RevocationStatus, SignatureAlgorithm, SignatureReport, Status,
    TimestampInfo, ValidationTime, VerificationReport,
};
#[cfg(feature = "asic")]
pub use eidas_asic as asic;
#[cfg(feature = "cades")]
pub use eidas_cades as cades;
#[cfg(feature = "jades")]
pub use eidas_jades as jades;
#[cfg(feature = "xades")]
pub use eidas_xades as xades;
#[cfg(feature = "pades")]
pub use eidas_pades as pades;
#[cfg(feature = "trust-list")]
pub use eidas_trust as trust;
#[cfg(feature = "ts-119-615")]
pub use eidas_qualify as qualify;
pub use eidas_policy as policy;
pub use eidas_revocation as revocation;
pub use eidas_timestamp as timestamp;
pub use eidas_x509::{ChainBuilder, ChainValidationResult, TrustAnchor};

pub mod verifier;
pub use verifier::{ContainerHint, DetachedFormat, VerificationInput, Verifier, VerifierBuilder};
