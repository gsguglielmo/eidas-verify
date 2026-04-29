//! Shared types for `eidas-verify`.
//!
//! This crate holds data types and traits that every format-specific crate
//! (`eidas-cms`, `eidas-pades`, `eidas-xades`, `eidas-jades`, `eidas-asic`)
//! depends on. It intentionally pulls in no signature / parser code — it is
//! the *lingua franca* of the workspace.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod algorithm;
pub mod error;
pub mod report;
pub mod time;

pub use algorithm::{AlgorithmId, AlgorithmPolicy, HashAlgorithm, SignatureAlgorithm};
pub use error::{Error, Result};
pub use report::{
    CertificateInfo, ContainerInfo, DiagnosticMessage, DiagnosticSeverity, Level, Qualification,
    QualificationQualifier, RevocationInfo, RevocationStatus, SignatureReport, Status,
    TimestampInfo, VerificationReport,
};
pub use time::ValidationTime;
