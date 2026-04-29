//! `VerificationReport` and its constituent types.
//!
//! The vocabulary follows ETSI EN 319 102-1:
//! - `Status` — overall verdict (`TotalPassed`, `IndeterminateSub`, `TotalFailedSub`).
//! - `Level` — highest AdES level the signature actually reached.
//! - `Qualification` — ETSI TS 119 615 qualification (AdES / AdES-QC / QES).

use chrono::{DateTime, Utc};
use std::fmt;

use crate::AlgorithmId;

/// Top-level verdict. Mirrors the "Main Status" of EN 319 102-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Status {
    /// All checks passed at the requested level.
    TotalPassed,
    /// Some checks could not be completed (missing revocation data,
    /// expired TSA, …) but nothing is known to be invalid.
    IndeterminateSub,
    /// At least one mandatory check explicitly failed.
    TotalFailedSub,
}

/// Highest AdES conformance level reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Level {
    /// No recognisable AdES level could be assigned.
    Unknown,
    /// B-B — basic signature with signed attributes.
    BB,
    /// B-T — basic + signature timestamp.
    BT,
    /// B-LT — long-term: embedded validation data.
    BLT,
    /// B-LTA — long-term with archive timestamp(s).
    BLTA,
}

/// Qualification per ETSI TS 119 615.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Qualification {
    /// Not advanced — fails one or more AdES requirements.
    NotAdES,
    /// Advanced Electronic Signature.
    AdES,
    /// Advanced + issued under a qualified certificate.
    AdESqc,
    /// Qualified Electronic Signature.
    QES,
}

/// Additional qualifiers attached to `Qualification` (ETSI TS 119 615 §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum QualificationQualifier {
    QcForESig,
    QcForESeal,
    QcForWSA,
    QcQSCDManagedOnBehalf,
    QcQSCDStatusAsInCert,
    QcQSCDByTL,
    QcNotQSCD,
    QcWithSSCD,
    QcWithQSCD,
    QcStatement,
    NotQualified,
    Legal,
    Natural,
}

/// Severity of a diagnostic message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Structured diagnostic.
///
/// `code` is stable and machine-readable (e.g. `CHAIN_EXPIRED`,
/// `REVOCATION_REVOKED`); `message` is human-readable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiagnosticMessage {
    pub severity: DiagnosticSeverity,
    pub code: &'static str,
    pub message: String,
}

impl DiagnosticMessage {
    #[must_use]
    pub fn info(code: &'static str, msg: impl Into<String>) -> Self {
        Self { severity: DiagnosticSeverity::Info, code, message: msg.into() }
    }

    #[must_use]
    pub fn warn(code: &'static str, msg: impl Into<String>) -> Self {
        Self { severity: DiagnosticSeverity::Warning, code, message: msg.into() }
    }

    #[must_use]
    pub fn error(code: &'static str, msg: impl Into<String>) -> Self {
        Self { severity: DiagnosticSeverity::Error, code, message: msg.into() }
    }
}

impl fmt::Display for DiagnosticMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            DiagnosticSeverity::Info => "INFO",
            DiagnosticSeverity::Warning => "WARN",
            DiagnosticSeverity::Error => "ERROR",
        };
        write!(f, "[{sev}] {}: {}", self.code, self.message)
    }
}

/// A flattened view of an X.509 certificate used in the report.
///
/// We keep the raw DER around so callers can re-parse if they need fields we
/// did not surface here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// Subject Key Identifier, if present.
    pub ski: Option<Vec<u8>>,
    /// Authority Key Identifier, if present.
    pub aki: Option<Vec<u8>>,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes_opt"))]
    pub der: Vec<u8>,
}

#[cfg(feature = "serde")]
mod serde_bytes_opt {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use serde::de::{Deserialize, Error};
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(Error::custom)
    }
}

/// Revocation status recorded for a certificate in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RevocationStatus {
    /// No revocation material was available.
    Unknown,
    /// Covered by CRL or OCSP and currently valid.
    Good,
    /// Revoked at the given time.
    Revoked { at: DateTime<Utc>, reason: Option<String> },
}

/// Revocation evidence attached to one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RevocationInfo {
    /// Subject of the certificate this info is about.
    pub subject: String,
    pub status: RevocationStatus,
    /// Source: "CRL", "OCSP", "embedded-LT", etc.
    pub source: String,
    /// `this_update` / `produced_at` of the evidence.
    pub produced_at: Option<DateTime<Utc>>,
    /// `next_update` of the evidence, if any.
    pub next_update: Option<DateTime<Utc>>,
}

/// RFC 3161 timestamp captured in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimestampInfo {
    /// Role of the timestamp ("signature", "archive-v3", "content", …).
    pub kind: String,
    pub genesis_time: DateTime<Utc>,
    pub tsa_subject: Option<String>,
    pub imprint_algorithm: Option<AlgorithmId>,
    /// Whether the TSA cert chain validated and the imprint matched.
    pub valid: bool,
}

/// Container-level info (ASiC manifest, PDF revisions, …).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ContainerInfo {
    Pdf { revisions: usize },
    Asic { mime_type: String, entries: Vec<String> },
    Jws { encoding: String },
}

/// Report for a single signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignatureReport {
    pub status: Status,
    pub level_reached: Level,
    pub qualification: Qualification,
    pub qualifiers: Vec<QualificationQualifier>,
    pub signer: Option<CertificateInfo>,
    pub chain: Vec<CertificateInfo>,
    /// `signing-time` attribute as claimed by the signer (unverified).
    pub signing_time_claimed: Option<DateTime<Utc>>,
    /// Trustworthy signing time derived from embedded timestamps.
    pub signing_time_best: Option<DateTime<Utc>>,
    pub algorithm: Option<AlgorithmId>,
    pub timestamps: Vec<TimestampInfo>,
    pub revocation: Vec<RevocationInfo>,
    pub diagnostics: Vec<DiagnosticMessage>,
}

impl SignatureReport {
    /// Report a fresh-failure with no checks passed.
    #[must_use]
    pub fn failed(code: &'static str, msg: impl Into<String>) -> Self {
        Self {
            status: Status::TotalFailedSub,
            level_reached: Level::Unknown,
            qualification: Qualification::NotAdES,
            qualifiers: Vec::new(),
            signer: None,
            chain: Vec::new(),
            signing_time_claimed: None,
            signing_time_best: None,
            algorithm: None,
            timestamps: Vec::new(),
            revocation: Vec::new(),
            diagnostics: vec![DiagnosticMessage::error(code, msg)],
        }
    }
}

/// Top-level report returned by `Verifier::verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationReport {
    pub signatures: Vec<SignatureReport>,
    pub container: Option<ContainerInfo>,
}

impl VerificationReport {
    /// True if every signature reached `TotalPassed`.
    #[must_use]
    pub fn is_total_passed(&self) -> bool {
        !self.signatures.is_empty()
            && self.signatures.iter().all(|s| s.status == Status::TotalPassed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering_matches_spec() {
        assert!(Level::Unknown < Level::BB);
        assert!(Level::BB < Level::BT);
        assert!(Level::BT < Level::BLT);
        assert!(Level::BLT < Level::BLTA);
    }

    #[test]
    fn diagnostic_display() {
        let d = DiagnosticMessage::warn("X", "oops");
        assert_eq!(d.to_string(), "[WARN] X: oops");
    }

    #[test]
    fn total_passed_requires_signatures() {
        let r = VerificationReport { signatures: Vec::new(), container: None };
        assert!(!r.is_total_passed());
    }

    #[test]
    fn failed_report_is_self_consistent() {
        let r = SignatureReport::failed("FOO", "bar");
        assert_eq!(r.status, Status::TotalFailedSub);
        assert_eq!(r.level_reached, Level::Unknown);
        assert_eq!(r.diagnostics.len(), 1);
        assert_eq!(r.diagnostics[0].severity, DiagnosticSeverity::Error);
    }
}
