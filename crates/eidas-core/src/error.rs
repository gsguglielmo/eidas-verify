//! Crate-wide error type.
//!
//! `Error` is a flat enum: format crates add their own variants via
//! `#[from]` converters so callers can match on specific failure modes.

use thiserror::Error;

/// Convenience alias used throughout the workspace.
pub type Result<T> = core::result::Result<T, Error>;

/// Top-level error returned by every public API in the workspace.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Structural parsing of ASN.1 / DER failed.
    #[error("ASN.1/DER parse error: {0}")]
    Asn1(String),

    /// XML parsing failed.
    #[error("XML parse error: {0}")]
    Xml(String),

    /// JSON parsing failed.
    #[error("JSON parse error: {0}")]
    Json(String),

    /// PDF parsing failed.
    #[error("PDF parse error: {0}")]
    Pdf(String),

    /// ZIP / ASiC parsing failed.
    #[error("ZIP container error: {0}")]
    Zip(String),

    /// Certificate chain could not be built or did not validate.
    #[error("certificate chain: {0}")]
    Chain(String),

    /// Cryptographic verification failed (bad signature, bad hash, etc.).
    #[error("cryptographic check failed: {0}")]
    Crypto(String),

    /// Revocation check reached an indeterminate state or found a revoked cert.
    #[error("revocation: {0}")]
    Revocation(String),

    /// Timestamp token failed to validate.
    #[error("timestamp: {0}")]
    Timestamp(String),

    /// Trust list could not be parsed or verified.
    #[error("trust list: {0}")]
    TrustList(String),

    /// Input did not meet the required algorithm policy.
    #[error("algorithm policy: {0}")]
    Policy(String),

    /// Caller-supplied configuration is invalid (missing anchors, etc.).
    #[error("configuration: {0}")]
    Config(String),

    /// Input was in an unsupported or unrecognised format.
    #[error("unsupported input: {0}")]
    Unsupported(String),

    /// Catch-all for unexpected states that should not normally occur.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Attach a short human-readable context prefix.
    #[must_use]
    pub fn context(self, ctx: &str) -> Self {
        match self {
            Self::Asn1(m) => Self::Asn1(format!("{ctx}: {m}")),
            Self::Xml(m) => Self::Xml(format!("{ctx}: {m}")),
            Self::Json(m) => Self::Json(format!("{ctx}: {m}")),
            Self::Pdf(m) => Self::Pdf(format!("{ctx}: {m}")),
            Self::Zip(m) => Self::Zip(format!("{ctx}: {m}")),
            Self::Chain(m) => Self::Chain(format!("{ctx}: {m}")),
            Self::Crypto(m) => Self::Crypto(format!("{ctx}: {m}")),
            Self::Revocation(m) => Self::Revocation(format!("{ctx}: {m}")),
            Self::Timestamp(m) => Self::Timestamp(format!("{ctx}: {m}")),
            Self::TrustList(m) => Self::TrustList(format!("{ctx}: {m}")),
            Self::Policy(m) => Self::Policy(format!("{ctx}: {m}")),
            Self::Config(m) => Self::Config(format!("{ctx}: {m}")),
            Self::Unsupported(m) => Self::Unsupported(format!("{ctx}: {m}")),
            Self::Internal(m) => Self::Internal(format!("{ctx}: {m}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_preserves_variant() {
        let e = Error::Chain("missing anchor".into()).context("phase 2");
        assert!(matches!(e, Error::Chain(_)));
        assert_eq!(e.to_string(), "certificate chain: phase 2: missing anchor");
    }
}
