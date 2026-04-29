//! Validation-time semantics per ETSI EN 319 102-1 §5.3.

use chrono::{DateTime, Utc};

/// Point in time at which a signature is evaluated.
///
/// Per EN 319 102-1, validation is always carried out "at a reference time".
/// The variants below correspond to the three evaluation modes the standard
/// enumerates (current time, historical time chosen by the caller, and the
/// "best signature time" derived from embedded timestamps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ValidationTime {
    /// Current wall-clock time sampled when the verifier starts.
    Now,

    /// Caller-supplied instant — lets the caller perform a historical check.
    At(DateTime<Utc>),

    /// Resolve the reference time from the signature itself: the latest
    /// trustworthy timestamp among signing-time attribute, content timestamp,
    /// signature timestamp and archive timestamps (cascade of EN 319 102-1
    /// §5.6.2.1 "POE initialisation" / §5.6.3 "selection of signing time").
    BestSignatureTime,
}

impl Default for ValidationTime {
    fn default() -> Self {
        Self::Now
    }
}

impl ValidationTime {
    /// Resolve to a concrete instant.
    ///
    /// For `BestSignatureTime`, callers must supply the already-computed best
    /// signature time (or `None` if no trustworthy timestamp is available, in
    /// which case the current clock is used).
    #[must_use]
    pub fn resolve(self, best_signature_time: Option<DateTime<Utc>>) -> DateTime<Utc> {
        match self {
            Self::Now => Utc::now(),
            Self::At(t) => t,
            Self::BestSignatureTime => best_signature_time.unwrap_or_else(Utc::now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn at_resolves_to_supplied_instant() {
        let t = Utc.with_ymd_and_hms(2023, 6, 1, 12, 0, 0).unwrap();
        assert_eq!(ValidationTime::At(t).resolve(None), t);
    }

    #[test]
    fn best_falls_back_to_now_when_unavailable() {
        let before = Utc::now();
        let resolved = ValidationTime::BestSignatureTime.resolve(None);
        let after = Utc::now();
        assert!(resolved >= before && resolved <= after);
    }

    #[test]
    fn best_uses_supplied_signature_time() {
        let t = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(ValidationTime::BestSignatureTime.resolve(Some(t)), t);
    }

    #[test]
    fn default_is_now() {
        assert_eq!(ValidationTime::default(), ValidationTime::Now);
    }
}
