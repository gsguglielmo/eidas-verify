//! Typed representation of a TrustedList.

use chrono::{DateTime, Utc};
use x509_cert::Certificate;

/// One or more TrustedLists aggregated together.
///
/// This is the top-level container the caller hands to the qualification
/// engine. In a real deployment, callers would pre-download LOTL + each MS
/// TL, parse them, and combine them here.
#[derive(Debug, Clone, Default)]
pub struct TrustedLists {
    pub lists: Vec<TrustedList>,
}

impl TrustedLists {
    /// Return every territory ISO-3166 code known to this bundle.
    pub fn territories(&self) -> Vec<String> {
        self.lists.iter().filter_map(|l| l.territory.clone()).collect()
    }
}

/// A single parsed ETSI TS 119 612 `TrustServiceStatusList`.
#[derive(Debug, Clone, Default)]
pub struct TrustedList {
    /// ISO-3166 territory code (from `SchemeInformation/SchemeTerritory`).
    pub territory: Option<String>,
    /// Scheme type URI (LOTL vs. MS TL).
    pub scheme_type: Option<String>,
    /// TSL sequence number.
    pub sequence_number: Option<u32>,
    /// `ListIssueDateTime`.
    pub list_issue_datetime: Option<DateTime<Utc>>,
    /// `NextUpdate/dateTime`, if present.
    pub next_update: Option<DateTime<Utc>>,
    /// Providers (one entry per `TrustServiceProvider` element).
    pub providers: Vec<TrustServiceProvider>,
    /// Original DER-encoded LOTL/TL XML, kept for re-verification paths.
    pub source_xml: Vec<u8>,
}

/// A trust-service provider (TSP).
#[derive(Debug, Clone, Default)]
pub struct TrustServiceProvider {
    pub name: Option<String>,
    pub trade_name: Option<String>,
    pub country: Option<String>,
    pub services: Vec<TrustService>,
}

/// A single trust service operated by a TSP.
#[derive(Debug, Clone, Default)]
pub struct TrustService {
    /// e.g. `http://uri.etsi.org/TrstSvc/Svctype/CA/QC`.
    pub service_type_identifier: Option<String>,
    pub service_name: Option<String>,
    /// e.g. `http://uri.etsi.org/TrstSvc/Svcstatus/granted`.
    pub current_status: Option<String>,
    pub status_starting_time: Option<DateTime<Utc>>,
    /// All certificates that identify this service. Derived from
    /// `ServiceDigitalIdentity/DigitalId/X509Certificate` (one or more).
    pub certificates: Vec<Certificate>,
    /// Historical status instances — each records the previous service state
    /// and the time-window during which it was in force.
    pub history: Vec<ServiceStatus>,
    /// Additional qualifiers applicable to this service (e.g. QcForESig,
    /// QSCDStatusAsInCert). Stored as URIs for Phase 8 to interpret.
    pub qualifiers: Vec<String>,
}

/// A single historical status entry.
#[derive(Debug, Clone, Default)]
pub struct ServiceStatus {
    pub service_type_identifier: Option<String>,
    pub status: Option<String>,
    pub starting_time: Option<DateTime<Utc>>,
    /// Certificates valid during this historical state.
    pub certificates: Vec<Certificate>,
    pub qualifiers: Vec<String>,
}

impl TrustService {
    /// Return the (status, starting_time) in force at reference time `at`.
    ///
    /// Falls back to `(current_status, status_starting_time)` if no
    /// history entry covers `at`.
    pub fn status_at(&self, at: DateTime<Utc>) -> (Option<&str>, Option<DateTime<Utc>>) {
        // Current status window: starting_time ≤ at → current is the answer.
        if let Some(start) = self.status_starting_time {
            if at >= start {
                return (
                    self.current_status.as_deref(),
                    Some(start),
                );
            }
        }
        // Otherwise walk history; pick the latest entry whose starting_time ≤ at.
        let mut best: Option<&ServiceStatus> = None;
        for h in &self.history {
            if let Some(hst) = h.starting_time {
                if at >= hst && best.map_or(true, |b| hst > b.starting_time.unwrap()) {
                    best = Some(h);
                }
            }
        }
        match best {
            Some(h) => (h.status.as_deref(), h.starting_time),
            None => (self.current_status.as_deref(), self.status_starting_time),
        }
    }
}
