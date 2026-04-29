//! Look up qualification for a certificate against the trust lists.
//!
//! The full ETSI TS 119 615 algorithm considers:
//! - The chain's trust anchor matching a TSL-listed service's certificate.
//! - The service's status at the reference time (`granted`, `withdrawn`, ...).
//! - Qualifiers (e.g. `QcForESig`, `QCQSCDStatusAsInCert`) that refine
//!   AdES-QC → QES decisions.
//!
//! Phase 7 ships the lookup data (territory, status, qualifier URIs) and a
//! helper that walks the lists to find a service matching a given cert.
//! Phase 8 consumes this and produces the final `Qualification`.

use chrono::{DateTime, Utc};
use der::Encode;
use x509_cert::Certificate;

use crate::model::{TrustService, TrustedLists};

/// Service-type URI constants from ETSI TS 119 612.
pub mod service_type {
    pub const CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    pub const TSA_QTST: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
    pub const OCSP_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC";
    pub const CRL_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC";
}

/// Service-status URI constants.
pub mod status {
    pub const GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    pub const WITHDRAWN: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    pub const UNDER_SUPERVISION: &str =
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";
    pub const RECOGNISED: &str =
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";
}

/// Qualifier URI constants.
pub mod qualifier {
    pub const QC_FOR_ESIG: &str = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig";
    pub const QC_FOR_ESEAL: &str =
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal";
    pub const QC_WITH_QSCD: &str =
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD";
    pub const QC_QSCD_STATUS_AS_IN_CERT: &str =
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert";
    pub const QC_NO_QSCD: &str =
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD";
    pub const QC_STATEMENT: &str =
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement";
}

/// Outcome of a TL lookup for one certificate.
#[derive(Debug, Clone)]
pub struct ServiceMatch<'a> {
    pub territory: Option<String>,
    pub service: &'a TrustService,
    /// Status URI in force at the reference time.
    pub status_at: Option<String>,
}

/// Find the first trust-service in `tls` whose certificate equals `target` by
/// SubjectPublicKeyInfo byte-equality.
///
/// Matching is by SPKI rather than full cert DER so that TSP rekey/renewal
/// events (new cert, same key, same service entry) still match.
pub fn qualification_for<'a>(
    tls: &'a TrustedLists,
    target: &Certificate,
    at: DateTime<Utc>,
) -> Option<ServiceMatch<'a>> {
    let target_spki = target
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;

    for tl in &tls.lists {
        for tsp in &tl.providers {
            for svc in &tsp.services {
                // Check current certs first.
                let match_now = svc.certificates.iter().any(|c| {
                    c.tbs_certificate
                        .subject_public_key_info
                        .to_der()
                        .map(|d| d == target_spki)
                        .unwrap_or(false)
                });
                let match_history = svc.history.iter().any(|h| {
                    h.certificates.iter().any(|c| {
                        c.tbs_certificate
                            .subject_public_key_info
                            .to_der()
                            .map(|d| d == target_spki)
                            .unwrap_or(false)
                    })
                });
                if match_now || match_history {
                    let (st, _) = svc.status_at(at);
                    return Some(ServiceMatch {
                        territory: tl.territory.clone(),
                        service: svc,
                        status_at: st.map(str::to_string),
                    });
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_type_constants_are_canonical() {
        assert!(service_type::CA_QC.contains("CA/QC"));
        assert!(qualifier::QC_FOR_ESIG.ends_with("QCForESig"));
    }
}
