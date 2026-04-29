//! Qualification decision engine.

use chrono::{DateTime, Utc};
use eidas_core::{DiagnosticMessage, Qualification, QualificationQualifier};
use eidas_trust::qualify::{qualification_for, qualifier as q_uri, status as s_uri, ServiceMatch};
use eidas_trust::TrustedLists;
use x509_cert::Certificate;

use crate::qcstatements::{parse_qc_statements, QcStatements};

/// What the caller passes in.
pub struct QualificationInput<'a> {
    /// Signer certificate.
    pub signer: &'a Certificate,
    /// Full chain: `[signer, …, anchor]`.
    pub chain: &'a [Certificate],
    /// Caller-supplied trust lists (LOTL + MS TLs).
    pub trusted_lists: &'a TrustedLists,
    /// Reference time for status lookup.
    pub at: DateTime<Utc>,
    /// Pre-TL qualification from the signature-level verifier (normally
    /// `Qualification::AdES` when B-B crypto passed).
    pub baseline: Qualification,
}

/// What the engine returns.
#[derive(Debug, Clone)]
pub struct QualificationOutput {
    pub qualification: Qualification,
    pub qualifiers: Vec<QualificationQualifier>,
    pub diagnostics: Vec<DiagnosticMessage>,
    /// Territory (ISO 3166 code) of the TSL that supplied the match, if any.
    pub territory: Option<String>,
    /// Parsed qcStatements flags, for reporting.
    pub qc_statements: QcStatements,
}

/// Compute the TS 119 615 qualification for a signer.
pub fn qualify_signer(input: &QualificationInput<'_>) -> QualificationOutput {
    let mut diagnostics = Vec::new();
    let qc = parse_qc_statements(input.signer).unwrap_or_default();

    // 1. Search upward through the chain for a cert whose SPKI appears in
    //    any trust-service entry. Typically it's the immediate issuer CA.
    let matched: Option<ServiceMatch<'_>> = input
        .chain
        .iter()
        .find_map(|c| qualification_for(input.trusted_lists, c, input.at));

    let Some(m) = matched else {
        diagnostics.push(DiagnosticMessage::info(
            "QUALIFY_NO_TSL_MATCH",
            "no certificate in the signer's chain is listed by any supplied TrustedList",
        ));
        return QualificationOutput {
            qualification: input.baseline,
            qualifiers: q_list_from_qc(&qc),
            diagnostics,
            territory: None,
            qc_statements: qc,
        };
    };

    let territory = m.territory.clone();

    // 2. Check the service status at `at`.
    let status_str = m.status_at.as_deref().unwrap_or("");
    let is_active = matches!(
        status_str,
        s if s == s_uri::GRANTED
            || s == s_uri::UNDER_SUPERVISION
            || s == s_uri::RECOGNISED
    );
    if !is_active {
        diagnostics.push(DiagnosticMessage::warn(
            "QUALIFY_SERVICE_NOT_ACTIVE",
            format!(
                "matching TSL service status at reference time is '{status_str}' — not granted/under-supervision"
            ),
        ));
        return QualificationOutput {
            qualification: Qualification::NotAdES,
            qualifiers: q_list_from_qc(&qc),
            diagnostics,
            territory,
            qc_statements: qc,
        };
    }

    // 3. Is the matching service a qualified-certificate issuer?
    let svc_type = m.service.service_type_identifier.as_deref().unwrap_or("");
    use eidas_trust::qualify::service_type as t_uri;
    if svc_type != t_uri::CA_QC {
        diagnostics.push(DiagnosticMessage::info(
            "QUALIFY_SERVICE_NOT_CA_QC",
            format!("matching service type '{svc_type}' is not CA/QC"),
        ));
        return QualificationOutput {
            qualification: input.baseline,
            qualifiers: q_list_from_qc(&qc),
            diagnostics,
            territory,
            qc_statements: qc,
        };
    }

    // 4. AdES-QC reached. Now evaluate QSCD to upgrade to QES.
    let qualifiers_uri: &[String] = &m.service.qualifiers;
    let has_qscd_qualifier =
        qualifiers_uri.iter().any(|q| q == q_uri::QC_WITH_QSCD);
    let has_status_as_in_cert =
        qualifiers_uri.iter().any(|q| q == q_uri::QC_QSCD_STATUS_AS_IN_CERT);
    let has_no_qscd_qualifier = qualifiers_uri.iter().any(|q| q == q_uri::QC_NO_QSCD);

    let mut qualifiers = q_list_from_service(qualifiers_uri);
    qualifiers.extend(q_list_from_qc(&qc));

    // QES conditions, in TS 119 615 priority order:
    // - TSL explicitly declares QC-WithQSCD, OR
    // - TSL says "status-as-in-cert" and cert asserts QcSSCD, OR
    // - TSL is silent on QSCD and cert asserts QcSSCD (§5.5.4 "trust cert").
    let qualification = if has_no_qscd_qualifier {
        Qualification::AdESqc
    } else if has_qscd_qualifier
        || (has_status_as_in_cert && qc.qc_sscd)
        || (!has_status_as_in_cert && qc.qc_sscd)
    {
        Qualification::QES
    } else {
        Qualification::AdESqc
    };

    diagnostics.push(DiagnosticMessage::info(
        "QUALIFY_MATCHED_CA_QC",
        format!(
            "chain terminates at a qualified CA in territory {}; status={status_str}",
            territory.as_deref().unwrap_or("?"),
        ),
    ));

    // Sanity: a cert without QcCompliance should not reach QES purely from
    // TSL data. Emit an informational diagnostic in that edge case.
    if !qc.qc_compliance && qualification == Qualification::QES {
        diagnostics.push(DiagnosticMessage::warn(
            "QUALIFY_QES_WITHOUT_QC_COMPLIANCE",
            "signer cert lacks QcCompliance statement but TSL qualifies it as QES — check certificate profile",
        ));
    }

    QualificationOutput {
        qualification,
        qualifiers: dedup(qualifiers),
        diagnostics,
        territory,
        qc_statements: qc,
    }
}

fn dedup(mut v: Vec<QualificationQualifier>) -> Vec<QualificationQualifier> {
    let mut seen = std::collections::HashSet::new();
    v.retain(|q| seen.insert(*q));
    v
}

fn q_list_from_qc(qc: &QcStatements) -> Vec<QualificationQualifier> {
    let mut out = Vec::new();
    if qc.qc_compliance {
        out.push(QualificationQualifier::QcStatement);
    }
    if qc.qc_type_esign {
        out.push(QualificationQualifier::QcForESig);
    }
    if qc.qc_type_eseal {
        out.push(QualificationQualifier::QcForESeal);
    }
    if qc.qc_type_web {
        out.push(QualificationQualifier::QcForWSA);
    }
    if qc.qc_sscd {
        out.push(QualificationQualifier::QcWithSSCD);
    }
    out
}

fn q_list_from_service(uris: &[String]) -> Vec<QualificationQualifier> {
    let mut out = Vec::new();
    for u in uris {
        match u.as_str() {
            q if q == q_uri::QC_FOR_ESIG => out.push(QualificationQualifier::QcForESig),
            q if q == q_uri::QC_FOR_ESEAL => out.push(QualificationQualifier::QcForESeal),
            q if q == q_uri::QC_WITH_QSCD => out.push(QualificationQualifier::QcWithQSCD),
            q if q == q_uri::QC_QSCD_STATUS_AS_IN_CERT => {
                out.push(QualificationQualifier::QcQSCDStatusAsInCert);
            }
            q if q == q_uri::QC_NO_QSCD => out.push(QualificationQualifier::QcNotQSCD),
            q if q == q_uri::QC_STATEMENT => out.push(QualificationQualifier::QcStatement),
            _ => {}
        }
    }
    out
}
