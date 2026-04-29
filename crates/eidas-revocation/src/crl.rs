//! CRL parsing + signature verification + lookup.

use chrono::{DateTime, Utc};
use der::{Decode, Encode};
use eidas_core::{Error, RevocationInfo, RevocationStatus, Result};
use eidas_x509::subject_display;
use x509_cert::crl::CertificateList;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;
use x509_cert::Certificate;

/// Outcome of a single CRL check for a particular certificate.
#[derive(Debug, Clone)]
pub struct CrlCheck {
    /// Fresh `RevocationInfo` suitable for embedding in a `SignatureReport`.
    pub info: RevocationInfo,
    /// True when the CRL's temporal window (`thisUpdate` ≤ at < `nextUpdate`)
    /// covers the reference time. An expired CRL yields a `Warning` diagnostic
    /// in the caller.
    pub fresh: bool,
}

/// Verify a CRL against its issuer and compute the status for `target_serial`.
///
/// The function performs:
/// 1. `tbsCertList.issuer` must equal `crl_issuer.subject`.
/// 2. `crl_issuer` must be CA-capable with `cRLSign` key usage.
/// 3. The CRL signature over `tbsCertList` must verify under the issuer key.
/// 4. The revoked list is scanned for `target_serial`.
pub fn verify_crl(
    crl_der: &[u8],
    crl_issuer: &Certificate,
    target_subject: &str,
    target_serial: &SerialNumber,
    at: DateTime<Utc>,
) -> Result<CrlCheck> {
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| Error::Asn1(format!("CRL: {e}")))?;

    if crl.tbs_cert_list.issuer != crl_issuer.tbs_certificate.subject {
        return Err(Error::Revocation(format!(
            "CRL issuer '{}' does not match supplied CA '{}'",
            crl.tbs_cert_list.issuer,
            subject_display(crl_issuer),
        )));
    }

    verify_crl_issuer_capability(crl_issuer)?;

    // Signature verification: tbsCertList bytes, signed by crl_issuer.
    let tbs_der = crl
        .tbs_cert_list
        .to_der()
        .map_err(|e| Error::Asn1(format!("CRL tbs encode: {e}")))?;
    let sig_bytes = crl
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Crypto("CRL signature BIT STRING has non-octet length".into()))?;

    eidas_cms::signature_verify::verify_cms_signature(
        crl_issuer,
        &crl.signature_algorithm,
        &crl.tbs_cert_list.signature,
        &tbs_der,
        sig_bytes,
    )
    .map_err(|e| match e {
        Error::Crypto(m) => Error::Revocation(format!("CRL signature invalid: {m}")),
        other => other,
    })?;

    // Temporal freshness.
    let this_update = time_to_utc(&crl.tbs_cert_list.this_update);
    let next_update = crl.tbs_cert_list.next_update.as_ref().map(time_to_utc);
    let fresh = at >= this_update && next_update.map_or(true, |nu| at < nu);

    // Scan revoked list.
    let status = match crl.tbs_cert_list.revoked_certificates.as_ref() {
        None => RevocationStatus::Good,
        Some(list) => list
            .iter()
            .find(|rc| &rc.serial_number == target_serial)
            .map(|rc| RevocationStatus::Revoked {
                at: time_to_utc(&rc.revocation_date),
                reason: None,
            })
            .unwrap_or(RevocationStatus::Good),
    };

    Ok(CrlCheck {
        info: RevocationInfo {
            subject: target_subject.to_string(),
            status,
            source: "CRL".into(),
            produced_at: Some(this_update),
            next_update,
        },
        fresh,
    })
}

fn verify_crl_issuer_capability(issuer: &Certificate) -> Result<()> {
    use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};

    let exts = issuer.tbs_certificate.extensions.as_ref();
    let mut saw_ca = false;
    let mut saw_crl_sign = false;
    if let Some(exts) = exts {
        for ext in exts {
            if ext.extn_id == ID_CE_BASIC_CONSTRAINTS {
                let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| Error::Asn1(format!("basicConstraints: {e}")))?;
                saw_ca = bc.ca;
            } else if ext.extn_id == ID_CE_KEY_USAGE {
                let ku = KeyUsage::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| Error::Asn1(format!("keyUsage: {e}")))?;
                saw_crl_sign = ku.0.into_iter().any(|u| u == KeyUsages::CRLSign);
            }
        }
    }
    if !saw_ca {
        return Err(Error::Revocation(format!(
            "CRL issuer '{}' is not a CA (basicConstraints.cA = false or absent)",
            subject_display(issuer)
        )));
    }
    if !saw_crl_sign {
        return Err(Error::Revocation(format!(
            "CRL issuer '{}' is missing cRLSign keyUsage",
            subject_display(issuer)
        )));
    }
    Ok(())
}

fn time_to_utc(t: &Time) -> DateTime<Utc> {
    t.to_system_time().into()
}

// Tests live in `tests/crl_tests.rs` — they require a real CA+CRL built by
// openssl, which can't be expressed cleanly as a unit test.
