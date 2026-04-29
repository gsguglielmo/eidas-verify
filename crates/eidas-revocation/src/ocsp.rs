//! OCSP response parsing + signature verification + status lookup.

use chrono::{DateTime, Utc};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use eidas_core::{Error, RevocationInfo, RevocationStatus, Result};
use eidas_x509::{ski, subject_display};
use sha1::{Digest, Sha1};
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId,
    SingleResponse,
};

/// `id-kp-OCSPSigning` EKU.
const ID_KP_OCSP_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

/// `id-pkix-ocsp-basic` — the only supported response type.
const ID_PKIX_OCSP_BASIC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// Outcome of an OCSP check for a particular certificate.
#[derive(Debug, Clone)]
pub struct OcspCheck {
    pub info: RevocationInfo,
    /// True when `thisUpdate` ≤ at < `nextUpdate` (where present).
    pub fresh: bool,
}

/// Verify an OCSP response and report the status of the target certificate.
///
/// Arguments:
/// - `response_der` — DER-encoded `OcspResponse`.
/// - `target` — the certificate whose status is being looked up.
/// - `issuer` — the CA that issued `target`. Used both to match the
///   `CertID` (hash of issuer name + key) and to validate the responder's
///   delegation when it is not `issuer` itself.
/// - `at` — reference time.
pub fn verify_ocsp(
    response_der: &[u8],
    target: &Certificate,
    issuer: &Certificate,
    at: DateTime<Utc>,
) -> Result<OcspCheck> {
    let outer = OcspResponse::from_der(response_der)
        .map_err(|e| Error::Asn1(format!("OcspResponse: {e}")))?;

    if outer.response_status != OcspResponseStatus::Successful {
        return Err(Error::Revocation(format!(
            "OCSP response status: {:?}",
            outer.response_status
        )));
    }
    let bytes = outer
        .response_bytes
        .ok_or_else(|| Error::Revocation("successful OCSP response has no responseBytes".into()))?;
    if bytes.response_type != ID_PKIX_OCSP_BASIC {
        return Err(Error::Unsupported(format!(
            "unsupported OCSP response type {}",
            bytes.response_type
        )));
    }
    let basic_der = bytes.response.as_bytes();
    let basic = BasicOcspResponse::from_der(basic_der)
        .map_err(|e| Error::Asn1(format!("BasicOcspResponse: {e}")))?;

    // Locate the responder certificate.
    let responder_owned = locate_responder(&basic, issuer)?;
    let responder_cert: &Certificate = match &responder_owned {
        ResponderPick::Embedded(c) => c,
        ResponderPick::Issuer => issuer,
    };

    // Verify the responder's delegation — either the issuer itself, or a cert
    // issued by the issuer with id-kp-OCSPSigning EKU.
    verify_responder_delegation(responder_cert, issuer)?;

    // Verify the responder signature over tbsResponseData.
    let tbs_der = basic
        .tbs_response_data
        .to_der()
        .map_err(|e| Error::Asn1(format!("OCSP tbs encode: {e}")))?;
    let sig_bytes = basic
        .signature
        .as_bytes()
        .ok_or_else(|| {
            Error::Crypto("OCSP signature BIT STRING has non-octet length".into())
        })?;
    // OCSP responses omit a separate digest-algorithm field — the signature
    // algorithm already identifies the hash. Passing the same alg as both
    // `sig_alg` and `digest_hint` is fine because the "hint" is only consulted
    // when `sig_alg` is generic (rsaEncryption), and the hash OID is looked
    // up from it the same way either place.
    eidas_cms::signature_verify::verify_cms_signature(
        responder_cert,
        &basic.signature_algorithm,
        &basic.signature_algorithm,
        &tbs_der,
        sig_bytes,
    )
    .map_err(|e| match e {
        Error::Crypto(m) => Error::Revocation(format!("OCSP signature invalid: {m}")),
        other => other,
    })?;

    // Find the SingleResponse that matches our target cert's CertID.
    let target_serial = target.tbs_certificate.serial_number.clone();
    let matched = match_single_response(&basic, issuer, &target_serial)?;

    // Temporal validity.
    let this_update = ocsp_time_to_utc(&matched.this_update)?;
    let next_update = matched
        .next_update
        .as_ref()
        .map(ocsp_time_to_utc)
        .transpose()?;
    let fresh = at >= this_update && next_update.map_or(true, |nu| at < nu);

    let status = match &matched.cert_status {
        CertStatus::Good(_) => RevocationStatus::Good,
        CertStatus::Revoked(info) => RevocationStatus::Revoked {
            at: ocsp_time_to_utc(&info.revocation_time)?,
            reason: None,
        },
        CertStatus::Unknown(_) => RevocationStatus::Unknown,
    };

    Ok(OcspCheck {
        info: RevocationInfo {
            subject: subject_display(target),
            status,
            source: "OCSP".into(),
            produced_at: Some(this_update),
            next_update,
        },
        fresh,
    })
}

/// Which certificate was chosen to verify the OCSP response.
enum ResponderPick {
    /// An entry from `basic.certs`, referenced by index.
    Embedded(Certificate),
    /// The supplied issuer cert (the "direct" responder case).
    Issuer,
}

/// Locate the certificate used to sign `basic`:
/// - If `basic.certs` contains a cert matching the ResponderID, use it.
/// - Otherwise, fall back to `issuer` (the "direct" signer case where the
///   CA itself answers OCSP queries).
fn locate_responder(
    basic: &BasicOcspResponse,
    issuer: &Certificate,
) -> Result<ResponderPick> {
    match &basic.tbs_response_data.responder_id {
        ResponderId::ByName(name) => {
            if let Some(certs) = &basic.certs {
                if let Some(c) = certs.iter().find(|c| c.tbs_certificate.subject == *name) {
                    return Ok(ResponderPick::Embedded(c.clone()));
                }
            }
            if issuer.tbs_certificate.subject == *name {
                return Ok(ResponderPick::Issuer);
            }
            Err(Error::Revocation(format!(
                "OCSP responder (byName '{name}') not found among response certs or supplied issuer"
            )))
        }
        ResponderId::ByKey(key_hash) => {
            let want = key_hash.as_bytes();
            if let Some(certs) = &basic.certs {
                if let Some(c) = certs.iter().find(|c| sha1_of_spk(c) == want) {
                    return Ok(ResponderPick::Embedded(c.clone()));
                }
            }
            if sha1_of_spk(issuer) == want {
                return Ok(ResponderPick::Issuer);
            }
            Err(Error::Revocation(
                "OCSP responder (byKey) not found among response certs or supplied issuer"
                    .into(),
            ))
        }
    }
}

/// SHA-1 hash of the responder's subject public key BIT STRING (octets only,
/// excluding the leading zero "unused bits" byte). Used by ResponderID::ByKey.
fn sha1_of_spk(cert: &Certificate) -> Vec<u8> {
    let spk = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let mut h = Sha1::new();
    h.update(spk);
    h.finalize().to_vec()
}

/// Ensure `responder` is authorised to sign OCSP responses for `issuer`.
fn verify_responder_delegation(responder: &Certificate, issuer: &Certificate) -> Result<()> {
    // Fast path: responder IS the issuer.
    if responder.tbs_certificate.subject == issuer.tbs_certificate.subject {
        let r_spki = responder
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap_or_default();
        let i_spki = issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap_or_default();
        if r_spki == i_spki {
            return Ok(());
        }
    }

    // Delegated responder: must be issued by `issuer` and carry OCSPSigning EKU.
    if responder.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(Error::Revocation(format!(
            "OCSP responder '{}' was not issued by '{}'",
            subject_display(responder),
            subject_display(issuer),
        )));
    }
    use const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let exts = responder.tbs_certificate.extensions.as_ref().ok_or_else(|| {
        Error::Revocation("OCSP responder cert has no extensions".into())
    })?;
    let mut has_ocsp_signing = false;
    for ext in exts {
        if ext.extn_id == ID_CE_EXT_KEY_USAGE {
            let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                .map_err(|e| Error::Asn1(format!("extKeyUsage: {e}")))?;
            has_ocsp_signing = eku.0.into_iter().any(|o| o == ID_KP_OCSP_SIGNING);
        }
    }
    if !has_ocsp_signing {
        return Err(Error::Revocation(format!(
            "OCSP responder '{}' lacks id-kp-OCSPSigning EKU",
            subject_display(responder)
        )));
    }
    // id-pkix-ocsp-nocheck handling is deferred to Phase 5 / LT verification
    // where we have a trustworthy notion of "at".
    let _ = ski; // keep import live for future refactors
    Ok(())
}

/// Find the `SingleResponse` whose `CertID` matches (issuer, serial).
fn match_single_response<'a>(
    basic: &'a BasicOcspResponse,
    issuer: &Certificate,
    target_serial: &SerialNumber,
) -> Result<&'a SingleResponse> {
    for sr in &basic.tbs_response_data.responses {
        if &sr.cert_id.serial_number != target_serial {
            continue;
        }
        if !cert_id_matches_issuer(sr, issuer)? {
            continue;
        }
        return Ok(sr);
    }
    Err(Error::Revocation(
        "OCSP response does not cover the requested (issuer, serial) pair".into(),
    ))
}

fn ocsp_time_to_utc(t: &x509_ocsp::OcspGeneralizedTime) -> Result<DateTime<Utc>> {
    let st = t.0.to_date_time().to_system_time();
    Ok(st.into())
}

fn cert_id_matches_issuer(sr: &SingleResponse, issuer: &Certificate) -> Result<bool> {
    use eidas_cms::digest::{digest, hash_from_oid};
    let hash_alg = match hash_from_oid(sr.cert_id.hash_algorithm.oid) {
        Ok(a) => a,
        Err(_) => {
            // Unknown digest alg: cannot compare, treat as no-match.
            return Ok(false);
        }
    };
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| Error::Asn1(format!("issuer name: {e}")))?;
    let issuer_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let want_name = digest(hash_alg, &issuer_name_der)?;
    let want_key = digest(hash_alg, issuer_key)?;

    Ok(sr.cert_id.issuer_name_hash.as_bytes() == want_name
        && sr.cert_id.issuer_key_hash.as_bytes() == want_key)
}

// Tests live in `tests/` with openssl-generated OCSP responses.
