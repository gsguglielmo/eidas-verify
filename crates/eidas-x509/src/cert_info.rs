//! Small accessors that hide x509-cert type plumbing.

use chrono::{DateTime, Utc};
use const_oid::db::rfc5280::{ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_SUBJECT_KEY_IDENTIFIER};
use der::asn1::OctetString;
use der::{Decode, Encode};
use eidas_core::{Error, Result};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
use x509_cert::Certificate;

/// Extract the Subject Key Identifier (SKI) extension value.
pub fn ski(cert: &Certificate) -> Option<Vec<u8>> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts {
        if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER {
            if let Ok(parsed) = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                return Some(parsed.0.as_bytes().to_vec());
            }
        }
    }
    None
}

/// Extract the Authority Key Identifier (AKI) `keyIdentifier` value.
pub fn aki(cert: &Certificate) -> Option<Vec<u8>> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts {
        if ext.extn_id == ID_CE_AUTHORITY_KEY_IDENTIFIER {
            if let Ok(parsed) = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                if let Some(kid) = parsed.key_identifier {
                    return Some(kid.as_bytes().to_vec());
                }
            }
        }
    }
    None
}

/// Render the Subject DN in OpenSSL-ish `CN=…, O=…, C=…` form (ordering
/// follows the ASN.1 encoding).
pub fn subject_display(cert: &Certificate) -> String {
    cert.tbs_certificate.subject.to_string()
}

/// Render the Issuer DN.
pub fn issuer_display(cert: &Certificate) -> String {
    cert.tbs_certificate.issuer.to_string()
}

/// Return `(not_before, not_after)` as UTC datetimes.
pub fn validity_window(cert: &Certificate) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let nb = cert
        .tbs_certificate
        .validity
        .not_before
        .to_system_time();
    let na = cert
        .tbs_certificate
        .validity
        .not_after
        .to_system_time();
    let nb: DateTime<Utc> = nb.into();
    let na: DateTime<Utc> = na.into();
    if nb > na {
        return Err(Error::Chain(format!(
            "certificate validity inverted: not_before {nb} after not_after {na}"
        )));
    }
    Ok((nb, na))
}

/// Re-encode a certificate's SubjectPublicKeyInfo to DER.
pub fn spki_der(cert: &Certificate) -> Result<Vec<u8>> {
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("re-encoding SPKI: {e}")))
}

/// Extract an `OctetString` value from an extension body, for testing.
#[doc(hidden)]
pub fn debug_octets(o: &OctetString) -> Vec<u8> {
    o.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    // Real certificate tests live in chain.rs alongside fixture material.
    use super::*;

    #[test]
    fn module_is_usable() {
        // Placeholder — genuine coverage comes from chain.rs where we build
        // actual certificate fixtures.
        let _ = spki_der;
        let _ = aki;
        let _ = ski;
        let _ = validity_window;
        let _ = subject_display;
        let _ = issuer_display;
    }
}
