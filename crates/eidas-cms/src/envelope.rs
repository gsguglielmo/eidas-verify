//! Shared helpers for parsing a CMS `ContentInfo` → `SignedData` and
//! extracting the embedded certificates + encap content.
//!
//! Exposed so higher-level layers (`eidas-cades` for LT/LTA, ASiC for
//! containers) can do their own per-signer logic without re-implementing
//! the envelope parsing.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::OctetString;
use der::{Decode, Encode};
use eidas_core::{Error, Result};
use x509_cert::Certificate;

use crate::oids;

/// Result of parsing a CMS envelope.
pub struct ParsedCms {
    /// Decoded SignedData.
    pub signed_data: SignedData,
    /// Certificates embedded in `SignedData.certificates`.
    pub embedded_certs: Vec<Certificate>,
    /// The bytes that were signed: either the embedded econtent (attached
    /// case) or the caller-supplied detached content.
    pub content_bytes: Vec<u8>,
}

/// Parse a CMS envelope and resolve the content bytes.
///
/// For attached signatures, `detached_content` is ignored. For detached
/// signatures, it is required.
pub fn parse_cms_envelope(cms_der: &[u8], detached_content: Option<&[u8]>) -> Result<ParsedCms> {
    let ci = ContentInfo::from_der(cms_der)
        .map_err(|e| Error::Asn1(format!("ContentInfo: {e}")))?;
    if ci.content_type != oids::ID_SIGNED_DATA {
        return Err(Error::Unsupported(format!(
            "outer ContentInfo is not SignedData (got {})",
            ci.content_type
        )));
    }
    let sd_bytes = ci
        .content
        .to_der()
        .map_err(|e| Error::Asn1(format!("re-encoding inner SignedData: {e}")))?;
    let sd = SignedData::from_der(&sd_bytes)
        .map_err(|e| Error::Asn1(format!("SignedData: {e}")))?;

    let content_bytes = resolve_content_bytes(&sd, detached_content)?;
    let embedded_certs = collect_embedded_certs(&sd);

    Ok(ParsedCms {
        signed_data: sd,
        embedded_certs,
        content_bytes,
    })
}

fn resolve_content_bytes(sd: &SignedData, detached: Option<&[u8]>) -> Result<Vec<u8>> {
    if let Some(any) = sd.encap_content_info.econtent.as_ref() {
        let any_der = any
            .to_der()
            .map_err(|e| Error::Asn1(format!("encap econtent: {e}")))?;
        let os = OctetString::from_der(&any_der)
            .map_err(|e| Error::Asn1(format!("econtent must be OCTET STRING: {e}")))?;
        return Ok(os.into_bytes());
    }
    detached
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Config("detached CAdES requires detached_content input".into()))
}

fn collect_embedded_certs(sd: &SignedData) -> Vec<Certificate> {
    let Some(set) = sd.certificates.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for choice in set.0.iter() {
        if let CertificateChoices::Certificate(c) = choice {
            out.push(c.clone());
        }
    }
    out
}
