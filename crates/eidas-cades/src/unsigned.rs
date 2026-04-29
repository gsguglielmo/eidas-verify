//! Parse CAdES unsigned attributes into structured forms.
//!
//! The unsigned attributes relevant to phases 2-5 are:
//! - `id-aa-signatureTimeStampToken` — contains one or more TSTs over the
//!   `SignerInfo.signature` octets.
//! - `id-aa-ets-certValues` — SEQUENCE OF Certificate (long-term cert store).
//! - `id-aa-ets-revocationValues` — SEQUENCE with optional CRLs and OCSP
//!   responses (long-term revocation store).
//! - `id-aa-ets-archiveTimestampV3` — TST over canonical CAdES data for
//!   archival purposes (B-LTA). We parse the token but flag imprint
//!   verification as out of scope.

use cms::signed_data::{SignedAttributes, SignerInfo};
use der::asn1::OctetString;
use der::{Decode, Encode, Reader, SliceReader, Tag};
use eidas_core::{Error, Result};
use eidas_cms::oids;
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;

/// Unsigned attributes bundle extracted from a `SignerInfo`.
#[derive(Default, Debug, Clone)]
pub struct UnsignedAttrs {
    /// Raw DER of each `TimeStampToken` under `signature-time-stamp`.
    pub signature_time_stamps: Vec<Vec<u8>>,
    /// Raw DER of each archive-timestamp-v3 token.
    pub archive_time_stamps_v3: Vec<Vec<u8>>,
    /// Certificates discovered via `id-aa-ets-certValues`.
    pub ets_cert_values: Vec<Certificate>,
    /// CRLs discovered via `id-aa-ets-revocationValues.crlVals`.
    pub ets_crls: Vec<Vec<u8>>,
    /// OCSP BasicOcspResponse DER blobs from `revocationValues.ocspVals`.
    pub ets_ocsps: Vec<Vec<u8>>,
    /// True if `id-aa-ets-revocationValues` was seen (even if empty).
    pub saw_revocation_values: bool,
    /// True if `id-aa-ets-certValues` was seen.
    pub saw_cert_values: bool,
}

/// Extract unsigned attributes from the signer.
pub fn extract(signer: &SignerInfo) -> Result<UnsignedAttrs> {
    let mut out = UnsignedAttrs::default();

    let Some(attrs) = signer.unsigned_attrs.as_ref() else {
        return Ok(out);
    };

    for attr in attrs.iter() {
        if attr.oid == oids::ID_AA_SIGNATURE_TIME_STAMP_TOKEN {
            for v in attr.values.iter() {
                let v_der = v.to_der().map_err(|e| Error::Asn1(e.to_string()))?;
                // Each value is already an encoded ContentInfo (TimeStampToken).
                out.signature_time_stamps.push(v_der);
            }
        } else if attr.oid == oids::ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 {
            for v in attr.values.iter() {
                let v_der = v.to_der().map_err(|e| Error::Asn1(e.to_string()))?;
                out.archive_time_stamps_v3.push(v_der);
            }
        } else if attr.oid == oids::ID_AA_ETS_CERT_VALUES {
            out.saw_cert_values = true;
            for v in attr.values.iter() {
                let v_der = v.to_der().map_err(|e| Error::Asn1(e.to_string()))?;
                let certs = parse_certificate_values(&v_der)?;
                out.ets_cert_values.extend(certs);
            }
        } else if attr.oid == oids::ID_AA_ETS_REVOCATION_VALUES {
            out.saw_revocation_values = true;
            for v in attr.values.iter() {
                let v_der = v.to_der().map_err(|e| Error::Asn1(e.to_string()))?;
                let (crls, ocsps) = parse_revocation_values(&v_der)?;
                out.ets_crls.extend(crls);
                out.ets_ocsps.extend(ocsps);
            }
        }
    }
    Ok(out)
}

/// `CertificateValues ::= SEQUENCE OF Certificate`
fn parse_certificate_values(der: &[u8]) -> Result<Vec<Certificate>> {
    let mut r = SliceReader::new(der).map_err(|e| Error::Asn1(e.to_string()))?;
    let header = der::Header::decode(&mut r).map_err(|e| Error::Asn1(e.to_string()))?;
    if header.tag != Tag::Sequence {
        return Err(Error::Asn1(
            "id-aa-ets-certValues is not SEQUENCE OF Certificate".into(),
        ));
    }
    let body = r
        .read_slice(header.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut b = SliceReader::new(body).map_err(|e| Error::Asn1(e.to_string()))?;
    let mut out = Vec::new();
    while !b.is_finished() {
        let cert = Certificate::decode(&mut b)
            .map_err(|e| Error::Asn1(format!("certValues entry: {e}")))?;
        out.push(cert);
    }
    Ok(out)
}

/// `RevocationValues ::= SEQUENCE {
///     crlVals     [0] SEQUENCE OF CertificateList OPTIONAL,
///     ocspVals    [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
///     otherRevVals [2] OtherRevVals OPTIONAL
/// }`
fn parse_revocation_values(der: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let mut r = SliceReader::new(der).map_err(|e| Error::Asn1(e.to_string()))?;
    let outer = der::Header::decode(&mut r).map_err(|e| Error::Asn1(e.to_string()))?;
    if outer.tag != Tag::Sequence {
        return Err(Error::Asn1(
            "id-aa-ets-revocationValues is not a SEQUENCE".into(),
        ));
    }
    let body = r
        .read_slice(outer.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut b = SliceReader::new(body).map_err(|e| Error::Asn1(e.to_string()))?;

    let mut crls = Vec::new();
    let mut ocsps = Vec::new();

    while !b.is_finished() {
        let hdr = der::Header::decode(&mut b).map_err(|e| Error::Asn1(e.to_string()))?;
        let inner_bytes = b
            .read_slice(hdr.length)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        match hdr.tag {
            Tag::ContextSpecific { constructed: true, number } if u8::from(number) == 0 => {
                // crlVals: SEQUENCE OF CertificateList (concatenated).
                let mut s = SliceReader::new(inner_bytes).map_err(|e| Error::Asn1(e.to_string()))?;
                while !s.is_finished() {
                    let crl_hdr = der::Header::decode(&mut s).map_err(|e| Error::Asn1(e.to_string()))?;
                    let crl_body = s
                        .read_slice(crl_hdr.length)
                        .map_err(|e| Error::Asn1(e.to_string()))?;
                    let full = reencode(crl_hdr, crl_body)?;
                    // Validate it parses as a CertificateList before keeping it.
                    let _ = CertificateList::from_der(&full)
                        .map_err(|e| Error::Asn1(format!("revocationValues CRL: {e}")))?;
                    crls.push(full);
                }
            }
            Tag::ContextSpecific { constructed: true, number } if u8::from(number) == 1 => {
                // ocspVals: SEQUENCE OF BasicOCSPResponse
                let mut s = SliceReader::new(inner_bytes).map_err(|e| Error::Asn1(e.to_string()))?;
                while !s.is_finished() {
                    let resp_hdr = der::Header::decode(&mut s).map_err(|e| Error::Asn1(e.to_string()))?;
                    let resp_body = s
                        .read_slice(resp_hdr.length)
                        .map_err(|e| Error::Asn1(e.to_string()))?;
                    let full = reencode(resp_hdr, resp_body)?;
                    ocsps.push(full);
                }
            }
            // Skip unknown optionals (otherRevVals [2] and future extensions).
            _ => {}
        }
    }
    Ok((crls, ocsps))
}

/// Re-encode a DER header + body into a standalone byte vector — used when
/// we want to hand a sub-element to another parser that expects a full
/// encoded TLV.
fn reencode(hdr: der::Header, body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    hdr.encode(&mut out)
        .map_err(|e| Error::Asn1(format!("re-encode header: {e}")))?;
    out.extend_from_slice(body);
    Ok(out)
}

// Convenience re-exports for callers.
pub use eidas_cms::attrs::find as find_attribute;
pub use eidas_cms::attrs::signing_time;
pub use eidas_cms::attrs::to_signed_der;

// Used only for doc; keep Attribute type name available.
#[allow(dead_code)]
fn _doc_ref(_a: &SignedAttributes) {}

// Required: OctetString import stays so a future refactor using it compiles;
// remove if the lint becomes noisy.
#[allow(dead_code)]
fn _unused_keep_imports() {
    let _ = OctetString::new(Vec::<u8>::new());
}
