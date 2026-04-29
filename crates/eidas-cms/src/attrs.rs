//! Helpers for navigating CMS `SignedAttributes` and re-encoding them.
//!
//! The re-encoding step (§6.1) is the subtle part: RFC 5652 specifies that
//! the *signed attributes* field in a `SignerInfo` is encoded with an
//! IMPLICIT `[0]` tag, **but** the value actually signed is those attributes
//! re-tagged as a plain `SET OF Attribute` (tag 0x31). That lets the verifier
//! reconstruct the bytes that the signer originally hashed.

use cms::signed_data::SignedAttributes;
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, SetOfVec};
use der::{Decode, Encode};
use eidas_core::{Error, Result};
use x509_cert::attr::{Attribute, AttributeValue};

use crate::oids;

/// Find the first attribute with the given OID.
pub fn find<'a>(attrs: &'a SignedAttributes, oid: ObjectIdentifier) -> Option<&'a Attribute> {
    attrs.iter().find(|a| a.oid == oid)
}

/// Find an attribute, require it to have exactly one value, and return that value.
pub fn single_value<'a>(
    attrs: &'a SignedAttributes,
    oid: ObjectIdentifier,
) -> Result<&'a AttributeValue> {
    let attr = find(attrs, oid)
        .ok_or_else(|| Error::Crypto(format!("missing required signed attribute {oid}")))?;
    let values: Vec<&AttributeValue> = attr.values.iter().collect();
    if values.len() != 1 {
        return Err(Error::Crypto(format!(
            "signed attribute {oid} expected 1 value, got {}",
            values.len()
        )));
    }
    Ok(values[0])
}

/// Decode the value of the `id-contentType` signed attribute.
pub fn content_type(attrs: &SignedAttributes) -> Result<ObjectIdentifier> {
    let v = single_value(attrs, oids::ID_CONTENT_TYPE)?;
    ObjectIdentifier::from_der(&v.to_der().map_err(|e| Error::Asn1(e.to_string()))?)
        .map_err(|e| Error::Asn1(format!("contentType attribute: {e}")))
}

/// Decode the value of the `id-messageDigest` signed attribute.
pub fn message_digest(attrs: &SignedAttributes) -> Result<Vec<u8>> {
    let v = single_value(attrs, oids::ID_MESSAGE_DIGEST)?;
    let der = v.to_der().map_err(|e| Error::Asn1(e.to_string()))?;
    let os = OctetString::from_der(&der).map_err(|e| Error::Asn1(format!("messageDigest: {e}")))?;
    Ok(os.into_bytes())
}

/// Decode the (optional) `signingTime` attribute as a `chrono::DateTime<Utc>`.
pub fn signing_time(attrs: &SignedAttributes) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let Some(attr) = find(attrs, oids::ID_SIGNING_TIME) else {
        return Ok(None);
    };
    let v: Vec<&AttributeValue> = attr.values.iter().collect();
    if v.len() != 1 {
        return Err(Error::Crypto("signingTime must have exactly one value".into()));
    }
    let der = v[0].to_der().map_err(|e| Error::Asn1(e.to_string()))?;

    // signingTime is a Time CHOICE { utcTime UTCTime, generalTime GeneralizedTime }.
    // We try both.
    if let Ok(t) = der::asn1::UtcTime::from_der(&der) {
        return Ok(Some(t.to_date_time().to_system_time().into()));
    }
    if let Ok(t) = der::asn1::GeneralizedTime::from_der(&der) {
        return Ok(Some(t.to_date_time().to_system_time().into()));
    }
    Err(Error::Asn1("signingTime: neither UTCTime nor GeneralizedTime".into()))
}

/// Re-encode `SignedAttributes` as a DER `SET OF Attribute` — the exact byte
/// sequence the signer originally hashed.
///
/// Quoting RFC 5652 §5.4: *"A separate encoding of the signedAttrs field is
/// performed for message digest calculation. The IMPLICIT \[0\] tag in the
/// signedAttrs is not used for the DER encoding, rather an EXPLICIT SET OF
/// tag is used."* Because `SignedAttributes` is a `SetOfVec<Attribute>` on
/// the wire, we can re-serialize it with its natural SET OF tag by calling
/// `to_der()` directly — `der`'s `SetOfVec` emits tag 0x31.
pub fn to_signed_der(attrs: &SignedAttributes) -> Result<Vec<u8>> {
    let set: &SetOfVec<Attribute> = attrs;
    set.to_der()
        .map_err(|e| Error::Asn1(format!("re-encoding signedAttrs: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::SetOfVec;

    fn make_attr(oid: ObjectIdentifier, value_der: &[u8]) -> Attribute {
        let any = der::Any::from_der(value_der).unwrap();
        let mut vs = SetOfVec::new();
        vs.insert(any).unwrap();
        Attribute { oid, values: vs }
    }

    #[test]
    fn find_locates_attribute() {
        let mut set: SetOfVec<Attribute> = SetOfVec::new();
        let oid_der = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
            .to_der()
            .unwrap();
        set.insert(make_attr(oids::ID_CONTENT_TYPE, &oid_der)).unwrap();

        assert!(find(&set, oids::ID_CONTENT_TYPE).is_some());
        assert!(find(&set, oids::ID_MESSAGE_DIGEST).is_none());
    }

    #[test]
    fn content_type_decodes_data_oid() {
        let mut set: SetOfVec<Attribute> = SetOfVec::new();
        let oid_der = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
            .to_der()
            .unwrap();
        set.insert(make_attr(oids::ID_CONTENT_TYPE, &oid_der)).unwrap();
        assert_eq!(content_type(&set).unwrap(), oids::ID_DATA);
    }

    #[test]
    fn message_digest_extracts_octets() {
        let mut set: SetOfVec<Attribute> = SetOfVec::new();
        let expected = vec![0xAA, 0xBB, 0xCC];
        let os_der = OctetString::new(expected.clone()).unwrap().to_der().unwrap();
        set.insert(make_attr(oids::ID_MESSAGE_DIGEST, &os_der)).unwrap();
        assert_eq!(message_digest(&set).unwrap(), expected);
    }

    #[test]
    fn to_signed_der_starts_with_set_tag() {
        let mut set: SetOfVec<Attribute> = SetOfVec::new();
        let oid_der = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
            .to_der()
            .unwrap();
        set.insert(make_attr(oids::ID_CONTENT_TYPE, &oid_der)).unwrap();
        let der = to_signed_der(&set).unwrap();
        // Tag 0x31 = universal class, constructed, SET OF.
        assert_eq!(der[0], 0x31, "first byte must be SET OF tag, got {:#x}", der[0]);
    }

    #[test]
    fn missing_attribute_is_error() {
        let set: SetOfVec<Attribute> = SetOfVec::new();
        assert!(matches!(
            content_type(&set),
            Err(Error::Crypto(_))
        ));
    }
}
