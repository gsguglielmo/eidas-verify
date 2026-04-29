//! Extract XAdES signature components from XML using quick-xml.

use base64::{engine::general_purpose::STANDARD, Engine};
use der::Decode;
use eidas_core::{Error, Result};
use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;
use x509_cert::Certificate;

/// What we pull out of an XAdES/XMLDSig document.
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub canonicalization_method: String,
    pub signature_method: String,
    /// Reference digest method (first Reference only).
    pub reference_digest_method: String,
    /// Reference digest value (base64-decoded).
    pub reference_digest_value: Vec<u8>,
    /// URI of the first Reference (empty means "root").
    pub reference_uri: String,
    /// Transform URIs applied to the reference (in order).
    pub reference_transforms: Vec<String>,
    /// SignatureValue bytes (base64-decoded).
    pub signature_value: Vec<u8>,
    /// Signer certificate from `KeyInfo/X509Data/X509Certificate`.
    pub signer_cert: Option<Certificate>,
}

/// Parse an XML document and extract the first `ds:Signature`.
pub fn parse_xml_signature(xml: &[u8]) -> Result<ParsedSignature> {
    let mut reader = Reader::from_reader(xml);
    reader.trim_text(true);

    let mut sig = Sig::default();
    let mut buf = Vec::new();
    let mut inside_signature = false;
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("xades parse: {e}")))?
        {
            Event::Start(ref e) if local(e.name()) == "Signature" => {
                inside_signature = true;
                parse_signature_block(&mut reader, &mut sig)?;
                break;
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if !inside_signature {
        return Err(Error::Xml("no <Signature> element found".into()));
    }
    sig.finalize()
}

fn local(n: QName<'_>) -> String {
    std::str::from_utf8(n.local_name().as_ref()).unwrap_or("").to_string()
}

#[derive(Default)]
struct Sig {
    canonicalization_method: Option<String>,
    signature_method: Option<String>,
    reference_digest_method: Option<String>,
    reference_digest_value: Option<Vec<u8>>,
    reference_uri: Option<String>,
    reference_transforms: Vec<String>,
    signature_value: Option<Vec<u8>>,
    signer_cert: Option<Certificate>,
}

impl Sig {
    fn finalize(self) -> Result<ParsedSignature> {
        Ok(ParsedSignature {
            canonicalization_method: self
                .canonicalization_method
                .ok_or_else(|| Error::Xml("missing CanonicalizationMethod".into()))?,
            signature_method: self
                .signature_method
                .ok_or_else(|| Error::Xml("missing SignatureMethod".into()))?,
            reference_digest_method: self
                .reference_digest_method
                .ok_or_else(|| Error::Xml("missing DigestMethod".into()))?,
            reference_digest_value: self
                .reference_digest_value
                .ok_or_else(|| Error::Xml("missing DigestValue".into()))?,
            reference_uri: self.reference_uri.unwrap_or_default(),
            reference_transforms: self.reference_transforms,
            signature_value: self
                .signature_value
                .ok_or_else(|| Error::Xml("missing SignatureValue".into()))?,
            signer_cert: self.signer_cert,
        })
    }
}

fn parse_signature_block(reader: &mut Reader<&[u8]>, sig: &mut Sig) -> Result<()> {
    let mut buf = Vec::new();
    let mut captured_reference = false;
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("signature block: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "Signature" => break,
            Event::Start(ref e) => {
                let n = local(e.name());
                match n.as_str() {
                    "SignedInfo" => parse_signed_info(reader, sig, &mut captured_reference)?,
                    "SignatureValue" => {
                        let s = read_text(reader, "SignatureValue")?;
                        sig.signature_value = Some(decode_b64(&s)?);
                    }
                    "KeyInfo" => parse_key_info(reader, sig)?,
                    // XAdES-specific blocks (Object/QualifyingProperties/…)
                    // are walked through but not parsed in this narrow crate.
                    _ => skip_subtree(reader, &n)?,
                }
            }
            Event::Empty(_) => {}
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_signed_info(
    reader: &mut Reader<&[u8]>,
    sig: &mut Sig,
    captured_reference: &mut bool,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        let ev = reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("SignedInfo: {e}")))?;
        let (is_empty, e) = match ev {
            Event::End(ref e) if local(e.name()) == "SignedInfo" => break,
            Event::Start(ref e) => (false, e.clone()),
            Event::Empty(ref e) => (true, e.clone()),
            Event::Eof => break,
            _ => {
                buf.clear();
                continue;
            }
        };
        let n = local(e.name());
        match n.as_str() {
            "CanonicalizationMethod" => {
                sig.canonicalization_method = Some(attr_value(&e, b"Algorithm"));
                if !is_empty {
                    skip_subtree(reader, &n)?;
                }
            }
            "SignatureMethod" => {
                sig.signature_method = Some(attr_value(&e, b"Algorithm"));
                if !is_empty {
                    skip_subtree(reader, &n)?;
                }
            }
            "Reference" if !*captured_reference => {
                sig.reference_uri = Some(attr_value(&e, b"URI"));
                if !is_empty {
                    parse_reference(reader, sig)?;
                }
                *captured_reference = true;
            }
            _ => {
                if !is_empty {
                    skip_subtree(reader, &n)?;
                }
            }
        }
        buf.clear();
    }
    Ok(())
}

fn parse_reference(reader: &mut Reader<&[u8]>, sig: &mut Sig) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        let ev = reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("Reference: {e}")))?;
        let (is_empty, e) = match ev {
            Event::End(ref e) if local(e.name()) == "Reference" => break,
            Event::Start(ref e) => (false, e.clone()),
            Event::Empty(ref e) => (true, e.clone()),
            Event::Eof => break,
            _ => {
                buf.clear();
                continue;
            }
        };
        let n = local(e.name());
        match n.as_str() {
            "Transforms" => {
                if !is_empty {
                    parse_transforms(reader, sig)?;
                }
            }
            "DigestMethod" => {
                sig.reference_digest_method = Some(attr_value(&e, b"Algorithm"));
                if !is_empty {
                    skip_subtree(reader, &n)?;
                }
            }
            "DigestValue" => {
                if is_empty {
                    sig.reference_digest_value = Some(Vec::new());
                } else {
                    let s = read_text(reader, "DigestValue")?;
                    sig.reference_digest_value = Some(decode_b64(&s)?);
                }
            }
            _ => {
                if !is_empty {
                    skip_subtree(reader, &n)?;
                }
            }
        }
        buf.clear();
    }
    Ok(())
}

fn parse_transforms(reader: &mut Reader<&[u8]>, sig: &mut Sig) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        let ev = reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("Transforms: {e}")))?;
        let (is_empty, e) = match ev {
            Event::End(ref e) if local(e.name()) == "Transforms" => break,
            Event::Start(ref e) => (false, e.clone()),
            Event::Empty(ref e) => (true, e.clone()),
            Event::Eof => break,
            _ => {
                buf.clear();
                continue;
            }
        };
        if local(e.name()) == "Transform" {
            sig.reference_transforms.push(attr_value(&e, b"Algorithm"));
            if !is_empty {
                skip_subtree(reader, "Transform")?;
            }
        } else if !is_empty {
            skip_subtree(reader, &local(e.name()))?;
        }
        buf.clear();
    }
    Ok(())
}

fn parse_key_info(reader: &mut Reader<&[u8]>, sig: &mut Sig) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("KeyInfo: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "KeyInfo" => break,
            Event::Start(ref e) if local(e.name()) == "X509Data" => {
                parse_x509_data(reader, sig)?;
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_x509_data(reader: &mut Reader<&[u8]>, sig: &mut Sig) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("X509Data: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "X509Data" => break,
            Event::Start(ref e) if local(e.name()) == "X509Certificate" => {
                let s = read_text(reader, "X509Certificate")?;
                let der = decode_b64(&s)?;
                sig.signer_cert = Some(
                    Certificate::from_der(&der)
                        .map_err(|e| Error::Asn1(format!("X509Certificate DER: {e}")))?,
                );
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn skip_subtree(reader: &mut Reader<&[u8]>, closing: &str) -> Result<()> {
    let mut depth = 1usize;
    let mut buf = Vec::new();
    while depth > 0 {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("skip: {e}")))?
        {
            Event::Start(_) => depth += 1,
            Event::End(ref e) => {
                let n = local(e.name());
                if n == closing && depth == 1 {
                    return Ok(());
                }
                depth -= 1;
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn read_text(reader: &mut Reader<&[u8]>, closing: &str) -> Result<String> {
    let mut buf = Vec::new();
    let mut out = String::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("read text: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == closing => break,
            Event::Text(t) => out.push_str(&t.unescape().unwrap_or_default()),
            Event::CData(c) => out.push_str(std::str::from_utf8(&c).unwrap_or("")),
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn attr_value(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> String {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == key {
            return std::str::from_utf8(a.value.as_ref())
                .unwrap_or("")
                .to_string();
        }
    }
    String::new()
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| Error::Xml(format!("base64: {e}")))
}
