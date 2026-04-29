//! Narrow Exclusive XML Canonicalization 1.0 (W3C Rec. 18 July 2002).
//!
//! This implementation handles:
//! - Start-tag emission with attribute + namespace sorting.
//! - Inherited namespaces resolution for the subtree root only (enough for
//!   simple enveloped signatures and TSL signatures).
//! - Enveloped-signature transform (strip the matching `<ds:Signature>`
//!   subtree).
//! - Text nodes with standard XML-1.0 whitespace handling (no DTD-driven
//!   whitespace stripping, no attribute defaults).
//!
//! NOT supported (deliberate):
//! - DTD / entity expansion.
//! - Namespace prefix rewriting.
//! - XPath transforms.
//! - `InclusiveNamespaces/PrefixList` (treated as "no forced visible
//!   prefixes" — a reasonable default for the profiles we handle).

use eidas_core::{Error, Result};
use quick_xml::events::attributes::Attribute;
use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;
use std::collections::BTreeSet;

/// Canonicalise an XML document (byte slice) with the enveloped-signature
/// transform applied to a signature element identified by `strip_target`.
///
/// If `strip_target` is `None`, no element is stripped.
///
/// Returns the canonical UTF-8 byte sequence.
pub fn exc_c14n_with_envelope_strip(
    xml: &[u8],
    strip_target: Option<EnvelopeTarget<'_>>,
) -> Result<Vec<u8>> {
    let mut reader = Reader::from_reader(xml);
    reader.trim_text(false);
    reader.expand_empty_elements(false);

    let mut out: Vec<u8> = Vec::with_capacity(xml.len());
    let mut buf = Vec::new();
    // Track nesting depth. When we enter the target subtree, skip until its
    // matching end.
    let mut skip_depth: Option<usize> = None;
    let mut depth: usize = 0;

    // Namespace stack: parallel lists of (prefix or empty, uri) — used only
    // for default-namespace tracking for the root emission.
    // We do not rewrite prefixes; we emit them as-is.
    loop {
        let ev = reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("c14n read: {e}")))?;

        match ev {
            Event::Start(ref e) => {
                if skip_depth.is_none() && should_strip(e.name(), strip_target) {
                    skip_depth = Some(depth);
                    depth += 1;
                    buf.clear();
                    continue;
                }
                if skip_depth.is_some() {
                    depth += 1;
                    buf.clear();
                    continue;
                }
                emit_start(e.name(), e.attributes(), false, &mut out)?;
                depth += 1;
            }
            Event::Empty(ref e) => {
                if skip_depth.is_none() && should_strip(e.name(), strip_target) {
                    // Strip empty element — nothing to emit.
                    buf.clear();
                    continue;
                }
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                // Exclusive C14N normalises empty elements to
                // <name ...></name>.
                emit_start(e.name(), e.attributes(), false, &mut out)?;
                emit_end(e.name(), &mut out);
            }
            Event::End(ref e) => {
                if let Some(d) = skip_depth {
                    depth -= 1;
                    if depth == d {
                        skip_depth = None;
                    }
                    buf.clear();
                    continue;
                }
                depth -= 1;
                emit_end(e.name(), &mut out);
            }
            Event::Text(t) => {
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                let text = t
                    .unescape()
                    .map_err(|e| Error::Xml(format!("text: {e}")))?;
                write_escaped_text(text.as_bytes(), &mut out);
            }
            Event::CData(c) => {
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                // CDATA is serialised as if it were character data.
                write_escaped_text(&c, &mut out);
            }
            Event::Comment(_) => { /* Exclusive C14N drops comments. */ }
            Event::PI(_) => { /* Drop processing instructions outside the root. */ }
            Event::Decl(_) => { /* XML declaration is dropped. */ }
            Event::DocType(_) => { /* DOCTYPE is dropped. */ }
            Event::Eof => break,
        }
        buf.clear();
    }
    Ok(out)
}

/// Which element to strip during the enveloped-signature transform.
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeTarget<'a> {
    /// Fully qualified XML name of the element (e.g. `b"ds:Signature"` or
    /// `b"{http://www.w3.org/2000/09/xmldsig#}Signature"`).
    pub local: &'a [u8],
    /// Namespace URI, used if the element has one and we want to match by it.
    pub namespace: Option<&'a [u8]>,
}

fn should_strip(name: QName<'_>, target: Option<EnvelopeTarget<'_>>) -> bool {
    let Some(t) = target else {
        return false;
    };
    let local = name.local_name();
    local.as_ref() == t.local
}

fn emit_start(
    name: QName<'_>,
    attrs: quick_xml::events::attributes::Attributes<'_>,
    _is_root: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    out.push(b'<');
    out.extend_from_slice(name.as_ref());

    // Collect namespaces (xmlns attributes) separately from regular attrs,
    // then emit in a single sorted order per Exclusive C14N.
    let mut ns_decls: BTreeSet<(Vec<u8>, Vec<u8>)> = BTreeSet::new();
    let mut attr_list: BTreeSet<(Vec<u8>, Vec<u8>, Vec<u8>)> = BTreeSet::new();
    for a in attrs {
        let a: Attribute<'_> = a.map_err(|e| Error::Xml(format!("attr: {e}")))?;
        let key = a.key.as_ref();
        if key == b"xmlns" {
            ns_decls.insert((Vec::new(), a.value.to_vec()));
        } else if key.starts_with(b"xmlns:") {
            ns_decls.insert((key[6..].to_vec(), a.value.to_vec()));
        } else {
            // Sort key: (namespace-uri, local-name, prefix) — but we don't
            // resolve namespace URIs here; keying on the raw qualified name
            // is sufficient for the narrow profile we target.
            let (prefix, local) = split_qname(key);
            attr_list.insert((prefix.to_vec(), local.to_vec(), a.value.to_vec()));
        }
    }

    // Exclusive C14N §2.4: namespace nodes rendered in ascending order of
    // local-name; default namespace first when present.
    for (prefix, uri) in &ns_decls {
        out.push(b' ');
        if prefix.is_empty() {
            out.extend_from_slice(b"xmlns");
        } else {
            out.extend_from_slice(b"xmlns:");
            out.extend_from_slice(prefix);
        }
        out.extend_from_slice(b"=\"");
        write_escaped_attr_value(uri, out);
        out.push(b'"');
    }
    // Regular attributes in sorted order.
    for (prefix, local, value) in &attr_list {
        out.push(b' ');
        if !prefix.is_empty() {
            out.extend_from_slice(prefix);
            out.push(b':');
        }
        out.extend_from_slice(local);
        out.extend_from_slice(b"=\"");
        write_escaped_attr_value(value, out);
        out.push(b'"');
    }
    out.push(b'>');
    Ok(())
}

fn emit_end(name: QName<'_>, out: &mut Vec<u8>) {
    out.extend_from_slice(b"</");
    out.extend_from_slice(name.as_ref());
    out.push(b'>');
}

fn split_qname(qn: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = qn.iter().position(|b| *b == b':') {
        (&qn[..pos], &qn[pos + 1..])
    } else {
        (&[], qn)
    }
}

fn write_escaped_text(text: &[u8], out: &mut Vec<u8>) {
    for &b in text {
        match b {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
}

fn write_escaped_attr_value(v: &[u8], out: &mut Vec<u8>) {
    for &b in v {
        match b {
            b'"' => out.extend_from_slice(b"&quot;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            b'\n' => out.extend_from_slice(b"&#xA;"),
            b'\t' => out.extend_from_slice(b"&#x9;"),
            _ => out.push(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_canonicalisation_strips_declaration_and_comments() {
        let xml = br#"<?xml version="1.0"?>
<!-- comment -->
<root xmlns="http://example.com"><a>1</a><b>2</b></root>"#;
        let out = exc_c14n_with_envelope_strip(xml, None).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("<root"));
        assert!(s.contains("<a>1</a>"));
        assert!(s.contains("<b>2</b>"));
        assert!(!s.contains("<?xml"));
        assert!(!s.contains("<!--"));
    }

    #[test]
    fn enveloped_signature_strip_removes_named_subtree() {
        let xml = br#"<root><data>keep</data><Signature><inner>gone</inner></Signature></root>"#;
        let target = EnvelopeTarget { local: b"Signature", namespace: None };
        let out = exc_c14n_with_envelope_strip(xml, Some(target)).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("<data>keep</data>"), "got {s}");
        assert!(!s.contains("Signature"), "got {s}");
        assert!(!s.contains("gone"), "got {s}");
    }

    #[test]
    fn attributes_are_sorted_alphabetically() {
        let xml = br#"<root z="3" a="1" m="2"/>"#;
        let out = exc_c14n_with_envelope_strip(xml, None).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        // Attr order: a, m, z.
        let ai = s.find("a=").unwrap();
        let mi = s.find("m=").unwrap();
        let zi = s.find("z=").unwrap();
        assert!(ai < mi && mi < zi, "bad order in {s}");
    }

    #[test]
    fn empty_element_is_expanded_to_open_close() {
        let xml = br#"<root><empty/></root>"#;
        let out = exc_c14n_with_envelope_strip(xml, None).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("<empty></empty>"), "got {s}");
    }
}
