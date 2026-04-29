//! XAdES verification — narrow profile.
//!
//! **Scope note.** XAdES signatures use XMLDSig (W3C Rec.) with all its
//! attendant canonicalisation machinery. A fully compliant verifier
//! requires Canonical XML 1.0, Canonical XML 1.1, Exclusive XML
//! Canonicalization, arbitrary XPath transforms, and XSLT support — that's
//! multi-thousand LoC.
//!
//! This crate ships a deliberately *narrow* pure-Rust XAdES verifier that
//! handles the most common profile:
//!
//! - Enveloped signature (signature lives inside the signed document).
//! - `CanonicalizationMethod` = Exclusive C14N 1.0 (`http://www.w3.org/2001/10/xml-exc-c14n#`).
//! - Exactly one `<ds:Reference>` over the document root (URI="").
//! - Transforms limited to `enveloped-signature` + Exclusive C14N.
//! - Signature algorithms: RSA-SHA256 / RSA-SHA384 / RSA-SHA512,
//!   ECDSA-SHA256 / ECDSA-SHA384.
//! - `<ds:KeyInfo>` carries the signer cert via `<ds:X509Data><ds:X509Certificate>`.
//!
//! Anything outside this profile yields `Error::Unsupported` with an explicit
//! diagnostic listing what it saw vs. what it handles. Full XMLDSig support
//! — plus XAdES B-T / B-LT / B-LTA level lifting, detached / enveloping
//! signatures, and more transforms — lands in a follow-up hardening phase
//! along with libxml2 / xmlsec1 FFI bindings.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod c14n;
pub mod parse;
pub mod verify;

pub use verify::{verify_xades, XadesInput};
