//! CAdES / CMS SignedData verification.
//!
//! Phase 2 implements CAdES **B-B**: a CMS SignedData whose signer-info carries
//! the mandatory signed attributes (`contentType`, `messageDigest`,
//! `signingCertificateV2`) and whose signature verifies against the signer's
//! public key, with the signer certificate chaining to a trust anchor.
//!
//! Higher levels (B-T, B-LT, B-LTA) are added in phases 4 and 5.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod attrs;
pub mod cades;
pub mod digest;
pub mod envelope;
pub mod oids;
pub mod signature_verify;

pub use cades::{verify_cades_bb, CadesInput};
pub use envelope::{parse_cms_envelope, ParsedCms};
