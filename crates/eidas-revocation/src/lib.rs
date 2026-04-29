//! Offline revocation checking — CRL + OCSP.
//!
//! Phase 3 scope:
//! - Parse CRLs (`x509_cert::crl::CertificateList`) and OCSP responses
//!   (`x509_ocsp::OcspResponse`) from DER bytes.
//! - Verify the CRL / OCSP-responder signature against a supplied issuer
//!   (or embedded responder) certificate, using the same crypto primitives
//!   as CAdES signature verification.
//! - For CRLs: check `thisUpdate` / `nextUpdate` validity windows, walk the
//!   revoked-certificate list, and return a [`RevocationStatus`] for a
//!   requested serial number.
//! - For OCSP: match `CertID` to a supplied (issuer, serial) pair, verify
//!   the responder's delegation (direct TL-issued responder OR
//!   `id-kp-OCSPSigning` EKU + same-issuer as the target cert), and return
//!   the cert's status.
//!
//! Out of scope for this phase:
//! - Network I/O (caller supplies bytes).
//! - Indirect CRLs (IndirectCRL flag in IDP) — flagged as unsupported.
//! - Delta CRLs.
//! - OCSP `id-pkix-ocsp-nocheck` checks (added alongside Phase 4 / 5 when
//!   timestamps let us reason about validity windows).

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod crl;
pub mod ocsp;

pub use crl::{verify_crl, CrlCheck};
pub use ocsp::{verify_ocsp, OcspCheck};
