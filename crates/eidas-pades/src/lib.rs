//! PAdES (PDF Advanced Electronic Signatures) verification.
//!
//! PAdES signatures are embedded in PDFs as a signature dictionary with:
//! - `/ByteRange [a b c d]` — two byte ranges of the PDF to hash over,
//!   skipping the `<hex>` placeholder in `/Contents`.
//! - `/Contents <hex>` — a hex-encoded DER CMS SignedData (detached) over
//!   the concatenation `pdf[a..a+b] ++ pdf[c..c+d]`.
//! - `/SubFilter` — one of `/adbe.pkcs7.detached` (legacy) or
//!   `/ETSI.CAdES.detached` (PAdES-B per ETSI EN 319 142-1).
//!
//! This crate:
//! 1. Scans the PDF bytes for `/ByteRange [...]` patterns — one per
//!    signature. PDFs may accumulate multiple signatures across incremental
//!    updates; each signature covers the prefix up to its own `/Contents`.
//! 2. For each signature, locates the adjacent `/Contents <hex>`, extracts
//!    the DER CMS bytes, and reconstructs the signed-data byte ranges.
//! 3. Dispatches each to `eidas-cades` for verification.
//!
//! Design note: we deliberately do NOT run a full PDF parser (`lopdf` /
//! `pdf`). ByteRange + Contents discovery is robust enough via direct
//! byte-scanning that a full object-graph walk adds surface area without
//! improving correctness for verification.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod scan;
pub mod verify;

pub use scan::{find_signatures, PdfSignatureLocation};
pub use verify::{verify_pades, PadesInput};
