//! ASiC (Associated Signature Container) verification per ETSI EN 319 162.
//!
//! An ASiC is a ZIP file containing:
//! - A `mimetype` entry (first, uncompressed) identifying the container
//!   variant: `application/vnd.etsi.asic-s+zip` or `application/vnd.etsi.asic-e+zip`.
//! - One or more signatures under `META-INF/`, typically:
//!   - `META-INF/signature.p7s` (ASiC-S, CAdES detached) or
//!   - `META-INF/signatures.p7s` / `META-INF/signatures*.p7s` (ASiC-E CAdES),
//!   - XAdES variants — deferred to Phase 11.
//! - The signed data files. For ASiC-S this is a single top-level file; for
//!   ASiC-E there can be multiple, optionally referenced from
//!   `META-INF/ASiCManifest*.xml`.
//!
//! Phase 9 scope:
//! - ASiC-S and ASiC-E with **CAdES** detached signatures.
//! - ASiC-E manifest parsing is **not** implemented: we treat each signature
//!   file as covering every top-level non-META-INF entry, verifying against
//!   each in turn. If none match, the signature is reported as failed.
//! - XAdES-inside-ASiC lands in Phase 11.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod verify;

pub use verify::{verify_asic, AsicInput};
