//! ETSI TS 119 615 qualification engine.
//!
//! Given a signer certificate, its validated chain, and a `TrustedLists`
//! bundle, produce a final [`Qualification`] (AdES / AdES-QC / QES) plus a
//! list of applicable [`QualificationQualifier`]s.
//!
//! The algorithm (simplified from TS 119 615 §5):
//!
//! 1. Walk the chain from the signer upward, looking for a certificate that
//!    matches a service in any supplied TrustedList (matched by SPKI).
//!    Typically the match happens at the issuing CA.
//! 2. If the matching service is a `CA/QC` service with status
//!    `granted` / `under-supervision` / `recognised` at the reference time,
//!    the signer is backed by a *qualified certificate* → **AdES-QC**.
//! 3. Refine with qualifiers and certificate QCStatements:
//!    - `QCWithQSCD` → QES.
//!    - `QCQSCDStatusAsInCert` + `id-etsi-qcs-QcSSCD` asserted in the
//!       cert's qcStatements → QES.
//!    - `QCNoQSCD` → stays at AdES-QC.
//!    - Without any QSCD qualifier: if the cert asserts QcSSCD, QES; else
//!      AdES-QC.
//!    - `QCForESig` and `QCForESeal` are recorded as qualifiers but do not
//!      alter the AdES-QC / QES decision.
//! 4. If no service matches, or the service status is `withdrawn`, return
//!    the pre-TL qualification unchanged (typically `Qualification::AdES`).
//!
//! Corners we deliberately do not handle yet (Phase 12 hardening):
//! - Mutual-recognition agreements with non-EU territories.
//! - "Granted-at-date" qualifiers applied per historical instance.
//! - TS 119 615 §5.5.6 "consistency checks" between TL qualifiers and
//!   cert statements (contradictions → `IndeterminateSub`).

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod qcstatements;
pub mod engine;

pub use engine::{qualify_signer, QualificationInput, QualificationOutput};
pub use qcstatements::{QcStatements, has_qc_sscd};
