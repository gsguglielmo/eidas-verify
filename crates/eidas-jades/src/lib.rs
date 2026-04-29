//! JAdES (ETSI TS 119 182-1) verification.
//!
//! JAdES is JWS (RFC 7515) with an extra set of protected-header claims for
//! AdES semantics. Phase 10 implements:
//!
//! - JWS compact serialisation (`header.payload.signature`) and JSON
//!   flattened serialisation.
//! - B-B verification: RS256/RS384/RS512 (PKCS#1v1.5), ES256/ES384 (ECDSA
//!   with raw r||s signatures, as specified by RFC 7518 §3.4).
//! - JAdES protected-header handling:
//!   - `x5t#S256` — must equal SHA-256 of the first cert in `x5c`.
//!   - `x5c` — cert chain in base64 DER (not base64url).
//!   - `sigT` — claimed signing time (`"YYYY-MM-DDThh:mm:ssZ"`).
//!   - `sigTst` — signature timestamp token (parsed but only diagnosed;
//!     full B-T lift lands in a follow-up phase alongside the CAdES
//!     best-signature-time cascade).
//! - Chain building against caller-supplied trust anchors, algorithm policy
//!   evaluation at the reference time.
//!
//! Not yet implemented (deferred):
//! - PS256/PS384/PS512 (RSASSA-PSS).
//! - EdDSA (Ed25519/Ed448).
//! - B-T / B-LT / B-LTA level lift (parsing + full cascade).
//! - RFC 7797 "b64 header" unencoded-payload support.
//! - JAdES JSON general serialisation with multiple signatures.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod jws;
pub mod verify;

pub use jws::{JwsHeader, JwsSignature};
pub use verify::{verify_jades, JadesInput};
