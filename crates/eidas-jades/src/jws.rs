//! JWS parsing (RFC 7515) + JAdES header typing.

use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use eidas_core::{Error, Result};
use serde::Deserialize;

/// A parsed JWS protected header (RFC 7515 §4 + JAdES extensions).
#[derive(Debug, Clone, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    /// Certificate chain in PKIX base64 DER (RFC 7515 §4.1.6).
    pub x5c: Option<Vec<String>>,
    /// SHA-256 thumbprint of the signer cert (RFC 7517 §4.9) — mandatory in
    /// JAdES. base64url-encoded.
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
    /// Claimed signing time (JAdES §5.1.11 `sigT`).
    #[serde(rename = "sigT")]
    pub sig_t: Option<String>,
    /// Signature timestamp(s) (JAdES §5.3.1 `sigTst`). Deferred structural parse.
    #[serde(rename = "sigTst")]
    pub sig_tst: Option<serde_json::Value>,
    /// Anything else — surfaced for diagnostics.
    #[serde(flatten)]
    pub extras: serde_json::Map<String, serde_json::Value>,
}

/// Parse result of a JWS (compact or flattened).
#[derive(Debug, Clone)]
pub struct JwsSignature {
    /// Protected header — decoded JSON.
    pub header: JwsHeader,
    /// Raw protected-header base64url string (needed to reconstruct the
    /// signing input as `b64(h) . b64(p)`).
    pub protected_b64: String,
    /// Raw payload base64url (or the unencoded payload for RFC 7797 style
    /// — only encoded path supported in Phase 10).
    pub payload_b64: String,
    /// Decoded payload bytes.
    pub payload: Vec<u8>,
    /// Raw signature bytes (decoded from base64url).
    pub signature: Vec<u8>,
}

impl JwsSignature {
    /// Parse from compact serialisation: `header.payload.signature`.
    pub fn from_compact(compact: &str) -> Result<Self> {
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Json(format!(
                "JWS compact must have 3 parts, got {}",
                parts.len()
            )));
        }
        let protected_b64 = parts[0].to_string();
        let payload_b64 = parts[1].to_string();
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| Error::Json(format!("JWS signature b64url: {e}")))?;
        let header_bytes = URL_SAFE_NO_PAD
            .decode(&protected_b64)
            .map_err(|e| Error::Json(format!("JWS header b64url: {e}")))?;
        let header: JwsHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::Json(format!("JWS header json: {e}")))?;
        let payload = URL_SAFE_NO_PAD
            .decode(&payload_b64)
            .map_err(|e| Error::Json(format!("JWS payload b64url: {e}")))?;
        Ok(Self {
            header,
            protected_b64,
            payload_b64,
            payload,
            signature,
        })
    }

    /// Parse from JSON flattened serialisation (RFC 7515 §7.2.2).
    pub fn from_flattened_json(json: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Flat {
            protected: Option<String>,
            payload: String,
            signature: String,
        }
        let f: Flat = serde_json::from_slice(json)
            .map_err(|e| Error::Json(format!("JWS flattened: {e}")))?;
        let protected_b64 = f.protected.ok_or_else(|| {
            Error::Json("JAdES requires a protected header; flattened JSON has none".into())
        })?;
        let signature = URL_SAFE_NO_PAD
            .decode(&f.signature)
            .map_err(|e| Error::Json(format!("JWS signature b64url: {e}")))?;
        let header_bytes = URL_SAFE_NO_PAD
            .decode(&protected_b64)
            .map_err(|e| Error::Json(format!("JWS header b64url: {e}")))?;
        let header: JwsHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::Json(format!("JWS header json: {e}")))?;
        let payload = URL_SAFE_NO_PAD
            .decode(&f.payload)
            .map_err(|e| Error::Json(format!("JWS payload b64url: {e}")))?;
        Ok(Self {
            header,
            protected_b64,
            payload_b64: f.payload,
            payload,
            signature,
        })
    }

    /// Signing input: `ASCII(b64url(header)) . ASCII(b64url(payload))`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.protected_b64.len() + 1 + self.payload_b64.len());
        v.extend_from_slice(self.protected_b64.as_bytes());
        v.push(b'.');
        v.extend_from_slice(self.payload_b64.as_bytes());
        v
    }

    /// Decode the first certificate in `x5c`.
    pub fn signer_certificate(&self) -> Result<Option<x509_cert::Certificate>> {
        let Some(chain) = self.header.x5c.as_ref() else {
            return Ok(None);
        };
        let Some(first) = chain.first() else {
            return Ok(None);
        };
        // RFC 7515 §4.1.6: x5c entries are PKIX base64 DER (not base64url).
        let der = STANDARD
            .decode(first.as_bytes())
            .map_err(|e| Error::Json(format!("x5c[0] b64: {e}")))?;
        let cert = <x509_cert::Certificate as der::Decode>::from_der(&der)
            .map_err(|e| Error::Asn1(format!("x5c[0] DER: {e}")))?;
        Ok(Some(cert))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_compact_rejects_bad_count() {
        let err = JwsSignature::from_compact("a.b").unwrap_err();
        assert!(matches!(err, Error::Json(_)));
    }

    #[test]
    fn signing_input_is_h_dot_p() {
        // Build a tiny hand-crafted JWS.
        let header = r#"{"alg":"RS256"}"#;
        let h_b64 = URL_SAFE_NO_PAD.encode(header);
        let p_b64 = URL_SAFE_NO_PAD.encode(b"hi");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"not-real");
        let compact = format!("{h_b64}.{p_b64}.{sig_b64}");
        let jws = JwsSignature::from_compact(&compact).unwrap();
        let si = jws.signing_input();
        assert_eq!(
            std::str::from_utf8(&si).unwrap(),
            format!("{h_b64}.{p_b64}")
        );
    }
}
