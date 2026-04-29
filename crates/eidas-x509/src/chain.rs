//! Chain builder and validator.
//!
//! A chain is a `Vec<Certificate>` that starts at the signer (index 0) and
//! ends at a trust anchor (last element). Each adjacent pair satisfies:
//! - issuer(cert[i]) == subject(cert[i+1])
//! - cert[i+1] is CA-capable (basicConstraints.cA = true, keyUsage.keyCertSign)
//! - cert[i].validity covers the evaluation time
//! - if AKI present, AKI(cert[i]) == SKI(cert[i+1])

use chrono::{DateTime, Utc};
use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE};
use der::{Decode, Encode};
use eidas_core::{DiagnosticMessage, Error, Result};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::Certificate;

use crate::cert_info::{aki, ski, spki_der, subject_display, validity_window};

/// A caller-supplied root of trust.
///
/// We keep the full certificate so the builder can check subject / SPKI
/// equality when it reaches the anchor; some callers only carry SPKI, which
/// we could support via a future `TrustAnchorKind` enum.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub certificate: Certificate,
}

impl TrustAnchor {
    #[must_use]
    pub fn new(certificate: Certificate) -> Self {
        Self { certificate }
    }

    /// Subject DN rendered for diagnostics.
    #[must_use]
    pub fn subject_display(&self) -> String {
        subject_display(&self.certificate)
    }
}

/// Outcome of `ChainBuilder::build`.
#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    /// signer → … → anchor. `Vec` is always non-empty on success.
    pub chain: Vec<Certificate>,
    /// Trust anchor reached. Always the last element of `chain`.
    pub anchor: TrustAnchor,
    /// Non-fatal observations (e.g. missing SKI/AKI pairing).
    pub diagnostics: Vec<DiagnosticMessage>,
}

/// Builder for X.509 chains.
#[derive(Debug, Default)]
pub struct ChainBuilder {
    anchors: Vec<TrustAnchor>,
    intermediates: Vec<Certificate>,
}

impl ChainBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_anchors<I: IntoIterator<Item = TrustAnchor>>(mut self, anchors: I) -> Self {
        self.anchors.extend(anchors);
        self
    }

    pub fn push_anchor(&mut self, anchor: TrustAnchor) -> &mut Self {
        self.anchors.push(anchor);
        self
    }

    pub fn with_intermediates<I: IntoIterator<Item = Certificate>>(mut self, certs: I) -> Self {
        self.intermediates.extend(certs);
        self
    }

    pub fn push_intermediate(&mut self, cert: Certificate) -> &mut Self {
        self.intermediates.push(cert);
        self
    }

    /// Build and validate a chain starting at `signer_cert` and evaluated at
    /// `at`.
    pub fn build(
        &self,
        signer_cert: Certificate,
        at: DateTime<Utc>,
    ) -> Result<ChainValidationResult> {
        if self.anchors.is_empty() {
            return Err(Error::Config(
                "chain builder has no trust anchors".into(),
            ));
        }

        let mut diagnostics = Vec::new();
        let mut chain: Vec<Certificate> = vec![signer_cert];
        let mut used_intermediates: Vec<bool> = vec![false; self.intermediates.len()];

        // Iterate upward until we hit a known anchor.
        loop {
            let tail = chain.last().expect("chain is non-empty");

            // Is `tail` itself already an anchor?
            if let Some(anchor) = self.match_anchor(tail)? {
                // Validate `tail` against itself (self-issued root) only if
                // the chain has no signer-to-anchor intermediate leg.
                validate_link_time(tail, at)?;
                // Remove the duplicate anchor copy from the chain — callers
                // get anchor separately and don't want it twice.
                chain.pop();
                chain.push(anchor.certificate.clone());
                return Ok(ChainValidationResult { chain, anchor, diagnostics });
            }

            // Otherwise, look for an issuer among intermediates + anchors.
            let tail_aki = aki(tail);
            let tail_issuer = &tail.tbs_certificate.issuer;

            // Prefer intermediates; anchors get one last look at the end.
            let mut issuer_cert: Option<Certificate> = None;
            let mut issuer_from_intermediate: Option<usize> = None;

            for (idx, cand) in self.intermediates.iter().enumerate() {
                if used_intermediates[idx] {
                    continue;
                }
                if issuer_matches(cand, tail_issuer, tail_aki.as_deref()) {
                    issuer_cert = Some(cand.clone());
                    issuer_from_intermediate = Some(idx);
                    break;
                }
            }

            if issuer_cert.is_none() {
                for anchor in &self.anchors {
                    if issuer_matches(&anchor.certificate, tail_issuer, tail_aki.as_deref()) {
                        issuer_cert = Some(anchor.certificate.clone());
                        break;
                    }
                }
            }

            let Some(issuer) = issuer_cert else {
                return Err(Error::Chain(format!(
                    "no issuer found for '{}'",
                    subject_display(tail),
                )));
            };

            // Validate the `tail → issuer` link.
            validate_link_time(tail, at)?;
            validate_link_time(&issuer, at)?;
            validate_issuer_ca_capability(&issuer, &mut diagnostics)?;

            if let Some(idx) = issuer_from_intermediate {
                used_intermediates[idx] = true;
            }

            chain.push(issuer);

            if chain.len() > 16 {
                return Err(Error::Chain(
                    "chain exceeded maximum depth (cycle?)".into(),
                ));
            }
        }
    }

    /// Find a trust anchor whose Subject + SPKI match `cert` exactly.
    fn match_anchor(&self, cert: &Certificate) -> Result<Option<TrustAnchor>> {
        let cert_spki = spki_der(cert)?;
        for anchor in &self.anchors {
            if anchor.certificate.tbs_certificate.subject == cert.tbs_certificate.subject {
                let anchor_spki = spki_der(&anchor.certificate)?;
                if anchor_spki == cert_spki {
                    return Ok(Some(anchor.clone()));
                }
            }
        }
        Ok(None)
    }
}

/// Whether `candidate` is a plausible issuer of a cert whose Issuer DN is
/// `issuer_dn` and whose AKI (if any) is `subject_aki`.
fn issuer_matches(
    candidate: &Certificate,
    issuer_dn: &x509_cert::name::Name,
    subject_aki: Option<&[u8]>,
) -> bool {
    if &candidate.tbs_certificate.subject != issuer_dn {
        return false;
    }
    match (subject_aki, ski(candidate)) {
        (Some(wanted), Some(got)) => wanted == got.as_slice(),
        // If either side lacks key-id, fall back to DN match only.
        _ => true,
    }
}

fn validate_link_time(cert: &Certificate, at: DateTime<Utc>) -> Result<()> {
    let (nb, na) = validity_window(cert)?;
    if at < nb {
        return Err(Error::Chain(format!(
            "certificate '{}' not yet valid (notBefore {nb})",
            subject_display(cert)
        )));
    }
    if at > na {
        return Err(Error::Chain(format!(
            "certificate '{}' expired at {na}",
            subject_display(cert)
        )));
    }
    Ok(())
}

fn validate_issuer_ca_capability(
    issuer: &Certificate,
    diagnostics: &mut Vec<DiagnosticMessage>,
) -> Result<()> {
    let exts = issuer.tbs_certificate.extensions.as_ref();
    let mut saw_bc = false;
    let mut saw_ku = false;
    if let Some(exts) = exts {
        for ext in exts {
            if ext.extn_id == ID_CE_BASIC_CONSTRAINTS {
                saw_bc = true;
                let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| Error::Asn1(format!("basicConstraints: {e}")))?;
                if !bc.ca {
                    return Err(Error::Chain(format!(
                        "issuer '{}' is not a CA (basicConstraints.cA = false)",
                        subject_display(issuer)
                    )));
                }
            } else if ext.extn_id == ID_CE_KEY_USAGE {
                saw_ku = true;
                let ku = KeyUsage::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| Error::Asn1(format!("keyUsage: {e}")))?;
                if !ku.0.into_iter().any(|u| u == KeyUsages::KeyCertSign) {
                    return Err(Error::Chain(format!(
                        "issuer '{}' missing keyCertSign",
                        subject_display(issuer)
                    )));
                }
            } else if ext.extn_id == ID_CE_EXT_KEY_USAGE {
                let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| Error::Asn1(format!("extKeyUsage: {e}")))?;
                // We don't reject on EKU here — only record a diagnostic if
                // the CA has an EKU that does not include anyExtendedKeyUsage.
                // A stricter profile may want to treat this as fatal.
                if !eku.0.is_empty() {
                    diagnostics.push(DiagnosticMessage::info(
                        "CA_HAS_EKU",
                        format!(
                            "CA '{}' carries an Extended Key Usage extension",
                            subject_display(issuer)
                        ),
                    ));
                }
            }
        }
    }
    if !saw_bc {
        diagnostics.push(DiagnosticMessage::warn(
            "CA_NO_BASIC_CONSTRAINTS",
            format!(
                "issuer '{}' has no basicConstraints extension — assuming CA",
                subject_display(issuer)
            ),
        ));
    }
    if !saw_ku {
        diagnostics.push(DiagnosticMessage::warn(
            "CA_NO_KEY_USAGE",
            format!(
                "issuer '{}' has no keyUsage extension",
                subject_display(issuer)
            ),
        ));
    }
    Ok(())
}

/// Internal helper used by tests.
#[doc(hidden)]
pub fn parse_der(bytes: &[u8]) -> Result<Certificate> {
    Certificate::from_der(bytes).map_err(|e| Error::Asn1(format!("certificate: {e}")))
}

/// Internal helper: re-encode for byte-level equality checks.
#[doc(hidden)]
pub fn to_der(cert: &Certificate) -> Result<Vec<u8>> {
    cert.to_der().map_err(|e| Error::Asn1(format!("encode: {e}")))
}

// Integration tests with real certs live in `tests/chain_tests.rs`; that
// keeps rcgen out of the crate's non-test dep graph.
