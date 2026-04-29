//! Top-level `Verifier` entry point.
//!
//! Phase 1 provides the wiring and type plumbing only: `verify()` returns an
//! explicit "not yet implemented" error that carries the planned format
//! dispatch. Phase 2 replaces this stub with real CAdES B-B handling.

#![allow(missing_docs)] // Docstrings land alongside the real impls in phase 2+.

use eidas_core::{AlgorithmPolicy, Error, Result, ValidationTime, VerificationReport};
use x509_cert::Certificate;

use crate::{ChainBuilder, TrustAnchor};

/// How the caller presents the signed data to `Verifier::verify`.
#[derive(Debug, Clone, Copy)]
pub enum VerificationInput<'a> {
    /// Self-contained: the container carries both document and signature.
    /// Used by PAdES, JAdES-compact, ASiC.
    Container {
        bytes: &'a [u8],
        hint: Option<ContainerHint>,
    },
    /// Detached: signature bytes + original signed document.
    /// Used by CAdES-detached, XAdES-detached, JAdES-detached.
    Detached {
        signature: &'a [u8],
        signed_data: &'a [u8],
        format: DetachedFormat,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerHint {
    Pdf,
    Asic,
    JadesCompact,
    JadesJson,
    XadesEnveloped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachedFormat {
    Cades,
    XadesDetached,
    JadesDetached,
}

/// The top-level verifier.
#[derive(Debug)]
pub struct Verifier {
    chain_builder: ChainBuilder,
    anchor_certs: Vec<Certificate>,
    intermediate_certs: Vec<Certificate>,
    policy: AlgorithmPolicy,
    time: ValidationTime,
}

impl Verifier {
    /// Start building a verifier.
    #[must_use]
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::default()
    }

    /// Access the chain builder (read-only).
    #[must_use]
    pub fn chain_builder(&self) -> &ChainBuilder {
        &self.chain_builder
    }

    /// Access the algorithm policy (read-only).
    #[must_use]
    pub fn policy(&self) -> &AlgorithmPolicy {
        &self.policy
    }

    /// Access the validation time (read-only).
    #[must_use]
    pub fn validation_time(&self) -> ValidationTime {
        self.time
    }

    /// Verify a signature input.
    ///
    /// Currently supported:
    /// - `DetachedFormat::Cades` — CAdES detached signature (B-B → B-LTA)
    /// - `VerificationInput::Container { hint: None }` — bare CMS
    ///   SignedData blob, treated as attached CAdES
    ///
    /// Everything else returns `Error::Unsupported`.
    pub fn verify(&self, input: VerificationInput<'_>) -> Result<VerificationReport> {
        #[cfg(feature = "cades")]
        {
            let trust = self.cades_trust_material();
            match input {
                VerificationInput::Detached {
                    signature,
                    signed_data,
                    format: DetachedFormat::Cades,
                } => {
                    return eidas_cades::verify_cades(
                        &eidas_cms::CadesInput {
                            cms: signature,
                            detached_content: Some(signed_data),
                        },
                        &trust,
                        &self.policy,
                        self.time,
                    );
                }
                #[cfg(feature = "pades")]
                VerificationInput::Container {
                    bytes,
                    hint: Some(ContainerHint::Pdf),
                } => {
                    return eidas_pades::verify_pades(
                        &eidas_pades::PadesInput { pdf: bytes },
                        &trust,
                        &self.policy,
                        self.time,
                    );
                }
                VerificationInput::Container { bytes, hint: None } => {
                    return eidas_cades::verify_cades(
                        &eidas_cms::CadesInput {
                            cms: bytes,
                            detached_content: None,
                        },
                        &trust,
                        &self.policy,
                        self.time,
                    );
                }
                _ => {}
            }
        }
        Err(Error::Unsupported(format!(
            "verification path not yet implemented: {input:?}"
        )))
    }

    #[cfg(feature = "cades")]
    fn cades_trust_material(&self) -> eidas_cades::CadesTrustMaterial {
        use eidas_cades::CadesTrustMaterial;
        // Reconstruct the anchor list from the chain builder's own state.
        // For that we expose the anchors through a new accessor on
        // ChainBuilder — simpler to track anchors on the builder itself.
        let mut mat = CadesTrustMaterial::new();
        mat.trust_anchors = self.anchor_certs.clone();
        mat.intermediates = self.intermediate_certs.clone();
        mat
    }
}

/// Builder for `Verifier`.
#[derive(Default)]
pub struct VerifierBuilder {
    anchors: Vec<TrustAnchor>,
    intermediates: Vec<Certificate>,
    policy: Option<AlgorithmPolicy>,
    time: Option<ValidationTime>,
}

impl VerifierBuilder {
    pub fn trust_anchors<I: IntoIterator<Item = Certificate>>(mut self, certs: I) -> Self {
        self.anchors
            .extend(certs.into_iter().map(TrustAnchor::new));
        self
    }

    pub fn intermediate_certificates<I: IntoIterator<Item = Certificate>>(
        mut self,
        certs: I,
    ) -> Self {
        self.intermediates.extend(certs);
        self
    }

    #[must_use]
    pub fn policy(mut self, policy: AlgorithmPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    #[must_use]
    pub fn validation_time(mut self, t: ValidationTime) -> Self {
        self.time = Some(t);
        self
    }

    pub fn build(self) -> Result<Verifier> {
        if self.anchors.is_empty() {
            return Err(Error::Config("at least one trust anchor is required".into()));
        }
        let anchor_certs: Vec<Certificate> =
            self.anchors.iter().map(|a| a.certificate.clone()).collect();
        let intermediate_certs = self.intermediates.clone();
        let chain_builder = ChainBuilder::new()
            .with_anchors(self.anchors)
            .with_intermediates(self.intermediates);
        Ok(Verifier {
            chain_builder,
            anchor_certs,
            intermediate_certs,
            policy: self.policy.unwrap_or_else(crate::policy::etsi_119_312_2023),
            time: self.time.unwrap_or(ValidationTime::Now),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_no_anchors() {
        let err = Verifier::builder().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }
}
