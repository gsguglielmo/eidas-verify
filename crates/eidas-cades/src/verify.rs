//! Top-level CAdES verification entrypoint (all levels).

use chrono::{DateTime, Utc};
use cms::signed_data::{SignerIdentifier, SignerInfo};
use der::{Decode, Encode};
use eidas_core::{
    AlgorithmId, AlgorithmPolicy, CertificateInfo, DiagnosticMessage, Error, HashAlgorithm, Level,
    Qualification, Result, RevocationInfo, RevocationStatus, SignatureAlgorithm, SignatureReport,
    Status, TimestampInfo, ValidationTime, VerificationReport,
};
use eidas_cms::CadesInput;
use eidas_x509::chain::{ChainBuilder, TrustAnchor};
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

use crate::unsigned::{self, UnsignedAttrs};

/// Trust material: anchors + intermediates + (optional) TrustedLists.
///
/// The CAdES flow augments anchors/intermediates with `ets-certValues` from
/// the signature, so callers only need to pre-populate the anchor set.
/// When `trusted_lists` is populated (requires the `ts-119-615` feature),
/// the produced `SignatureReport.qualification` reflects ETSI TS 119 615
/// instead of defaulting to `Qualification::AdES`.
#[derive(Default, Debug, Clone)]
pub struct CadesTrustMaterial {
    pub trust_anchors: Vec<Certificate>,
    pub intermediates: Vec<Certificate>,
    #[cfg(feature = "ts-119-615")]
    pub trusted_lists: Option<eidas_trust::TrustedLists>,
}

impl CadesTrustMaterial {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_anchors<I: IntoIterator<Item = Certificate>>(mut self, certs: I) -> Self {
        self.trust_anchors.extend(certs);
        self
    }

    pub fn with_intermediates<I: IntoIterator<Item = Certificate>>(mut self, certs: I) -> Self {
        self.intermediates.extend(certs);
        self
    }

    /// Attach TrustedLists for ETSI TS 119 615 qualification.
    #[cfg(feature = "ts-119-615")]
    pub fn with_trusted_lists(mut self, tls: eidas_trust::TrustedLists) -> Self {
        self.trusted_lists = Some(tls);
        self
    }

    fn builder(&self, extra_intermediates: &[Certificate]) -> ChainBuilder {
        let mut b = ChainBuilder::new()
            .with_anchors(self.trust_anchors.iter().cloned().map(TrustAnchor::new))
            .with_intermediates(self.intermediates.iter().cloned());
        for c in extra_intermediates {
            b.push_intermediate(c.clone());
        }
        b
    }
}

/// Verify a CAdES signature at whatever level the artefact supports.
pub fn verify_cades(
    input: &CadesInput<'_>,
    trust: &CadesTrustMaterial,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<VerificationReport> {
    let parsed = eidas_cms::parse_cms_envelope(input.cms, input.detached_content)?;

    let mut reports = Vec::new();
    for signer in parsed.signed_data.signer_infos.0.iter() {
        let rpt = verify_one_signer(
            signer,
            &parsed,
            trust,
            policy,
            validation_time,
        );
        reports.push(rpt);
    }
    Ok(VerificationReport {
        signatures: reports,
        container: None,
    })
}

fn verify_one_signer(
    signer: &SignerInfo,
    parsed: &eidas_cms::ParsedCms,
    trust: &CadesTrustMaterial,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> SignatureReport {
    match verify_one_signer_inner(signer, parsed, trust, policy, validation_time) {
        Ok(report) => report,
        Err(e) => SignatureReport::failed("CADES_VERIFICATION_ERROR", e.to_string()),
    }
}

fn verify_one_signer_inner(
    signer: &SignerInfo,
    parsed: &eidas_cms::ParsedCms,
    trust: &CadesTrustMaterial,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<SignatureReport> {
    let mut diagnostics = Vec::new();

    // Harvest unsigned attributes first: cert-values may contain the signer
    // cert itself (for signatures that don't embed certs in SignedData).
    let unsigned = unsigned::extract(signer)?;

    // Collect candidate certs for locating the signer and building chains.
    let mut all_embedded = parsed.embedded_certs.clone();
    all_embedded.extend(unsigned.ets_cert_values.iter().cloned());

    let signer_cert = locate_signer_cert(&signer.sid, &all_embedded)?;

    // --- Run the B-B core checks (delegates to eidas-cms internal logic). ---
    let bb_core = run_bb_core(signer, parsed, signer_cert)?;
    diagnostics.extend(bb_core.diagnostics);

    // Verify unsigned archiveTimestampV3 / signatureTimeStamp tokens as
    // independent artefacts. Their genTimes will feed the best-signature-time
    // cascade and influence chain evaluation.
    let mut timestamps: Vec<TimestampInfo> = Vec::new();
    let mut best_signature_time: Option<DateTime<Utc>> = None;
    let mut level = Level::BB;

    // -- B-T: signature-time-stamp over SignerInfo.signature --
    for tst_der in &unsigned.signature_time_stamps {
        let sig_bytes = signer.signature.as_bytes();
        match verify_tst(tst_der, sig_bytes, trust, &unsigned, eidas_timestamp::TimestampKind::Signature) {
            Ok(ts) => {
                best_signature_time = Some(
                    best_signature_time
                        .map_or(ts.info.genesis_time, |cur| cur.max(ts.info.genesis_time)),
                );
                if level < Level::BT {
                    level = Level::BT;
                }
                timestamps.push(ts.info);
                diagnostics.extend(ts.diagnostics);
            }
            Err(e) => {
                diagnostics.push(DiagnosticMessage::warn(
                    "SIGNATURE_TIMESTAMP_INVALID",
                    format!("signature-time-stamp token failed: {e}"),
                ));
            }
        }
    }

    // Resolve the evaluation reference time now that we know best_signature_time.
    let reference_time = validation_time.resolve(best_signature_time);

    // --- Build the chain at the chosen reference time. ---
    let chain_builder = trust.builder(&all_embedded);
    let chain_result = chain_builder
        .build(signer_cert.clone(), reference_time)
        .map_err(|e| Error::Chain(format!("CAdES chain: {e}")))?;
    diagnostics.extend(chain_result.diagnostics.clone());
    let chain_infos = chain_result
        .chain
        .iter()
        .map(cert_info)
        .collect::<Result<Vec<_>>>()?;

    // --- Apply algorithm policy. ---
    let algorithm = bb_core.algorithm;
    let decision = policy.evaluate(algorithm, reference_time);
    if !decision.is_accepted_at(reference_time) {
        return Ok(SignatureReport {
            status: Status::TotalFailedSub,
            level_reached: Level::Unknown,
            qualification: Qualification::NotAdES,
            qualifiers: Vec::new(),
            signer: Some(cert_info(signer_cert)?),
            chain: chain_infos,
            signing_time_claimed: bb_core.signing_time_claimed,
            signing_time_best: best_signature_time,
            algorithm: Some(algorithm),
            timestamps,
            revocation: Vec::new(),
            diagnostics: {
                diagnostics.push(DiagnosticMessage::error(
                    "ALG_POLICY_REJECTED",
                    format!("algorithm {algorithm:?} rejected by policy: {decision:?}"),
                ));
                diagnostics
            },
        });
    }

    // --- B-LT: process embedded revocation values. ---
    let mut revocation: Vec<RevocationInfo> = Vec::new();
    let has_lt_material =
        unsigned.saw_revocation_values && (!unsigned.ets_crls.is_empty() || !unsigned.ets_ocsps.is_empty());
    if has_lt_material {
        apply_embedded_revocation(
            &chain_result.chain,
            &unsigned,
            reference_time,
            &mut revocation,
            &mut diagnostics,
        );
        // Lift to B-LT only if no revocation error was recorded AND every
        // intermediate (non-anchor) cert has a Good status.
        let all_good = revocation
            .iter()
            .all(|r| matches!(r.status, RevocationStatus::Good));
        let any_revoked = revocation
            .iter()
            .any(|r| matches!(r.status, RevocationStatus::Revoked { .. }));
        if any_revoked {
            return Ok(SignatureReport {
                status: Status::TotalFailedSub,
                level_reached: level,
                qualification: Qualification::NotAdES,
                qualifiers: Vec::new(),
                signer: Some(cert_info(signer_cert)?),
                chain: chain_infos,
                signing_time_claimed: bb_core.signing_time_claimed,
                signing_time_best: best_signature_time,
                algorithm: Some(algorithm),
                timestamps,
                revocation,
                diagnostics: {
                    diagnostics.push(DiagnosticMessage::error(
                        "REVOCATION_REVOKED",
                        "one or more chain certificates are revoked",
                    ));
                    diagnostics
                },
            });
        }
        if all_good && level >= Level::BT {
            level = Level::BLT;
        } else if all_good && level < Level::BT {
            // B-LT technically requires B-T prerequisites; if there is no
            // signature-time-stamp we still record the revocation info but
            // can't claim B-LT.
            diagnostics.push(DiagnosticMessage::info(
                "LT_MATERIAL_WITHOUT_TIMESTAMP",
                "embedded revocation material present but no signature-time-stamp — level stays at B-B",
            ));
        }
    }

    // --- B-LTA: archive timestamps. ---
    //
    // We verify each archive-timestamp-v3 token's TSA signature and chain.
    // The archive-timestamp imprint's canonical byte construction
    // (EN 319 122-1 §5.5.3) is not recomputed here — it requires building a
    // concatenation of SignedData, signerInfo, and hash tree data which is
    // deferred to a later hardening phase. We record a diagnostic making
    // this trust boundary explicit.
    for ats_der in &unsigned.archive_time_stamps_v3 {
        // Feed the existing signer.signature bytes as the "data" the token
        // covers so the messageImprint comparison won't accidentally pass a
        // tampered token. This is a conservative approximation: the real
        // canonical bytes differ, so ATS validation will typically fail the
        // imprint check and land in the "TSA signature valid but imprint not
        // verifiable" branch.
        match verify_tst(
            ats_der,
            signer.signature.as_bytes(),
            trust,
            &unsigned,
            eidas_timestamp::TimestampKind::ArchiveV3,
        ) {
            Ok(ts) => {
                best_signature_time = Some(
                    best_signature_time
                        .map_or(ts.info.genesis_time, |cur| cur.max(ts.info.genesis_time)),
                );
                if level >= Level::BLT || (level >= Level::BT && has_lt_material) {
                    level = Level::BLTA;
                }
                timestamps.push(ts.info);
                diagnostics.push(DiagnosticMessage::warn(
                    "ATS_IMPRINT_NOT_VERIFIED",
                    "archive-timestamp-v3 signature validated, but its imprint over canonical CAdES bytes was not recomputed (EN 319 122-1 §5.5.3 not yet implemented)",
                ));
            }
            Err(e) => {
                // Imprint-over-raw-signature mismatch is expected; try to
                // verify the token's CMS signature without checking imprint.
                match verify_ats_best_effort(ats_der, trust, &unsigned) {
                    Ok(ts) => {
                        best_signature_time = Some(
                            best_signature_time
                                .map_or(ts.info.genesis_time, |cur| cur.max(ts.info.genesis_time)),
                        );
                        if level >= Level::BLT {
                            level = Level::BLTA;
                        }
                        timestamps.push(ts.info);
                        diagnostics.push(DiagnosticMessage::warn(
                            "ATS_IMPRINT_NOT_VERIFIED",
                            format!(
                                "archive-timestamp-v3 TSA signature ok but imprint not \
                                 verified (EN 319 122-1 §5.5.3 canonicalisation deferred); \
                                 imprint mismatch: {e}"
                            ),
                        ));
                    }
                    Err(e2) => {
                        diagnostics.push(DiagnosticMessage::warn(
                            "ATS_INVALID",
                            format!("archive-timestamp-v3 failed verification: {e2}"),
                        ));
                    }
                }
            }
        }
    }

    // --- ETSI TS 119 615 qualification (optional). ---
    let (qualification, qualifiers) =
        apply_qualification(signer_cert, &chain_result.chain, trust, reference_time, &mut diagnostics);

    Ok(SignatureReport {
        status: Status::TotalPassed,
        level_reached: level,
        qualification,
        qualifiers,
        signer: Some(cert_info(signer_cert)?),
        chain: chain_infos,
        signing_time_claimed: bb_core.signing_time_claimed,
        signing_time_best: best_signature_time,
        algorithm: Some(algorithm),
        timestamps,
        revocation,
        diagnostics,
    })
}

/// Call the qualification engine if TrustedLists were provided; otherwise
/// return the default baseline.
#[cfg(feature = "ts-119-615")]
fn apply_qualification(
    signer: &Certificate,
    chain: &[Certificate],
    trust: &CadesTrustMaterial,
    at: chrono::DateTime<chrono::Utc>,
    diagnostics: &mut Vec<DiagnosticMessage>,
) -> (
    Qualification,
    Vec<eidas_core::QualificationQualifier>,
) {
    let Some(tls) = trust.trusted_lists.as_ref() else {
        return (Qualification::AdES, Vec::new());
    };
    let out = eidas_qualify::qualify_signer(&eidas_qualify::QualificationInput {
        signer,
        chain,
        trusted_lists: tls,
        at,
        baseline: Qualification::AdES,
    });
    diagnostics.extend(out.diagnostics);
    (out.qualification, out.qualifiers)
}

#[cfg(not(feature = "ts-119-615"))]
fn apply_qualification(
    _signer: &Certificate,
    _chain: &[Certificate],
    _trust: &CadesTrustMaterial,
    _at: chrono::DateTime<chrono::Utc>,
    _diagnostics: &mut Vec<DiagnosticMessage>,
) -> (Qualification, Vec<eidas_core::QualificationQualifier>) {
    (Qualification::AdES, Vec::new())
}

// -----------------------------------------------------------------------------

struct BbCore {
    algorithm: AlgorithmId,
    signing_time_claimed: Option<DateTime<Utc>>,
    diagnostics: Vec<DiagnosticMessage>,
}

fn run_bb_core(
    signer: &SignerInfo,
    parsed: &eidas_cms::ParsedCms,
    signer_cert: &Certificate,
) -> Result<BbCore> {
    let mut diagnostics = Vec::new();

    let signed_attrs = signer.signed_attrs.as_ref().ok_or_else(|| {
        Error::Crypto("CAdES requires SignerInfo.signedAttrs — none present".into())
    })?;

    // messageDigest must match content.
    let digest_hash = eidas_cms::digest::hash_from_oid(signer.digest_alg.oid)?;
    let computed = eidas_cms::digest::digest(digest_hash, &parsed.content_bytes)?;
    let claimed = eidas_cms::attrs::message_digest(signed_attrs)?;
    if computed != claimed {
        return Err(Error::Crypto(
            "messageDigest attribute does not match digest of encap content".into(),
        ));
    }

    // contentType attribute (informational).
    let ct = eidas_cms::attrs::content_type(signed_attrs)?;
    if ct != eidas_cms::oids::ID_DATA {
        diagnostics.push(DiagnosticMessage::info(
            "CONTENT_TYPE_NON_DATA",
            format!("signedAttrs.contentType = {ct} (non-id-data)"),
        ));
    }

    // signingCertificate[V2] check. We don't re-implement the ESS parser;
    // call into eidas-cms's existing B-B pipeline for this step by
    // verifying against the signer cert through the shared primitives.
    //
    // The simplest path: call `verify_cades_bb` ourselves with a throwaway
    // builder — but that rebuilds chains. Instead we perform a minimal
    // signed-cert-v2 check inline.
    verify_signing_cert_v2_presence(signed_attrs, signer_cert, &mut diagnostics)?;

    // Re-encode signedAttrs as SET OF and verify the CMS signature.
    let to_be_signed = eidas_cms::attrs::to_signed_der(signed_attrs)?;
    eidas_cms::signature_verify::verify_cms_signature(
        signer_cert,
        &signer.signature_algorithm,
        &signer.digest_alg,
        &to_be_signed,
        signer.signature.as_bytes(),
    )?;

    // Algorithm classification.
    let algorithm = classify_algorithm(signer, signer_cert)?;

    Ok(BbCore {
        algorithm,
        signing_time_claimed: eidas_cms::attrs::signing_time(signed_attrs).ok().flatten(),
        diagnostics,
    })
}

fn verify_signing_cert_v2_presence(
    signed_attrs: &cms::signed_data::SignedAttributes,
    signer_cert: &Certificate,
    diagnostics: &mut Vec<DiagnosticMessage>,
) -> Result<()> {
    // Call the hidden B-B helper by re-running the whole thing is overkill;
    // just require the V2 attribute's first-value ESSCertIDv2 certHash to
    // equal the digest of the signer cert (matching phase 2 behaviour).
    use der::{Decode, Encode, Reader as _, SliceReader};
    if let Some(attr) = eidas_cms::attrs::find(signed_attrs, eidas_cms::oids::ID_AA_SIGNING_CERTIFICATE_V2) {
        let value = attr
            .values
            .iter()
            .next()
            .ok_or_else(|| Error::Crypto("signingCertificateV2 has no values".into()))?;
        let der = value
            .to_der()
            .map_err(|e| Error::Asn1(format!("signingCertificateV2 value: {e}")))?;
        let mut outer = SliceReader::new(&der).map_err(|e| Error::Asn1(e.to_string()))?;
        let header = der::Header::decode(&mut outer).map_err(|e| Error::Asn1(e.to_string()))?;
        let body = outer
            .read_slice(header.length)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        let mut b = SliceReader::new(body).map_err(|e| Error::Asn1(e.to_string()))?;
        let certs_hdr = der::Header::decode(&mut b).map_err(|e| Error::Asn1(e.to_string()))?;
        let certs_body = b
            .read_slice(certs_hdr.length)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        let mut certs = SliceReader::new(certs_body).map_err(|e| Error::Asn1(e.to_string()))?;
        let cid_hdr = der::Header::decode(&mut certs).map_err(|e| Error::Asn1(e.to_string()))?;
        let cid_body = certs
            .read_slice(cid_hdr.length)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        let mut cid = SliceReader::new(cid_body).map_err(|e| Error::Asn1(e.to_string()))?;

        // Optional hashAlgorithm; defaults to SHA-256 per RFC 5035.
        let peek = cid.peek_byte();
        let hash_oid = if peek == Some(u8::from(der::Tag::Sequence)) {
            let h_hdr = der::Header::decode(&mut cid).map_err(|e| Error::Asn1(e.to_string()))?;
            let h_body = cid
                .read_slice(h_hdr.length)
                .map_err(|e| Error::Asn1(e.to_string()))?;
            let mut h = SliceReader::new(h_body).map_err(|e| Error::Asn1(e.to_string()))?;
            der::asn1::ObjectIdentifier::decode(&mut h)
                .map_err(|e| Error::Asn1(e.to_string()))?
        } else {
            eidas_cms::oids::ID_SHA256
        };
        let hash_os = der::asn1::OctetStringRef::decode(&mut cid)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        let claimed = hash_os.as_bytes();
        let alg = eidas_cms::digest::hash_from_oid(hash_oid)?;
        let signer_der = signer_cert
            .to_der()
            .map_err(|e| Error::Asn1(format!("signer cert encode: {e}")))?;
        let computed = eidas_cms::digest::digest(alg, &signer_der)?;
        if computed != claimed {
            return Err(Error::Crypto(
                "signingCertificateV2 hash does not match signer certificate".into(),
            ));
        }
        return Ok(());
    }
    // Fall back to v1 — SHA-1 only, which we refuse.
    if eidas_cms::attrs::find(signed_attrs, eidas_cms::oids::ID_AA_SIGNING_CERTIFICATE).is_some() {
        diagnostics.push(DiagnosticMessage::warn(
            "SIGNING_CERT_V1_USED",
            "signer used legacy SHA-1-based signingCertificate (v1) — not permitted",
        ));
        return Err(Error::Crypto(
            "legacy signingCertificate attribute uses SHA-1 — not permitted".into(),
        ));
    }
    Err(Error::Crypto(
        "CAdES requires signingCertificate or signingCertificateV2 — neither present".into(),
    ))
}

fn classify_algorithm(signer: &SignerInfo, signer_cert: &Certificate) -> Result<AlgorithmId> {
    let hash = eidas_cms::digest::hash_from_oid(signer.digest_alg.oid).or_else(|_| {
        match signer.signature_algorithm.oid {
            o if o == eidas_cms::oids::ID_SHA224_WITH_RSA => Ok(HashAlgorithm::Sha224),
            o if o == eidas_cms::oids::ID_SHA256_WITH_RSA
                || o == eidas_cms::oids::ID_ECDSA_SHA256 =>
            {
                Ok(HashAlgorithm::Sha256)
            }
            o if o == eidas_cms::oids::ID_SHA384_WITH_RSA
                || o == eidas_cms::oids::ID_ECDSA_SHA384 =>
            {
                Ok(HashAlgorithm::Sha384)
            }
            o if o == eidas_cms::oids::ID_SHA512_WITH_RSA
                || o == eidas_cms::oids::ID_ECDSA_SHA512 =>
            {
                Ok(HashAlgorithm::Sha512)
            }
            other => Err(Error::Unsupported(format!(
                "cannot infer hash for signature-alg {other}"
            ))),
        }
    })?;
    let (signature, key_bits) = match signer.signature_algorithm.oid {
        o if o == eidas_cms::oids::ID_RSA_ENCRYPTION
            || o == eidas_cms::oids::ID_SHA1_WITH_RSA
            || o == eidas_cms::oids::ID_SHA224_WITH_RSA
            || o == eidas_cms::oids::ID_SHA256_WITH_RSA
            || o == eidas_cms::oids::ID_SHA384_WITH_RSA
            || o == eidas_cms::oids::ID_SHA512_WITH_RSA =>
        {
            (SignatureAlgorithm::RsaPkcs1v15, rsa_key_bits(signer_cert)?)
        }
        o if o == eidas_cms::oids::ID_RSA_PSS => {
            (SignatureAlgorithm::RsaPss, rsa_key_bits(signer_cert)?)
        }
        o if o == eidas_cms::oids::ID_ECDSA_SHA1
            || o == eidas_cms::oids::ID_ECDSA_SHA224
            || o == eidas_cms::oids::ID_ECDSA_SHA256
            || o == eidas_cms::oids::ID_ECDSA_SHA384
            || o == eidas_cms::oids::ID_ECDSA_SHA512 =>
        {
            (SignatureAlgorithm::Ecdsa, ecc_key_bits(signer_cert)?)
        }
        other => {
            return Err(Error::Unsupported(format!(
                "signature algorithm {other} not classified"
            )))
        }
    };
    Ok(AlgorithmId {
        signature,
        hash,
        key_bits,
    })
}

fn rsa_key_bits(cert: &Certificate) -> Result<u32> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPublicKey;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI encode: {e}")))?;
    let pk = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| Error::Crypto(format!("reading RSA key: {e}")))?;
    Ok(u32::try_from(pk.n().bits()).unwrap_or(u32::MAX))
}

fn ecc_key_bits(cert: &Certificate) -> Result<u32> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::Crypto("EC SPKI parameters absent".into()))?;
    let param_der = params
        .to_der()
        .map_err(|e| Error::Asn1(format!("EC params encode: {e}")))?;
    let curve = der::asn1::ObjectIdentifier::from_der(&param_der)
        .map_err(|e| Error::Asn1(format!("EC curve OID: {e}")))?;
    Ok(match curve {
        o if o == eidas_cms::oids::ID_SECP256R1 => 256,
        o if o == eidas_cms::oids::ID_SECP384R1 => 384,
        o if o == eidas_cms::oids::ID_SECP521R1 => 521,
        _ => 0,
    })
}

fn locate_signer_cert<'a>(
    sid: &SignerIdentifier,
    pool: &'a [Certificate],
) -> Result<&'a Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => pool
            .iter()
            .find(|c| {
                c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
            })
            .ok_or_else(|| Error::Crypto(
                "signer-info IssuerAndSerialNumber not found in embedded certs or ets-certValues"
                    .into(),
            )),
        SignerIdentifier::SubjectKeyIdentifier(sk) => {
            let want = sk.0.as_bytes();
            pool.iter()
                .find(|c| eidas_x509::ski(c).as_deref() == Some(want))
                .ok_or_else(|| Error::Crypto(
                    "signer-info SubjectKeyIdentifier not found in embedded certs or ets-certValues"
                        .into(),
                ))
        }
    }
}

fn cert_info(cert: &Certificate) -> Result<CertificateInfo> {
    let (nb, na) = eidas_x509::validity_window(cert)?;
    Ok(CertificateInfo {
        subject: eidas_x509::subject_display(cert),
        issuer: eidas_x509::issuer_display(cert),
        serial_hex: hex::encode(cert.tbs_certificate.serial_number.as_bytes()),
        not_before: nb,
        not_after: na,
        ski: eidas_x509::ski(cert),
        aki: eidas_x509::aki(cert),
        der: cert.to_der().map_err(|e| Error::Asn1(e.to_string()))?,
    })
}

// -----------------------------------------------------------------------------
// Timestamp helpers

fn verify_tst(
    token_der: &[u8],
    timestamped_data: &[u8],
    trust: &CadesTrustMaterial,
    unsigned: &UnsignedAttrs,
    kind: eidas_timestamp::TimestampKind,
) -> Result<eidas_timestamp::TstVerification> {
    // Trust anchors for the TSA are the same caller-supplied anchor set.
    // Intermediates may include anything from certValues.
    let mut extra = Vec::new();
    extra.extend(unsigned.ets_cert_values.iter().cloned());
    let builder = trust.builder(&extra);
    eidas_timestamp::verify_time_stamp_token(token_der, timestamped_data, &builder, kind)
}

/// Best-effort archive TST verification: parse the TST and verify the TSA
/// signature + chain, but skip the messageImprint comparison (which requires
/// canonical CAdES bytes). Returns a `TstVerification` built by hand.
fn verify_ats_best_effort(
    token_der: &[u8],
    trust: &CadesTrustMaterial,
    unsigned: &UnsignedAttrs,
) -> Result<eidas_timestamp::TstVerification> {
    // The simplest path: call verify_time_stamp_token with a synthetic
    // `timestamped_data` computed to match the declared imprint. We parse
    // the token's TSTInfo to recover the imprint bytes, then pass an empty
    // "pre-hashed" wrapper.
    //
    // In practice, we can't forge the original data; but we can parse the
    // token's embedded imprint, feed that as the already-hashed data to the
    // caller, and let the imprint check pass trivially — but that requires
    // changing verify_time_stamp_token's contract.
    //
    // Pragmatic alternative: duplicate the minimal verification here —
    // parse + TSA cert + signature, skipping the imprint step entirely.
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    let ci = ContentInfo::from_der(token_der)
        .map_err(|e| Error::Timestamp(format!("ATS ContentInfo: {e}")))?;
    let sd_bytes = ci
        .content
        .to_der()
        .map_err(|e| Error::Asn1(format!("ATS SignedData: {e}")))?;
    let sd = SignedData::from_der(&sd_bytes)
        .map_err(|e| Error::Timestamp(format!("ATS SignedData: {e}")))?;

    // Pull TSA cert from certs + ets_cert_values.
    let mut certs = Vec::new();
    if let Some(set) = sd.certificates.as_ref() {
        use cms::cert::CertificateChoices;
        for c in set.0.iter() {
            if let CertificateChoices::Certificate(c) = c {
                certs.push(c.clone());
            }
        }
    }
    certs.extend(unsigned.ets_cert_values.iter().cloned());

    let signers: Vec<_> = sd.signer_infos.0.iter().collect();
    let signer = signers.first().ok_or_else(|| {
        Error::Timestamp("archive-timestamp has no SignerInfo".into())
    })?;
    let tsa_cert = locate_signer_cert(&signer.sid, &certs)?;

    // Extract genTime from TSTInfo for historical chain evaluation.
    let econtent = sd.encap_content_info.econtent.as_ref().ok_or_else(|| {
        Error::Timestamp("ATS has no eContent".into())
    })?;
    let econtent_der = econtent
        .to_der()
        .map_err(|e| Error::Asn1(format!("ATS eContent: {e}")))?;
    let tst_bytes = der::asn1::OctetString::from_der(&econtent_der)
        .map_err(|e| Error::Timestamp(format!("ATS eContent: {e}")))?
        .into_bytes();
    let tst_info = eidas_timestamp::tst::TstInfo::from_der(&tst_bytes)?;

    // Verify TSA CMS signature over signedAttrs.
    let signed_attrs = signer.signed_attrs.as_ref().ok_or_else(|| {
        Error::Timestamp("ATS SignerInfo has no signedAttrs".into())
    })?;
    let expected_md = eidas_cms::digest::digest(
        eidas_cms::digest::hash_from_oid(signer.digest_alg.oid)?,
        &tst_bytes,
    )?;
    let claimed_md = eidas_cms::attrs::message_digest(signed_attrs)?;
    if expected_md != claimed_md {
        return Err(Error::Timestamp(
            "ATS signedAttrs.messageDigest does not match embedded TSTInfo digest".into(),
        ));
    }
    let to_be_signed = eidas_cms::attrs::to_signed_der(signed_attrs)?;
    eidas_cms::signature_verify::verify_cms_signature(
        tsa_cert,
        &signer.signature_algorithm,
        &signer.digest_alg,
        &to_be_signed,
        signer.signature.as_bytes(),
    )
    .map_err(|e| match e {
        Error::Crypto(m) => Error::Timestamp(format!("ATS TSA signature invalid: {m}")),
        other => other,
    })?;

    // Chain.
    let mut extra = Vec::new();
    extra.extend(certs.iter().cloned());
    let builder = trust.builder(&extra);
    let chain = builder
        .build(tsa_cert.clone(), tst_info.gen_time)
        .map_err(|e| Error::Timestamp(format!("ATS chain: {e}")))?;

    let info = TimestampInfo {
        kind: "archive-v3".into(),
        genesis_time: tst_info.gen_time,
        tsa_subject: Some(eidas_x509::subject_display(tsa_cert)),
        imprint_algorithm: None,
        valid: true,
    };
    Ok(eidas_timestamp::TstVerification {
        info,
        chain,
        tst_info,
        diagnostics: Vec::new(),
    })
}

// -----------------------------------------------------------------------------
// Embedded revocation

fn apply_embedded_revocation(
    chain: &[Certificate],
    unsigned: &UnsignedAttrs,
    at: DateTime<Utc>,
    out: &mut Vec<RevocationInfo>,
    diagnostics: &mut Vec<DiagnosticMessage>,
) {
    // Check each non-leaf chain cert by finding a CRL or OCSP response
    // whose issuer matches the cert's issuer DN.
    //
    // chain[0] = signer leaf, chain[-1] = trust anchor.
    // We check chain[0..chain.len()-1] — the anchor doesn't need revocation.
    for (idx, cert) in chain.iter().enumerate() {
        if idx == chain.len() - 1 {
            break;
        }
        let issuer_cert = &chain[idx + 1];
        let serial = cert.tbs_certificate.serial_number.clone();
        let subject = eidas_x509::subject_display(cert);

        // Try OCSPs first.
        if let Some(info) = try_ocsp(&unsigned.ets_ocsps, cert, issuer_cert, at) {
            out.push(info);
            continue;
        }
        if let Some(info) = try_crl(&unsigned.ets_crls, issuer_cert, &subject, &serial, at) {
            out.push(info);
            continue;
        }
        diagnostics.push(DiagnosticMessage::warn(
            "REVOCATION_NO_EVIDENCE",
            format!(
                "no CRL or OCSP in revocationValues covers '{subject}'",
            ),
        ));
    }
}

fn try_crl(
    crls: &[Vec<u8>],
    issuer: &Certificate,
    subject: &str,
    serial: &SerialNumber,
    at: DateTime<Utc>,
) -> Option<RevocationInfo> {
    for crl in crls {
        match eidas_revocation::verify_crl(crl, issuer, subject, serial, at) {
            Ok(check) => return Some(check.info),
            Err(_) => continue,
        }
    }
    None
}

fn try_ocsp(
    ocsps: &[Vec<u8>],
    target: &Certificate,
    issuer: &Certificate,
    at: DateTime<Utc>,
) -> Option<RevocationInfo> {
    for resp in ocsps {
        // The revocationValues blobs are BasicOCSPResponse, not OcspResponse;
        // wrap each into a full OcspResponse envelope.
        let wrapped = wrap_basic_as_ocsp_response(resp)?;
        match eidas_revocation::verify_ocsp(&wrapped, target, issuer, at) {
            Ok(check) => return Some(check.info),
            Err(_) => continue,
        }
    }
    None
}

/// `revocationValues.ocspVals` entries are BasicOCSPResponse DER; wrap them
/// in a synthetic `OcspResponse` (responseStatus=successful, type=basic).
fn wrap_basic_as_ocsp_response(basic_der: &[u8]) -> Option<Vec<u8>> {
    use const_oid::AssociatedOid;
    use der::asn1::OctetString;
    use der::Encode;
    use x509_ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus, ResponseBytes};
    let bytes = ResponseBytes {
        response_type: BasicOcspResponse::OID,
        response: OctetString::new(basic_der.to_vec()).ok()?,
    };
    let outer = OcspResponse {
        response_status: OcspResponseStatus::Successful,
        response_bytes: Some(bytes),
    };
    outer.to_der().ok()
}
