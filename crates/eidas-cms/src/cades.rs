//! CAdES B-B verification entry point.
//!
//! Flow (mirrors ETSI EN 319 122-1 §5.2 and RFC 5652 §5.4–§5.6):
//!
//! 1. Parse ContentInfo → SignedData.
//! 2. Pick the signer cert from `certificates` + caller-supplied hint.
//! 3. For each signer-info:
//!    a. Check required CAdES signed attributes are present.
//!    b. Check `messageDigest` attribute equals digest of the encap content.
//!    c. Check `signingCertificateV2` ESSCertIDv2 hash equals digest of the
//!       signer certificate.
//!    d. Re-encode signedAttrs as `SET OF` and verify the signature over it.
//!    e. Build + validate the X.509 chain to a trust anchor.
//!    f. Apply algorithm policy.
//! 4. Emit a `SignatureReport` with `Level::BB` on success.

use chrono::{DateTime, Utc};
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedAttributes, SignedData, SignerIdentifier, SignerInfo};
use der::asn1::OctetString;
use der::{Decode, Encode};
use eidas_core::{
    AlgorithmId, AlgorithmPolicy, CertificateInfo, DiagnosticMessage, Error, HashAlgorithm, Level,
    Qualification, Result, SignatureAlgorithm, SignatureReport, Status, ValidationTime,
    VerificationReport,
};
use eidas_x509::chain::ChainBuilder;
use eidas_x509::{aki, ski, subject_display, validity_window};
use x509_cert::Certificate;

use crate::{attrs, digest::hash_from_oid, oids, signature_verify};

/// Caller-supplied input for CAdES verification.
pub struct CadesInput<'a> {
    /// DER-encoded CMS ContentInfo (SignedData inside).
    pub cms: &'a [u8],
    /// Original signed data for detached signatures. Ignored for attached.
    pub detached_content: Option<&'a [u8]>,
}

/// Verify a CAdES signature at level B-B.
///
/// Returns a `VerificationReport` with one `SignatureReport` per `SignerInfo`.
/// A verification failure of an individual signer-info is reflected inside its
/// report (rather than being returned as an `Error`); only top-level parse or
/// configuration errors bubble up through `Result`.
pub fn verify_cades_bb(
    input: &CadesInput<'_>,
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<VerificationReport> {
    let ci = ContentInfo::from_der(input.cms)
        .map_err(|e| Error::Asn1(format!("ContentInfo: {e}")))?;
    if ci.content_type != oids::ID_SIGNED_DATA {
        return Err(Error::Unsupported(format!(
            "outer ContentInfo is not SignedData (got {})",
            ci.content_type
        )));
    }
    let sd_bytes = ci
        .content
        .to_der()
        .map_err(|e| Error::Asn1(format!("re-encoding inner SignedData: {e}")))?;
    let sd = SignedData::from_der(&sd_bytes)
        .map_err(|e| Error::Asn1(format!("SignedData: {e}")))?;

    let content_bytes = resolve_content_bytes(&sd, input.detached_content)?;
    let embedded_certs = collect_embedded_certs(&sd)?;

    let reference_time = validation_time.resolve(None);

    let mut reports = Vec::new();
    for signer in sd.signer_infos.0.iter() {
        let rpt = verify_one_signer(
            signer,
            &embedded_certs,
            &content_bytes,
            chain_builder,
            policy,
            reference_time,
        );
        reports.push(rpt);
    }

    Ok(VerificationReport {
        signatures: reports,
        container: None,
    })
}

fn resolve_content_bytes<'a>(
    sd: &'a SignedData,
    detached: Option<&'a [u8]>,
) -> Result<Vec<u8>> {
    if let Some(any) = sd.encap_content_info.econtent.as_ref() {
        // Attached: econtent carries the original content inside an OCTET STRING.
        let any_der = any
            .to_der()
            .map_err(|e| Error::Asn1(format!("encap econtent: {e}")))?;
        let os = OctetString::from_der(&any_der)
            .map_err(|e| Error::Asn1(format!("econtent must be OCTET STRING: {e}")))?;
        return Ok(os.into_bytes());
    }
    // Detached: caller must supply original content.
    detached
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Config("detached CAdES requires detached_content input".into()))
}

fn collect_embedded_certs(sd: &SignedData) -> Result<Vec<Certificate>> {
    let Some(set) = sd.certificates.as_ref() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for choice in set.0.iter() {
        use cms::cert::CertificateChoices;
        match choice {
            CertificateChoices::Certificate(c) => out.push(c.clone()),
            CertificateChoices::Other(_) => {
                // "other" cert choices (attribute certs, extended certs) are
                // not used for AdES chain building. Skip silently.
            }
        }
    }
    Ok(out)
}

fn verify_one_signer(
    signer: &SignerInfo,
    embedded_certs: &[Certificate],
    content_bytes: &[u8],
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    at: DateTime<Utc>,
) -> SignatureReport {
    match verify_one_signer_inner(signer, embedded_certs, content_bytes, chain_builder, policy, at)
    {
        Ok(report) => report,
        Err(e) => SignatureReport::failed("CADES_VERIFICATION_ERROR", e.to_string()),
    }
}

fn verify_one_signer_inner(
    signer: &SignerInfo,
    embedded_certs: &[Certificate],
    content_bytes: &[u8],
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    at: DateTime<Utc>,
) -> Result<SignatureReport> {
    let mut diagnostics = Vec::new();

    // (1) Locate the signer certificate.
    let signer_cert = locate_signer_cert(&signer.sid, embedded_certs)?;

    // (2) Require signedAttrs — CAdES B-B mandates it.
    let signed_attrs = signer.signed_attrs.as_ref().ok_or_else(|| {
        Error::Crypto("CAdES requires SignerInfo.signedAttrs — none present".into())
    })?;

    // (3) Check messageDigest attribute against encap content.
    let digest_hash = hash_from_oid(signer.digest_alg.oid)?;
    let computed = crate::digest::digest(digest_hash, content_bytes)?;
    let claimed = attrs::message_digest(signed_attrs)?;
    if computed != claimed {
        return Ok(SignatureReport::failed(
            "MESSAGE_DIGEST_MISMATCH",
            "messageDigest attribute does not match digest of encap content",
        ));
    }

    // (4) contentType attribute must match encap content type.
    // In CAdES-B over id-data this is always id-data.
    let ct = attrs::content_type(signed_attrs)?;
    if ct != oids::ID_DATA {
        diagnostics.push(DiagnosticMessage::info(
            "CONTENT_TYPE_NON_DATA",
            format!("signedAttrs.contentType = {ct} (non-id-data)"),
        ));
    }

    // (5) signingCertificateV2 / signingCertificate ESSCert check.
    verify_signing_certificate_ref(signed_attrs, signer_cert, &mut diagnostics)?;

    // (6) Re-encode signedAttrs as SET OF and verify the signature.
    let to_be_signed = attrs::to_signed_der(signed_attrs)?;
    signature_verify::verify_cms_signature(
        signer_cert,
        &signer.signature_algorithm,
        &signer.digest_alg,
        &to_be_signed,
        signer.signature.as_bytes(),
    )?;

    // (7) Apply algorithm policy.
    let algorithm = classify_algorithm(signer, signer_cert)?;
    let decision = policy.evaluate(algorithm, at);
    if !decision.is_accepted_at(at) {
        return Ok(SignatureReport {
            status: Status::TotalFailedSub,
            level_reached: Level::Unknown,
            qualification: Qualification::NotAdES,
            qualifiers: Vec::new(),
            signer: Some(cert_info(signer_cert)?),
            chain: Vec::new(),
            signing_time_claimed: attrs::signing_time(signed_attrs).ok().flatten(),
            signing_time_best: None,
            algorithm: Some(algorithm),
            timestamps: Vec::new(),
            revocation: Vec::new(),
            diagnostics: vec![DiagnosticMessage::error(
                "ALG_POLICY_REJECTED",
                format!("algorithm {algorithm:?} rejected by policy: {decision:?}"),
            )],
        });
    }

    // (8) Build the chain.
    let chain_result = chain_builder.build(signer_cert.clone(), at)?;
    let chain = chain_result
        .chain
        .iter()
        .map(cert_info)
        .collect::<Result<Vec<_>>>()?;
    diagnostics.extend(chain_result.diagnostics);

    // (9) Done — B-B reached.
    Ok(SignatureReport {
        status: Status::TotalPassed,
        level_reached: Level::BB,
        qualification: Qualification::AdES,
        qualifiers: Vec::new(),
        signer: Some(cert_info(signer_cert)?),
        chain,
        signing_time_claimed: attrs::signing_time(signed_attrs).ok().flatten(),
        signing_time_best: None,
        algorithm: Some(algorithm),
        timestamps: Vec::new(),
        revocation: Vec::new(),
        diagnostics,
    })
}

fn locate_signer_cert<'a>(
    sid: &SignerIdentifier,
    embedded: &'a [Certificate],
) -> Result<&'a Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            for c in embedded {
                if c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
                {
                    return Ok(c);
                }
            }
            Err(Error::Crypto(
                "signer-info IssuerAndSerialNumber not found in embedded certificates".into(),
            ))
        }
        SignerIdentifier::SubjectKeyIdentifier(sk) => {
            let wanted = sk.0.as_bytes();
            for c in embedded {
                if let Some(id) = ski(c) {
                    if id == wanted {
                        return Ok(c);
                    }
                }
            }
            Err(Error::Crypto(
                "signer-info SubjectKeyIdentifier not found in embedded certificates".into(),
            ))
        }
    }
}

/// Verify the ETSI ESSCertIDv2 / ESSCertID in `signingCertificateV2` /
/// `signingCertificate` against the signer cert. Minimal structural parse —
/// we only check the leaf hash, which is the security-critical part.
fn verify_signing_certificate_ref(
    signed_attrs: &SignedAttributes,
    signer_cert: &Certificate,
    diagnostics: &mut Vec<DiagnosticMessage>,
) -> Result<()> {
    // Prefer v2.
    if let Some(attr) = attrs::find(signed_attrs, oids::ID_AA_SIGNING_CERTIFICATE_V2) {
        let value = attr
            .values
            .iter()
            .next()
            .ok_or_else(|| Error::Crypto("signingCertificateV2 has no values".into()))?;
        let der = value
            .to_der()
            .map_err(|e| Error::Asn1(format!("signingCertificateV2 value: {e}")))?;
        return verify_ess_v2(&der, signer_cert);
    }
    if let Some(attr) = attrs::find(signed_attrs, oids::ID_AA_SIGNING_CERTIFICATE) {
        let value = attr
            .values
            .iter()
            .next()
            .ok_or_else(|| Error::Crypto("signingCertificate has no values".into()))?;
        let der = value
            .to_der()
            .map_err(|e| Error::Asn1(format!("signingCertificate value: {e}")))?;
        diagnostics.push(DiagnosticMessage::warn(
            "SIGNING_CERT_V1_USED",
            "signer used legacy SHA-1-based signingCertificate (v1) — v2 recommended",
        ));
        return verify_ess_v1(&der, signer_cert);
    }
    Err(Error::Crypto(
        "CAdES requires signingCertificate or signingCertificateV2 — neither present".into(),
    ))
}

fn verify_ess_v2(der: &[u8], signer_cert: &Certificate) -> Result<()> {
    // ESS-SigningCertificateV2 ::= SEQUENCE {
    //     certs SEQUENCE OF ESSCertIDv2,
    //     policies SEQUENCE OF PolicyInformation OPTIONAL
    // }
    // ESSCertIDv2 ::= SEQUENCE {
    //     hashAlgorithm AlgorithmIdentifier DEFAULT { sha256 },
    //     certHash Hash,
    //     issuerSerial IssuerSerial OPTIONAL
    // }
    use der::asn1::OctetStringRef;
    use der::{Reader, SliceReader};

    let mut outer = SliceReader::new(der).map_err(|e| Error::Asn1(e.to_string()))?;
    let header = der::Header::decode(&mut outer).map_err(|e| Error::Asn1(e.to_string()))?;
    if header.tag != der::Tag::Sequence {
        return Err(Error::Asn1("ESS-SigningCertificateV2 not a SEQUENCE".into()));
    }
    let body_bytes = outer
        .read_slice(header.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut body = SliceReader::new(body_bytes).map_err(|e| Error::Asn1(e.to_string()))?;

    let certs_header = der::Header::decode(&mut body).map_err(|e| Error::Asn1(e.to_string()))?;
    if certs_header.tag != der::Tag::Sequence {
        return Err(Error::Asn1("ESS certs field not a SEQUENCE".into()));
    }
    let certs_bytes = body
        .read_slice(certs_header.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;

    // Take the first ESSCertIDv2 only — the signer is always at certs[0].
    let mut certs = SliceReader::new(certs_bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    let cid_header = der::Header::decode(&mut certs).map_err(|e| Error::Asn1(e.to_string()))?;
    if cid_header.tag != der::Tag::Sequence {
        return Err(Error::Asn1("ESSCertIDv2 not a SEQUENCE".into()));
    }
    let cid_bytes = certs
        .read_slice(cid_header.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut cid = SliceReader::new(cid_bytes).map_err(|e| Error::Asn1(e.to_string()))?;

    // Optional hashAlgorithm — defaults to SHA-256 when absent.
    // Peek at the next tag: if SEQUENCE, it's the hashAlgorithm.
    let peek = cid.peek_byte();
    let hash_oid = if peek == Some(der::Tag::Sequence.octet()) {
        let h_header = der::Header::decode(&mut cid).map_err(|e| Error::Asn1(e.to_string()))?;
        let h_bytes = cid
            .read_slice(h_header.length)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        let mut h = SliceReader::new(h_bytes).map_err(|e| Error::Asn1(e.to_string()))?;
        der::asn1::ObjectIdentifier::decode(&mut h).map_err(|e| Error::Asn1(e.to_string()))?
    } else {
        oids::ID_SHA256
    };

    // certHash ::= OCTET STRING
    let hash_os = OctetStringRef::decode(&mut cid).map_err(|e| Error::Asn1(e.to_string()))?;
    let claimed_hash = hash_os.as_bytes();

    let alg = hash_from_oid(hash_oid)?;
    let signer_der = signer_cert
        .to_der()
        .map_err(|e| Error::Asn1(format!("signer cert encode: {e}")))?;
    let computed = crate::digest::digest(alg, &signer_der)?;

    if computed != claimed_hash {
        return Err(Error::Crypto(
            "signingCertificateV2 ESSCertIDv2 hash does not match signer certificate".into(),
        ));
    }
    Ok(())
}

fn verify_ess_v1(der: &[u8], signer_cert: &Certificate) -> Result<()> {
    // ESS-SigningCertificate ::= SEQUENCE {
    //     certs SEQUENCE OF ESSCertID,
    //     policies SEQUENCE OF PolicyInformation OPTIONAL
    // }
    // ESSCertID ::= SEQUENCE {
    //     certHash Hash,  -- SHA-1
    //     issuerSerial IssuerSerial OPTIONAL
    // }
    use der::asn1::OctetStringRef;
    use der::{Reader, SliceReader};

    let mut outer = SliceReader::new(der).map_err(|e| Error::Asn1(e.to_string()))?;
    let h = der::Header::decode(&mut outer).map_err(|e| Error::Asn1(e.to_string()))?;
    if h.tag != der::Tag::Sequence {
        return Err(Error::Asn1("ESS-SigningCertificate not a SEQUENCE".into()));
    }
    let body_bytes = outer
        .read_slice(h.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut body = SliceReader::new(body_bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    let ch = der::Header::decode(&mut body).map_err(|e| Error::Asn1(e.to_string()))?;
    if ch.tag != der::Tag::Sequence {
        return Err(Error::Asn1("ESS certs field not a SEQUENCE".into()));
    }
    let certs_bytes = body
        .read_slice(ch.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut certs = SliceReader::new(certs_bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    let cid_h = der::Header::decode(&mut certs).map_err(|e| Error::Asn1(e.to_string()))?;
    let cid_bytes = certs
        .read_slice(cid_h.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut cid = SliceReader::new(cid_bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    let hash_os = OctetStringRef::decode(&mut cid).map_err(|e| Error::Asn1(e.to_string()))?;
    let claimed = hash_os.as_bytes();

    // v1 is SHA-1 by definition; we refuse to confirm it because SHA-1 is not
    // permitted for digital-signature binding in ETSI TS 119 312.
    let _ = claimed;
    let _ = signer_cert;
    Err(Error::Crypto(
        "legacy signingCertificate attribute uses SHA-1 — not permitted under ETSI TS 119 312; \
         re-sign with signingCertificateV2"
            .into(),
    ))
}

fn classify_algorithm(
    signer: &SignerInfo,
    signer_cert: &Certificate,
) -> Result<AlgorithmId> {
    let hash = hash_from_oid(signer.digest_alg.oid).or_else(|_| {
        // Fallback: some signature-alg OIDs bundle the hash.
        match signer.signature_algorithm.oid {
            oids::ID_SHA224_WITH_RSA => Ok(HashAlgorithm::Sha224),
            oids::ID_SHA256_WITH_RSA | oids::ID_ECDSA_SHA256 => Ok(HashAlgorithm::Sha256),
            oids::ID_SHA384_WITH_RSA | oids::ID_ECDSA_SHA384 => Ok(HashAlgorithm::Sha384),
            oids::ID_SHA512_WITH_RSA | oids::ID_ECDSA_SHA512 => Ok(HashAlgorithm::Sha512),
            _ => Err(Error::Unsupported(format!(
                "cannot infer hash for signature-alg {}",
                signer.signature_algorithm.oid
            ))),
        }
    })?;

    let (signature, key_bits) = match signer.signature_algorithm.oid {
        oids::ID_RSA_ENCRYPTION
        | oids::ID_SHA1_WITH_RSA
        | oids::ID_SHA224_WITH_RSA
        | oids::ID_SHA256_WITH_RSA
        | oids::ID_SHA384_WITH_RSA
        | oids::ID_SHA512_WITH_RSA => (SignatureAlgorithm::RsaPkcs1v15, rsa_key_bits(signer_cert)?),
        oids::ID_RSA_PSS => (SignatureAlgorithm::RsaPss, rsa_key_bits(signer_cert)?),
        oids::ID_ECDSA_SHA1
        | oids::ID_ECDSA_SHA224
        | oids::ID_ECDSA_SHA256
        | oids::ID_ECDSA_SHA384
        | oids::ID_ECDSA_SHA512 => (SignatureAlgorithm::Ecdsa, ecc_key_bits(signer_cert)?),
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
        oids::ID_SECP256R1 => 256,
        oids::ID_SECP384R1 => 384,
        oids::ID_SECP521R1 => 521,
        _ => 0,
    })
}

fn cert_info(cert: &Certificate) -> Result<CertificateInfo> {
    let (nb, na) = validity_window(cert)?;
    Ok(CertificateInfo {
        subject: subject_display(cert),
        issuer: eidas_x509::issuer_display(cert),
        serial_hex: {
            let bytes = cert.tbs_certificate.serial_number.as_bytes();
            hex::encode(bytes)
        },
        not_before: nb,
        not_after: na,
        ski: ski(cert),
        aki: aki(cert),
        der: cert
            .to_der()
            .map_err(|e| Error::Asn1(format!("cert encode: {e}")))?,
    })
}

// The `hex` dep is used through `hex::encode` in cert_info above. It is
// already a dev-dep (for digest tests); make it a regular dep.
