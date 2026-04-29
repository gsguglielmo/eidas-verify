//! XAdES verification entrypoint.

use chrono::{DateTime, Utc};
use der::Encode;
use eidas_core::{
    AlgorithmId, AlgorithmPolicy, CertificateInfo, ContainerInfo, DiagnosticMessage, Error,
    HashAlgorithm, Level, Qualification, Result, SignatureAlgorithm, SignatureReport, Status,
    ValidationTime, VerificationReport,
};
use eidas_x509::chain::ChainBuilder;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;

use crate::c14n::{exc_c14n_with_envelope_strip, EnvelopeTarget};
use crate::parse::{parse_xml_signature, ParsedSignature};

/// Narrow-profile XMLDSig URIs we accept.
mod uris {
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    pub const ENVELOPED_SIG: &str =
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    pub const ECDSA_SHA256: &str =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    pub const ECDSA_SHA384: &str =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
}

/// Caller-supplied XAdES input.
pub struct XadesInput<'a> {
    /// The XML document carrying an enveloped `<ds:Signature>`.
    pub xml: &'a [u8],
}

/// Verify an enveloped XAdES signature.
pub fn verify_xades(
    input: &XadesInput<'_>,
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<VerificationReport> {
    let parsed = parse_xml_signature(input.xml)?;
    let rpt = verify_one(&parsed, input.xml, chain_builder, policy, validation_time);
    Ok(VerificationReport {
        signatures: vec![rpt],
        container: Some(ContainerInfo::Jws {
            encoding: "xmldsig-enveloped".into(),
        }),
    })
}

fn verify_one(
    parsed: &ParsedSignature,
    full_xml: &[u8],
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> SignatureReport {
    match verify_one_inner(parsed, full_xml, chain_builder, policy, validation_time) {
        Ok(r) => r,
        Err(e) => SignatureReport::failed("XADES_VERIFICATION_ERROR", e.to_string()),
    }
}

fn verify_one_inner(
    parsed: &ParsedSignature,
    full_xml: &[u8],
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<SignatureReport> {
    let mut diagnostics = Vec::new();

    // --- Profile checks. ---
    if parsed.canonicalization_method != uris::EXC_C14N {
        return Err(Error::Unsupported(format!(
            "CanonicalizationMethod `{}` outside narrow XAdES profile (need {})",
            parsed.canonicalization_method,
            uris::EXC_C14N,
        )));
    }
    if !parsed.reference_transforms.is_empty() {
        let enveloped = parsed
            .reference_transforms
            .iter()
            .any(|u| u == uris::ENVELOPED_SIG);
        let xcn = parsed
            .reference_transforms
            .iter()
            .any(|u| u == uris::EXC_C14N);
        let others: Vec<_> = parsed
            .reference_transforms
            .iter()
            .filter(|u| u.as_str() != uris::ENVELOPED_SIG && u.as_str() != uris::EXC_C14N)
            .collect();
        if !others.is_empty() {
            return Err(Error::Unsupported(format!(
                "unsupported Transforms in XAdES profile: {others:?}"
            )));
        }
        let _ = (enveloped, xcn);
    }

    // --- Signer cert from KeyInfo. ---
    let signer = parsed.signer_cert.clone().ok_or_else(|| {
        Error::Crypto("XAdES KeyInfo has no X509Certificate".into())
    })?;

    // --- Step 1: compute the Reference digest (the bytes the signer
    // committed to). For URI="" this is the root, canonicalised with the
    // enveloped-signature transform applied if listed.
    let digest_alg = xml_digest_alg(&parsed.reference_digest_method)?;
    let reference_input = if parsed
        .reference_transforms
        .iter()
        .any(|u| u == uris::ENVELOPED_SIG)
    {
        exc_c14n_with_envelope_strip(
            full_xml,
            Some(EnvelopeTarget {
                local: b"Signature",
                namespace: None,
            }),
        )?
    } else {
        exc_c14n_with_envelope_strip(full_xml, None)?
    };
    let computed_digest = digest_bytes(digest_alg, &reference_input);
    if computed_digest != parsed.reference_digest_value {
        return Ok(SignatureReport::failed(
            "REFERENCE_DIGEST_MISMATCH",
            "XAdES Reference DigestValue does not match the canonicalised document",
        ));
    }

    // --- Step 2: verify the SignatureValue over the canonicalised SignedInfo. ---
    let signed_info_c14n = canonicalise_signed_info(full_xml)?;
    let (family, hash, key_bits) = verify_xmldsig_signature(
        &signer,
        &parsed.signature_method,
        &signed_info_c14n,
        &parsed.signature_value,
    )?;

    let algorithm = AlgorithmId { signature: family, hash, key_bits };

    // --- Policy + chain. ---
    let reference_time = validation_time.resolve(None);
    let decision = policy.evaluate(algorithm, reference_time);
    if !decision.is_accepted_at(reference_time) {
        return Ok(SignatureReport {
            status: Status::TotalFailedSub,
            level_reached: Level::Unknown,
            qualification: Qualification::NotAdES,
            qualifiers: Vec::new(),
            signer: Some(cert_info(&signer)?),
            chain: Vec::new(),
            signing_time_claimed: None,
            signing_time_best: None,
            algorithm: Some(algorithm),
            timestamps: Vec::new(),
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
    let chain = chain_builder
        .build(signer.clone(), reference_time)
        .map_err(|e| Error::Chain(format!("XAdES chain: {e}")))?;
    let chain_infos = chain.chain.iter().map(cert_info).collect::<Result<Vec<_>>>()?;
    diagnostics.extend(chain.diagnostics);

    diagnostics.push(DiagnosticMessage::warn(
        "XADES_NARROW_PROFILE",
        "verified under eidas-xades' narrow profile (enveloped signature, exc-c14n, \
         no DTD/XPath); full XMLDSig compliance requires the deferred libxml2/xmlsec1 backend",
    ));

    Ok(SignatureReport {
        status: Status::TotalPassed,
        level_reached: Level::BB,
        qualification: Qualification::AdES,
        qualifiers: Vec::new(),
        signer: Some(cert_info(&signer)?),
        chain: chain_infos,
        signing_time_claimed: None,
        signing_time_best: None,
        algorithm: Some(algorithm),
        timestamps: Vec::new(),
        revocation: Vec::new(),
        diagnostics,
    })
}

/// Canonicalise the `<SignedInfo>` subtree in isolation.
///
/// We extract the element by a simple byte scan — this works because the
/// narrow profile guarantees `<SignedInfo>` is a top-level child of
/// `<Signature>` with no CDATA that could embed the tag.
fn canonicalise_signed_info(full_xml: &[u8]) -> Result<Vec<u8>> {
    let start = find_tag(full_xml, b"SignedInfo")
        .ok_or_else(|| Error::Xml("cannot locate <SignedInfo> opener".into()))?;
    let end_close = find_tag(&full_xml[start..], b"/SignedInfo")
        .ok_or_else(|| Error::Xml("cannot locate </SignedInfo>".into()))?;
    // `end_close` points at `<`; skip past the closing `>`.
    let end_after_gt = &full_xml[start..];
    let gt = end_after_gt[end_close..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or_else(|| Error::Xml("malformed </SignedInfo>".into()))?;
    let end = start + end_close + gt + 1;
    let subtree = &full_xml[start..end];
    exc_c14n_with_envelope_strip(subtree, None)
}

fn find_tag(xml: &[u8], tag: &[u8]) -> Option<usize> {
    // Match `<tag` or `<tag ` or `<tag>` or `<tag/`.
    let mut needle = Vec::with_capacity(tag.len() + 1);
    needle.push(b'<');
    needle.extend_from_slice(tag);
    for i in 0..xml.len().saturating_sub(needle.len()) {
        if xml[i..].starts_with(&needle) {
            let next = xml[i + needle.len()];
            if next == b' ' || next == b'>' || next == b'/' || next == b'\n' || next == b'\r' || next == b'\t' {
                return Some(i);
            }
        }
    }
    None
}

fn xml_digest_alg(uri: &str) -> Result<HashAlgorithm> {
    Ok(match uri {
        u if u == uris::SHA256 => HashAlgorithm::Sha256,
        u if u == uris::SHA384 => HashAlgorithm::Sha384,
        u if u == uris::SHA512 => HashAlgorithm::Sha512,
        other => {
            return Err(Error::Unsupported(format!(
                "XAdES DigestMethod `{other}` not supported in narrow profile"
            )))
        }
    })
}

fn digest_bytes(alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        _ => Vec::new(),
    }
}

fn verify_xmldsig_signature(
    cert: &Certificate,
    sig_method: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(SignatureAlgorithm, HashAlgorithm, u32)> {
    match sig_method {
        u if u == uris::RSA_SHA256 => {
            let bits = rsa_verify(cert, HashAlgorithm::Sha256, signing_input, signature)?;
            Ok((SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha256, bits))
        }
        u if u == uris::RSA_SHA384 => {
            let bits = rsa_verify(cert, HashAlgorithm::Sha384, signing_input, signature)?;
            Ok((SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha384, bits))
        }
        u if u == uris::RSA_SHA512 => {
            let bits = rsa_verify(cert, HashAlgorithm::Sha512, signing_input, signature)?;
            Ok((SignatureAlgorithm::RsaPkcs1v15, HashAlgorithm::Sha512, bits))
        }
        u if u == uris::ECDSA_SHA256 => {
            let bits = ecdsa_p256_verify(cert, signing_input, signature)?;
            Ok((SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256, bits))
        }
        u if u == uris::ECDSA_SHA384 => {
            let bits = ecdsa_p384_verify(cert, signing_input, signature)?;
            Ok((SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha384, bits))
        }
        other => Err(Error::Unsupported(format!(
            "XAdES SignatureMethod `{other}` not supported in narrow profile"
        ))),
    }
}

fn rsa_verify(
    cert: &Certificate,
    hash: HashAlgorithm,
    data: &[u8],
    signature: &[u8],
) -> Result<u32> {
    use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPublicKey;
    use signature::Verifier;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI: {e}")))?;
    let pk = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| Error::Crypto(format!("RSA key decode: {e}")))?;
    let bits = u32::try_from(pk.n().bits()).unwrap_or(u32::MAX);
    let sig = RsaSig::try_from(signature)
        .map_err(|e| Error::Crypto(format!("RSA sig parse: {e}")))?;
    match hash {
        HashAlgorithm::Sha256 => VerifyingKey::<Sha256>::new(pk).verify(data, &sig),
        HashAlgorithm::Sha384 => VerifyingKey::<Sha384>::new(pk).verify(data, &sig),
        HashAlgorithm::Sha512 => VerifyingKey::<Sha512>::new(pk).verify(data, &sig),
        _ => {
            return Err(Error::Unsupported(format!(
                "RSA hash {hash:?} not supported"
            )))
        }
    }
    .map_err(|e| Error::Crypto(format!("RSA verification failed: {e}")))?;
    Ok(bits)
}

fn ecdsa_p256_verify(cert: &Certificate, data: &[u8], signature: &[u8]) -> Result<u32> {
    use p256::ecdsa::{Signature as Sig, VerifyingKey as Vk};
    use signature::hazmat::PrehashVerifier;
    use spki::SubjectPublicKeyInfoRef;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI: {e}")))?;
    let spki = SubjectPublicKeyInfoRef::try_from(spki_der.as_slice())
        .map_err(|e| Error::Asn1(format!("SPKI parse: {e}")))?;
    let vk = Vk::try_from(spki)
        .map_err(|e| Error::Crypto(format!("P-256 key decode: {e}")))?;
    // XMLDSig ECDSA signatures are raw r||s (RFC 6931 §2.3.2).
    let sig = Sig::try_from(signature)
        .map_err(|e| Error::Crypto(format!("ECDSA sig parse (expected raw r||s): {e}")))?;
    let prehash = Sha256::digest(data);
    vk.verify_prehash(&prehash, &sig)
        .map_err(|e| Error::Crypto(format!("ECDSA verification failed: {e}")))?;
    Ok(256)
}

fn ecdsa_p384_verify(cert: &Certificate, data: &[u8], signature: &[u8]) -> Result<u32> {
    use p384::ecdsa::{Signature as Sig, VerifyingKey as Vk};
    use signature::hazmat::PrehashVerifier;
    use spki::SubjectPublicKeyInfoRef;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI: {e}")))?;
    let spki = SubjectPublicKeyInfoRef::try_from(spki_der.as_slice())
        .map_err(|e| Error::Asn1(format!("SPKI parse: {e}")))?;
    let vk = Vk::try_from(spki)
        .map_err(|e| Error::Crypto(format!("P-384 key decode: {e}")))?;
    let sig = Sig::try_from(signature)
        .map_err(|e| Error::Crypto(format!("ECDSA sig parse: {e}")))?;
    let prehash = Sha384::digest(data);
    vk.verify_prehash(&prehash, &sig)
        .map_err(|e| Error::Crypto(format!("ECDSA verification failed: {e}")))?;
    Ok(384)
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

// Silence unused-chrono import warning when no datetime fields are handled yet.
#[allow(dead_code)]
fn _keep_chrono(_: DateTime<Utc>) {}
