//! JAdES verification entrypoint.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use der::{Decode, Encode};
use eidas_core::{
    AlgorithmId, AlgorithmPolicy, CertificateInfo, ContainerInfo, DiagnosticMessage, Error,
    HashAlgorithm, Level, Qualification, Result, SignatureAlgorithm, SignatureReport, Status,
    ValidationTime, VerificationReport,
};
use eidas_x509::chain::ChainBuilder;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;

use crate::jws::{JwsHeader, JwsSignature};

/// Caller-supplied JAdES input.
pub struct JadesInput<'a> {
    /// Compact form (`header.payload.signature`) or flattened-JSON form.
    pub bytes: &'a [u8],
    /// `true` if `bytes` is JSON; `false` for compact.
    pub is_json: bool,
}

/// Verify a JAdES signature.
pub fn verify_jades(
    input: &JadesInput<'_>,
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<VerificationReport> {
    let jws = if input.is_json {
        JwsSignature::from_flattened_json(input.bytes)?
    } else {
        let text = std::str::from_utf8(input.bytes)
            .map_err(|e| Error::Json(format!("JWS compact is not UTF-8: {e}")))?;
        JwsSignature::from_compact(text.trim())?
    };

    let rpt = verify_one(&jws, chain_builder, policy, validation_time);
    Ok(VerificationReport {
        signatures: vec![rpt],
        container: Some(ContainerInfo::Jws {
            encoding: if input.is_json { "flattened-json".into() } else { "compact".into() },
        }),
    })
}

fn verify_one(
    jws: &JwsSignature,
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> SignatureReport {
    match verify_one_inner(jws, chain_builder, policy, validation_time) {
        Ok(r) => r,
        Err(e) => SignatureReport::failed("JADES_VERIFICATION_ERROR", e.to_string()),
    }
}

fn verify_one_inner(
    jws: &JwsSignature,
    chain_builder: &ChainBuilder,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<SignatureReport> {
    let mut diagnostics = Vec::new();

    // 1. Locate the signer cert (first entry in `x5c`).
    let signer = jws
        .signer_certificate()?
        .ok_or_else(|| Error::Crypto("JAdES header has no x5c cert chain".into()))?;

    // 2. x5t#S256 binding: SHA-256 of the signer cert must match the header.
    enforce_x5t_s256(&jws.header, &signer, &mut diagnostics)?;

    // 3. Verify the signature over `h.p` with the declared alg.
    let (signature_family, hash, key_bits) =
        verify_jws_signature(&signer, &jws.header.alg, &jws.signing_input(), &jws.signature)?;

    // 4. Algorithm policy check.
    let algorithm = AlgorithmId {
        signature: signature_family,
        hash,
        key_bits,
    };
    let signing_time_claimed = jws
        .header
        .sig_t
        .as_deref()
        .and_then(parse_sig_t);

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
            signing_time_claimed,
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

    // 5. Build and validate the chain — intermediates come from x5c tail.
    let mut extra_intermediates = Vec::new();
    if let Some(chain) = &jws.header.x5c {
        for (i, entry) in chain.iter().enumerate() {
            if i == 0 {
                continue; // signer already found
            }
            use base64::engine::general_purpose::STANDARD as B64;
            let der = B64
                .decode(entry.as_bytes())
                .map_err(|e| Error::Json(format!("x5c[{i}] b64: {e}")))?;
            let cert = Certificate::from_der(&der)
                .map_err(|e| Error::Asn1(format!("x5c[{i}] DER: {e}")))?;
            extra_intermediates.push(cert);
        }
    }
    let effective_builder = extend_builder(chain_builder, extra_intermediates);
    let chain_result = effective_builder
        .build(signer.clone(), reference_time)
        .map_err(|e| Error::Chain(format!("JAdES chain: {e}")))?;
    diagnostics.extend(chain_result.diagnostics.clone());
    let chain_infos = chain_result
        .chain
        .iter()
        .map(cert_info)
        .collect::<Result<Vec<_>>>()?;

    // 6. Informational diagnostic if a sigTst is present; full B-T lift is
    //    deferred.
    if jws.header.sig_tst.is_some() {
        diagnostics.push(DiagnosticMessage::info(
            "JADES_SIG_TST_NOT_VERIFIED",
            "sigTst header present but B-T timestamp verification for JAdES is deferred",
        ));
    }

    Ok(SignatureReport {
        status: Status::TotalPassed,
        level_reached: Level::BB,
        qualification: Qualification::AdES,
        qualifiers: Vec::new(),
        signer: Some(cert_info(&signer)?),
        chain: chain_infos,
        signing_time_claimed,
        signing_time_best: None,
        algorithm: Some(algorithm),
        timestamps: Vec::new(),
        revocation: Vec::new(),
        diagnostics,
    })
}

fn extend_builder(base: &ChainBuilder, extras: Vec<Certificate>) -> ChainBuilder {
    // ChainBuilder doesn't expose its anchors/intermediates for clone, so we
    // build on top of the supplied one by pushing extra intermediates.
    // Because ChainBuilder::with_intermediates takes ownership by value, we
    // reconstruct via Clone on the base.
    let mut b = base.clone();
    for c in extras {
        b.push_intermediate(c);
    }
    b
}

fn enforce_x5t_s256(
    header: &JwsHeader,
    cert: &Certificate,
    diagnostics: &mut Vec<DiagnosticMessage>,
) -> Result<()> {
    let Some(claimed) = header.x5t_s256.as_deref() else {
        // JAdES requires x5t#S256. Hard fail.
        return Err(Error::Crypto(
            "JAdES requires the `x5t#S256` header — header absent".into(),
        ));
    };
    let claimed_bytes = URL_SAFE_NO_PAD
        .decode(claimed)
        .map_err(|e| Error::Json(format!("x5t#S256 b64url: {e}")))?;
    let der = cert
        .to_der()
        .map_err(|e| Error::Asn1(format!("cert DER: {e}")))?;
    let computed: Vec<u8> = Sha256::digest(&der).to_vec();
    if computed != claimed_bytes {
        return Err(Error::Crypto(
            "x5t#S256 header does not match SHA-256 of the signer certificate".into(),
        ));
    }
    let _ = diagnostics;
    Ok(())
}

fn verify_jws_signature(
    cert: &Certificate,
    alg: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(SignatureAlgorithm, HashAlgorithm, u32)> {
    match alg {
        "RS256" | "RS384" | "RS512" => {
            let hash = match alg {
                "RS256" => HashAlgorithm::Sha256,
                "RS384" => HashAlgorithm::Sha384,
                _ => HashAlgorithm::Sha512,
            };
            let key_bits = rsa_verify(cert, hash, signing_input, signature)?;
            Ok((SignatureAlgorithm::RsaPkcs1v15, hash, key_bits))
        }
        "ES256" => {
            let key_bits = ecdsa_verify_p256(cert, signing_input, signature)?;
            Ok((SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256, key_bits))
        }
        "ES384" => {
            let key_bits = ecdsa_verify_p384(cert, signing_input, signature)?;
            Ok((SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha384, key_bits))
        }
        other => Err(Error::Unsupported(format!(
            "JAdES alg `{other}` not supported in Phase 10 (try RS256/RS384/RS512 or ES256/ES384)"
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
        .map_err(|e| Error::Asn1(format!("SPKI encode: {e}")))?;
    let pk = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| Error::Crypto(format!("RSA public key decode: {e}")))?;
    let key_bits = u32::try_from(pk.n().bits()).unwrap_or(u32::MAX);
    let sig = RsaSig::try_from(signature)
        .map_err(|e| Error::Crypto(format!("RSA signature parse: {e}")))?;
    match hash {
        HashAlgorithm::Sha256 => VerifyingKey::<Sha256>::new(pk).verify(data, &sig),
        HashAlgorithm::Sha384 => VerifyingKey::<Sha384>::new(pk).verify(data, &sig),
        HashAlgorithm::Sha512 => VerifyingKey::<Sha512>::new(pk).verify(data, &sig),
        _ => {
            return Err(Error::Unsupported(format!(
                "RSA hash {hash:?} not supported for JAdES"
            )))
        }
    }
    .map_err(|e| Error::Crypto(format!("RSA signature verification failed: {e}")))?;
    Ok(key_bits)
}

fn ecdsa_verify_p256(cert: &Certificate, data: &[u8], signature: &[u8]) -> Result<u32> {
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk};
    use signature::hazmat::PrehashVerifier;
    use spki::SubjectPublicKeyInfoRef;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI encode: {e}")))?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| Error::Asn1(format!("SPKI parse: {e}")))?;
    let vk = P256Vk::try_from(spki_ref)
        .map_err(|e| Error::Crypto(format!("P-256 key decode: {e}")))?;
    // JWS ES256 signatures are raw r||s (64 bytes), not DER.
    let sig = P256Sig::try_from(signature)
        .map_err(|e| Error::Crypto(format!("ES256 sig parse (expected 64 bytes raw): {e}")))?;
    let prehash = Sha256::digest(data);
    vk.verify_prehash(&prehash, &sig)
        .map_err(|e| Error::Crypto(format!("ES256 verification failed: {e}")))?;
    Ok(256)
}

fn ecdsa_verify_p384(cert: &Certificate, data: &[u8], signature: &[u8]) -> Result<u32> {
    use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Vk};
    use signature::hazmat::PrehashVerifier;
    use spki::SubjectPublicKeyInfoRef;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("SPKI encode: {e}")))?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| Error::Asn1(format!("SPKI parse: {e}")))?;
    let vk = P384Vk::try_from(spki_ref)
        .map_err(|e| Error::Crypto(format!("P-384 key decode: {e}")))?;
    let sig = P384Sig::try_from(signature)
        .map_err(|e| Error::Crypto(format!("ES384 sig parse (expected 96 bytes raw): {e}")))?;
    let prehash = Sha384::digest(data);
    vk.verify_prehash(&prehash, &sig)
        .map_err(|e| Error::Crypto(format!("ES384 verification failed: {e}")))?;
    Ok(384)
}

fn parse_sig_t(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
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
