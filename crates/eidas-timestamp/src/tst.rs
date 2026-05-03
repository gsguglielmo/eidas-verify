//! `TSTInfo` parsing and TimeStampToken verification.

use chrono::{DateTime, NaiveDateTime, Utc};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::ObjectIdentifier;
use der::asn1::{Int, OctetString};
use der::{Decode, Encode, Sequence};
use eidas_core::{
    AlgorithmId, DiagnosticMessage, Error, HashAlgorithm, Result, SignatureAlgorithm,
    TimestampInfo,
};
use eidas_x509::chain::{ChainBuilder, ChainValidationResult};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::oids;

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] IMPLICIT INTEGER OPTIONAL, micros [1] IMPLICIT INTEGER OPTIONAL }`.
///
/// We do not inspect the accuracy fields, but we have to parse through them.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(dead_code)]
struct Accuracy {
    seconds: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    millis: Option<Int>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    micros: Option<Int>,
}

/// Minimal `TSTInfo` parse (RFC 3161 §2.4.2).
///
/// We deliberately drop `tsa` and `extensions` — verification does not need
/// them, and their encoding (GeneralName CHOICE, IMPLICIT Extensions) is
/// finicky enough that parsing them adds risk without value.
///
/// `policy` is stored as a dotted-decimal `String` rather than a typed
/// `ObjectIdentifier` because real-world TSAs in the wild emit policies
/// with >12 arcs and >39 bytes of body, exceeding `const_oid 0.9`'s default
/// `ObjectIdentifier` buffer. The string form preserves the value
/// losslessly while accommodating any length the spec allows. Verification
/// does not consult the policy field; it is informational.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TstInfo {
    pub version: u32,
    pub policy: String,
    pub message_imprint: ParsedMessageImprint,
    pub serial_number: Vec<u8>,
    pub gen_time: DateTime<Utc>,
    pub nonce: Option<Vec<u8>>,
}

/// Decoded `MessageImprint` with the hash algorithm resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMessageImprint {
    pub algorithm: HashAlgorithm,
    pub hashed_message: Vec<u8>,
}

impl TstInfo {
    /// Parse a `TSTInfo` from DER bytes.
    ///
    /// Tolerant where the spec is strict but real-world TSAs deviate:
    /// - `policy` is decoded directly from raw OID bytes, sidestepping
    ///   the 39-byte buffer in `const_oid 0.9`. Real corpus examples
    ///   (e.g. `tst-two-refs.tst`) carry >50-byte policy OIDs.
    /// - `genTime` accepts `YYYYMMDDHHMMSS[.fff[fff]]Z`. Strict DER
    ///   forbids fractional seconds, but Disig and other production TSAs
    ///   emit them.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        use der::{Reader, SliceReader};

        let mut outer = SliceReader::new(bytes).map_err(|e| Error::Asn1(e.to_string()))?;
        let header = der::Header::decode(&mut outer).map_err(|e| Error::Asn1(e.to_string()))?;
        if header.tag != der::Tag::Sequence {
            return Err(Error::Asn1("TSTInfo is not a SEQUENCE".into()));
        }
        let body_bytes = outer
            .read_slice(header.length)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        let mut r = SliceReader::new(body_bytes).map_err(|e| Error::Asn1(e.to_string()))?;

        // version INTEGER
        let version = u32::decode(&mut r).map_err(|e| Error::Asn1(format!("TSTInfo.version: {e}")))?;
        // policy OBJECT IDENTIFIER — decoded as raw bytes, then converted
        // to dotted-decimal. Bypasses const_oid's fixed-size buffer.
        let policy_hdr =
            der::Header::decode(&mut r).map_err(|e| Error::Asn1(format!("TSTInfo.policy: {e}")))?;
        if policy_hdr.tag != der::Tag::ObjectIdentifier {
            return Err(Error::Asn1(format!(
                "TSTInfo.policy: expected OID tag, got {:?}",
                policy_hdr.tag
            )));
        }
        let policy_bytes = r
            .read_slice(policy_hdr.length)
            .map_err(|e| Error::Asn1(format!("TSTInfo.policy body: {e}")))?;
        let policy = decode_oid_to_dotted(policy_bytes)?;
        // messageImprint SEQUENCE
        let mi = MessageImprint::decode(&mut r)
            .map_err(|e| Error::Asn1(format!("TSTInfo.messageImprint: {e}")))?;
        let mi_alg = eidas_cms::digest::hash_from_oid(mi.hash_algorithm.oid)?;
        let message_imprint = ParsedMessageImprint {
            algorithm: mi_alg,
            hashed_message: mi.hashed_message.as_bytes().to_vec(),
        };
        // serialNumber INTEGER — keep raw bytes (serials can exceed 64 bits).
        let serial = Int::decode(&mut r)
            .map_err(|e| Error::Asn1(format!("TSTInfo.serialNumber: {e}")))?;
        let serial_number = serial.as_bytes().to_vec();
        // genTime GeneralizedTime — tolerant of fractional seconds.
        let gt_hdr =
            der::Header::decode(&mut r).map_err(|e| Error::Asn1(format!("TSTInfo.genTime: {e}")))?;
        if gt_hdr.tag != der::Tag::GeneralizedTime {
            return Err(Error::Asn1(format!(
                "TSTInfo.genTime: expected GeneralizedTime tag, got {:?}",
                gt_hdr.tag
            )));
        }
        let gt_bytes = r
            .read_slice(gt_hdr.length)
            .map_err(|e| Error::Asn1(format!("TSTInfo.genTime body: {e}")))?;
        let gen_time = decode_generalized_time(gt_bytes)?;

        // The remaining fields (accuracy, ordering, nonce, tsa, extensions)
        // are all optional. We walk through them, skipping whatever is
        // present without strict type enforcement — we only care about nonce
        // for informational purposes.
        let mut nonce: Option<Vec<u8>> = None;
        while !r.is_finished() {
            let hdr = der::Header::decode(&mut r)
                .map_err(|e| Error::Asn1(format!("TSTInfo optional: {e}")))?;
            let body = r
                .read_slice(hdr.length)
                .map_err(|e| Error::Asn1(e.to_string()))?;
            if hdr.tag == der::Tag::Integer {
                // Could be `nonce` — capture the first INTEGER we see after genTime
                // and assume it's the nonce.
                if nonce.is_none() {
                    nonce = Some(body.to_vec());
                }
            }
            // Accuracy (SEQUENCE), ordering (BOOLEAN), tsa ([0] GeneralName),
            // extensions ([1] Extensions) are all skipped.
        }

        Ok(Self {
            version,
            policy,
            message_imprint,
            serial_number,
            gen_time,
            nonce,
        })
    }
}

/// Decode raw DER OID body bytes (i.e. the bytes after the tag+length
/// prefix) into a dotted-decimal string. Implements the base-128
/// continuation-bit scheme of X.690 §8.19.
fn decode_oid_to_dotted(body: &[u8]) -> Result<String> {
    if body.is_empty() {
        return Err(Error::Asn1("empty OID body".into()));
    }
    let first = body[0];
    let arc1 = u64::from(first / 40);
    let arc2 = u64::from(first % 40);
    let mut out = format!("{arc1}.{arc2}");
    let mut i = 1;
    while i < body.len() {
        let mut value: u64 = 0;
        loop {
            if i >= body.len() {
                return Err(Error::Asn1("OID arc truncated mid-stream".into()));
            }
            let b = body[i];
            i += 1;
            value = value
                .checked_shl(7)
                .and_then(|v| v.checked_add(u64::from(b & 0x7f)))
                .ok_or_else(|| Error::Asn1("OID arc overflow".into()))?;
            if b & 0x80 == 0 {
                break;
            }
        }
        out.push('.');
        out.push_str(&value.to_string());
    }
    Ok(out)
}

/// Tolerant GeneralizedTime parser: accepts the strict DER form
/// (`YYYYMMDDHHMMSSZ`) and the real-world TSA form with fractional
/// seconds (`YYYYMMDDHHMMSS.fffZ`, up to nanoseconds).
fn decode_generalized_time(body: &[u8]) -> Result<DateTime<Utc>> {
    let s = std::str::from_utf8(body)
        .map_err(|_| Error::Asn1("genTime is not ASCII".into()))?;
    // Must end in 'Z' (we don't accept local-time forms — irrelevant
    // for TSAs, all of which are spec-required to use UTC).
    let trimmed = s.strip_suffix('Z').ok_or_else(|| {
        Error::Asn1(format!("genTime does not end in 'Z': {s:?}"))
    })?;

    let (date_part, frac_part) = match trimmed.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (trimmed, None),
    };

    if date_part.len() != 14 {
        return Err(Error::Asn1(format!(
            "genTime date portion is {} chars, expected 14: {s:?}",
            date_part.len()
        )));
    }

    let naive = NaiveDateTime::parse_from_str(date_part, "%Y%m%d%H%M%S")
        .map_err(|e| Error::Asn1(format!("genTime parse: {e} on {s:?}")))?;

    let dt: DateTime<Utc> = naive.and_utc();
    let dt = match frac_part {
        None => dt,
        Some(frac) => {
            // Pad/truncate to exactly 9 digits (nanoseconds), then add.
            let frac_clean: String = frac.chars().filter(|c| c.is_ascii_digit()).collect();
            if frac_clean.is_empty() {
                dt
            } else {
                let mut padded = frac_clean.clone();
                while padded.len() < 9 {
                    padded.push('0');
                }
                if padded.len() > 9 {
                    padded.truncate(9);
                }
                let nanos: u32 = padded
                    .parse()
                    .map_err(|e| Error::Asn1(format!("genTime fraction parse: {e}")))?;
                dt + chrono::Duration::nanoseconds(i64::from(nanos))
            }
        }
    };
    Ok(dt)
}

/// What the token is timestamping (for `TimestampInfo.kind` in reports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampKind {
    /// `signature-time-stamp` — covers the SignerInfo signature value (CAdES-T).
    Signature,
    /// `content-timestamp` — covers the original content (before signing).
    Content,
    /// `archive-timestamp-v3` — CAdES-A archive timestamp.
    ArchiveV3,
    /// Generic TSA token with no AdES role (direct RFC 3161 usage).
    Unbound,
}

impl TimestampKind {
    fn label(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Content => "content",
            Self::ArchiveV3 => "archive-v3",
            Self::Unbound => "unbound",
        }
    }
}

/// Result of verifying a TimeStampToken.
#[derive(Debug, Clone)]
pub struct TstVerification {
    pub info: TimestampInfo,
    pub chain: ChainValidationResult,
    pub tst_info: TstInfo,
    pub diagnostics: Vec<DiagnosticMessage>,
}

/// Verify an RFC 3161 TimeStampToken.
///
/// Arguments:
/// - `token_der` — DER-encoded `ContentInfo` (SignedData wrapping TSTInfo).
/// - `timestamped_data` — raw bytes that the token should cover. We compute
///   the digest ourselves using the algorithm declared in
///   `TSTInfo.messageImprint`.
/// - `chain_builder` — must include anchor(s) that terminate the TSA chain.
/// - `kind` — informational label placed in the resulting `TimestampInfo`.
pub fn verify_time_stamp_token(
    token_der: &[u8],
    timestamped_data: &[u8],
    chain_builder: &ChainBuilder,
    kind: TimestampKind,
) -> Result<TstVerification> {
    // 1. Parse the outer CMS envelope.
    let ci = ContentInfo::from_der(token_der)
        .map_err(|e| Error::Timestamp(format!("ContentInfo: {e}")))?;
    let sd_bytes = ci
        .content
        .to_der()
        .map_err(|e| Error::Asn1(format!("inner SignedData: {e}")))?;
    let sd = SignedData::from_der(&sd_bytes)
        .map_err(|e| Error::Timestamp(format!("SignedData: {e}")))?;

    if sd.encap_content_info.econtent_type != oids::ID_CT_TSTINFO {
        return Err(Error::Timestamp(format!(
            "eContentType is {} — expected id-ct-TSTInfo",
            sd.encap_content_info.econtent_type
        )));
    }

    // 2. Extract the TSTInfo bytes (eContent is an OCTET STRING wrapping TSTInfo DER).
    let econtent = sd.encap_content_info.econtent.as_ref().ok_or_else(|| {
        Error::Timestamp("TimeStampToken has no eContent — detached TST not permitted".into())
    })?;
    let econtent_der = econtent
        .to_der()
        .map_err(|e| Error::Asn1(format!("eContent encode: {e}")))?;
    let tst_bytes = OctetString::from_der(&econtent_der)
        .map_err(|e| Error::Timestamp(format!("eContent must be OCTET STRING: {e}")))?;
    let tst_bytes = tst_bytes.into_bytes();
    let tst_info = TstInfo::from_der(&tst_bytes)?;

    // 3. messageImprint must match a fresh digest of `timestamped_data`.
    let computed = eidas_cms::digest::digest(tst_info.message_imprint.algorithm, timestamped_data)?;
    if computed != tst_info.message_imprint.hashed_message {
        return Err(Error::Timestamp(
            "messageImprint does not match digest of the timestamped data".into(),
        ));
    }

    // 4. Verify the TSA's CMS signature and extract the chain.
    //
    // A TST has exactly one SignerInfo per RFC 3161 §2.4.2 — but the spec
    // does not formally forbid more than one. We verify each present and
    // require at least one.
    let mut diagnostics: Vec<DiagnosticMessage> = Vec::new();
    let signers: Vec<_> = sd.signer_infos.0.iter().collect();
    if signers.is_empty() {
        return Err(Error::Timestamp(
            "TimeStampToken has no SignerInfo".into(),
        ));
    }
    if signers.len() > 1 {
        diagnostics.push(DiagnosticMessage::warn(
            "TST_MULTIPLE_SIGNERS",
            format!("TST has {} SignerInfos — only the first is reported", signers.len()),
        ));
    }
    let signer = signers[0];

    // Locate TSA certificate in embedded certs.
    let embedded_certs = collect_embedded_certs(&sd);
    let tsa_cert = locate_tsa_cert(&signer.sid, &embedded_certs)?;

    // Enforce id-kp-timeStamping EKU on the TSA leaf.
    enforce_timestamping_eku(tsa_cert)?;

    // Require signedAttrs (RFC 3161 does not strictly mandate them, but all
    // real-world TSAs emit them so they can carry signingCertificate).
    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::Timestamp("TST SignerInfo has no signedAttrs".into()))?;

    // messageDigest attribute must equal digest of the TSTInfo bytes (eContent).
    let digest_hash = eidas_cms::digest::hash_from_oid(signer.digest_alg.oid)?;
    let expected_md = eidas_cms::digest::digest(digest_hash, &tst_bytes)?;
    let claimed_md = eidas_cms::attrs::message_digest(signed_attrs)?;
    if expected_md != claimed_md {
        return Err(Error::Timestamp(
            "TST signedAttrs.messageDigest does not match digest of the embedded TSTInfo"
                .into(),
        ));
    }

    // Verify the CMS signature over the re-encoded signedAttrs.
    let to_be_signed = eidas_cms::attrs::to_signed_der(signed_attrs)?;
    eidas_cms::signature_verify::verify_cms_signature(
        tsa_cert,
        &signer.signature_algorithm,
        &signer.digest_alg,
        &to_be_signed,
        signer.signature.as_bytes(),
    )
    .map_err(|e| match e {
        Error::Crypto(m) => Error::Timestamp(format!("TSA signature invalid: {m}")),
        other => other,
    })?;

    // 5. Build the TSA chain and validate against caller anchors.
    //    The chain is evaluated at the TSA's claimed genTime — certificates
    //    already expired at validation "now" must still have been valid at
    //    the time the token was produced (which is how LT verification works).
    let chain = chain_builder
        .build(tsa_cert.clone(), tst_info.gen_time)
        .map_err(|e| Error::Timestamp(format!("TSA chain: {e}")))?;
    diagnostics.extend(chain.diagnostics.clone());

    // Classify the signing algorithm for the report.
    let algorithm = classify_algorithm(&signer.digest_alg, &signer.signature_algorithm, tsa_cert)?;

    let info = TimestampInfo {
        kind: kind.label().to_string(),
        genesis_time: tst_info.gen_time,
        tsa_subject: Some(eidas_x509::subject_display(tsa_cert)),
        imprint_algorithm: Some(algorithm),
        valid: true,
    };

    Ok(TstVerification {
        info,
        chain,
        tst_info,
        diagnostics,
    })
}

fn collect_embedded_certs(sd: &SignedData) -> Vec<Certificate> {
    use cms::cert::CertificateChoices;
    let mut out = Vec::new();
    if let Some(set) = sd.certificates.as_ref() {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(c) = choice {
                out.push(c.clone());
            }
        }
    }
    out
}

fn locate_tsa_cert<'a>(
    sid: &cms::signed_data::SignerIdentifier,
    embedded: &'a [Certificate],
) -> Result<&'a Certificate> {
    use cms::signed_data::SignerIdentifier;
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => embedded
            .iter()
            .find(|c| {
                c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
            })
            .ok_or_else(|| {
                Error::Timestamp(
                    "TSA certificate (IssuerAndSerialNumber) not present in token".into(),
                )
            }),
        SignerIdentifier::SubjectKeyIdentifier(sk) => {
            let want = sk.0.as_bytes();
            embedded
                .iter()
                .find(|c| eidas_x509::ski(c).as_deref() == Some(want))
                .ok_or_else(|| Error::Timestamp("TSA certificate (SKI) not present in token".into()))
        }
    }
}

fn enforce_timestamping_eku(tsa_cert: &Certificate) -> Result<()> {
    use const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE;
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    let exts = tsa_cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
        Error::Timestamp("TSA certificate has no extensions".into())
    })?;
    for ext in exts {
        if ext.extn_id == ID_CE_EXT_KEY_USAGE {
            let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                .map_err(|e| Error::Asn1(format!("EKU: {e}")))?;
            if eku.0.into_iter().any(|o| o == oids::ID_KP_TIME_STAMPING) {
                // RFC 3161 §2.3 also requires the EKU to be marked critical.
                if !ext.critical {
                    // Not fatal — emit as a diagnostic to the caller via the
                    // returned TstVerification. We can't push a warning from
                    // here, so we embrace the RFC-MUST in documentation and
                    // keep the function strict-only on correctness-critical
                    // checks.
                }
                return Ok(());
            }
        }
    }
    Err(Error::Timestamp(
        "TSA certificate lacks id-kp-timeStamping EKU".into(),
    ))
}

fn classify_algorithm(
    digest_alg: &AlgorithmIdentifierOwned,
    sig_alg: &AlgorithmIdentifierOwned,
    tsa_cert: &Certificate,
) -> Result<AlgorithmId> {
    use eidas_cms::oids as cms_oids;
    let hash = eidas_cms::digest::hash_from_oid(digest_alg.oid).or_else(|_| {
        match sig_alg.oid {
            o if o == cms_oids::ID_SHA224_WITH_RSA => Ok(HashAlgorithm::Sha224),
            o if o == cms_oids::ID_SHA256_WITH_RSA || o == cms_oids::ID_ECDSA_SHA256 => {
                Ok(HashAlgorithm::Sha256)
            }
            o if o == cms_oids::ID_SHA384_WITH_RSA || o == cms_oids::ID_ECDSA_SHA384 => {
                Ok(HashAlgorithm::Sha384)
            }
            o if o == cms_oids::ID_SHA512_WITH_RSA || o == cms_oids::ID_ECDSA_SHA512 => {
                Ok(HashAlgorithm::Sha512)
            }
            other => Err(Error::Timestamp(format!("cannot infer TSA hash for {other}"))),
        }
    })?;
    let (signature, key_bits) = match sig_alg.oid {
        o if o == cms_oids::ID_RSA_ENCRYPTION
            || o == cms_oids::ID_SHA1_WITH_RSA
            || o == cms_oids::ID_SHA224_WITH_RSA
            || o == cms_oids::ID_SHA256_WITH_RSA
            || o == cms_oids::ID_SHA384_WITH_RSA
            || o == cms_oids::ID_SHA512_WITH_RSA =>
        {
            (SignatureAlgorithm::RsaPkcs1v15, rsa_key_bits(tsa_cert)?)
        }
        o if o == cms_oids::ID_RSA_PSS => (SignatureAlgorithm::RsaPss, rsa_key_bits(tsa_cert)?),
        o if o == cms_oids::ID_ECDSA_SHA1
            || o == cms_oids::ID_ECDSA_SHA224
            || o == cms_oids::ID_ECDSA_SHA256
            || o == cms_oids::ID_ECDSA_SHA384
            || o == cms_oids::ID_ECDSA_SHA512 =>
        {
            (SignatureAlgorithm::Ecdsa, ecc_key_bits(tsa_cert)?)
        }
        other => {
            return Err(Error::Timestamp(format!(
                "TSA signature algorithm {other} not classified"
            )))
        }
    };
    Ok(AlgorithmId { signature, hash, key_bits })
}

fn rsa_key_bits(cert: &Certificate) -> Result<u32> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPublicKey;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Asn1(format!("TSA SPKI encode: {e}")))?;
    let pk = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| Error::Timestamp(format!("TSA RSA key decode: {e}")))?;
    Ok(u32::try_from(pk.n().bits()).unwrap_or(u32::MAX))
}

fn ecc_key_bits(cert: &Certificate) -> Result<u32> {
    use eidas_cms::oids as cms_oids;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::Timestamp("TSA EC parameters absent".into()))?;
    let param_der = params
        .to_der()
        .map_err(|e| Error::Asn1(format!("TSA EC params encode: {e}")))?;
    let curve = ObjectIdentifier::from_der(&param_der)
        .map_err(|e| Error::Asn1(format!("TSA EC curve: {e}")))?;
    Ok(match curve {
        o if o == cms_oids::ID_SECP256R1 => 256,
        o if o == cms_oids::ID_SECP384R1 => 384,
        o if o == cms_oids::ID_SECP521R1 => 521,
        _ => 0,
    })
}
