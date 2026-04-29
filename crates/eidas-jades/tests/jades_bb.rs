//! End-to-end JAdES B-B verification.

use std::fs;
use std::path::Path;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use der::Decode;
use eidas_core::{Level, Status, ValidationTime};
use eidas_jades::{verify_jades, JadesInput};
use eidas_x509::chain::{ChainBuilder, TrustAnchor};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use x509_cert::Certificate;

fn openssl_present() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("spawn openssl");
    assert!(
        out.status.success(),
        "command failed: {cmd:?}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn pem_to_der(pem_bytes: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(pem_bytes).unwrap();
    let mut in_block = false;
    let mut b64 = String::new();
    for line in s.lines() {
        if line.starts_with("-----BEGIN ") { in_block = true; continue; }
        if line.starts_with("-----END ") { break; }
        if in_block { b64.push_str(line.trim()); }
    }
    STANDARD.decode(b64).unwrap()
}

struct Pki {
    ca: Certificate,
    leaf_der: Vec<u8>,
    leaf_key_pem: std::path::PathBuf,
    _dir: TempDir,
}

fn build_pki(key_algorithm: &str) -> Pki {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let ca_key = p.join("ca.key");
    let ca_pem = p.join("ca.pem");

    let ca_gen_args: Vec<String> = match key_algorithm {
        "RSA" => vec![
            "genpkey".into(), "-algorithm".into(), "RSA".into(),
            "-pkeyopt".into(), "rsa_keygen_bits:2048".into(),
            "-out".into(), ca_key.to_string_lossy().into(),
        ],
        "EC:P-256" => vec![
            "genpkey".into(), "-algorithm".into(), "EC".into(),
            "-pkeyopt".into(), "ec_paramgen_curve:P-256".into(),
            "-out".into(), ca_key.to_string_lossy().into(),
        ],
        _ => panic!("unsupported key alg"),
    };
    run(Command::new("openssl").args(&ca_gen_args));
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &ca_key.to_string_lossy(),
        "-out", &ca_pem.to_string_lossy(),
        "-subj", "/CN=JAdES test CA",
        "-days", "3650",
        "-set_serial", "1",
    ]));

    let leaf_key = p.join("leaf.key");
    let leaf_csr = p.join("leaf.csr");
    let leaf_pem = p.join("leaf.pem");
    let leaf_ext = p.join("leaf.ext");
    let leaf_gen_args: Vec<String> = match key_algorithm {
        "RSA" => vec![
            "genpkey".into(), "-algorithm".into(), "RSA".into(),
            "-pkeyopt".into(), "rsa_keygen_bits:2048".into(),
            "-out".into(), leaf_key.to_string_lossy().into(),
        ],
        "EC:P-256" => vec![
            "genpkey".into(), "-algorithm".into(), "EC".into(),
            "-pkeyopt".into(), "ec_paramgen_curve:P-256".into(),
            "-out".into(), leaf_key.to_string_lossy().into(),
        ],
        _ => unreachable!(),
    };
    run(Command::new("openssl").args(&leaf_gen_args));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", "/CN=JAdES test signer",
    ]));
    fs::write(
        &leaf_ext,
        "keyUsage = critical, digitalSignature, nonRepudiation\nbasicConstraints = CA:FALSE\n",
    )
    .unwrap();
    run(Command::new("openssl").args([
        "x509", "-req",
        "-in", &leaf_csr.to_string_lossy(),
        "-CA", &ca_pem.to_string_lossy(),
        "-CAkey", &ca_key.to_string_lossy(),
        "-CAcreateserial",
        "-out", &leaf_pem.to_string_lossy(),
        "-days", "3650",
        "-sha256",
        "-extfile", &leaf_ext.to_string_lossy(),
    ]));

    let ca_der = pem_to_der(&fs::read(&ca_pem).unwrap());
    let leaf_der = pem_to_der(&fs::read(&leaf_pem).unwrap());
    Pki {
        ca: Certificate::from_der(&ca_der).unwrap(),
        leaf_der,
        leaf_key_pem: leaf_key,
        _dir: dir,
    }
}

/// Use openssl to sign `signing_input` (raw bytes) and return the signature
/// in the format JWS expects. For RS256 this is PKCS#1 v1.5 DER (which is
/// what openssl emits with `dgst -sign -sha256`, and which JWS treats as the
/// signature value directly). For ES256, openssl emits DER-encoded r||s; we
/// convert to the raw 64-byte form required by RFC 7518 §3.4.
fn jws_sign_rsa_sha256(leaf_key_pem: &Path, signing_input: &[u8]) -> Vec<u8> {
    let dir = leaf_key_pem.parent().unwrap();
    let si = dir.join("si.bin");
    fs::write(&si, signing_input).unwrap();
    let out = dir.join("sig.bin");
    run(Command::new("openssl").args([
        "dgst", "-sha256",
        "-sign", &leaf_key_pem.to_string_lossy(),
        "-out", &out.to_string_lossy(),
        &si.to_string_lossy(),
    ]));
    fs::read(&out).unwrap()
}

fn jws_sign_es256(leaf_key_pem: &Path, signing_input: &[u8]) -> Vec<u8> {
    let dir = leaf_key_pem.parent().unwrap();
    let si = dir.join("si.bin");
    fs::write(&si, signing_input).unwrap();
    let der_out = dir.join("sig.der");
    run(Command::new("openssl").args([
        "dgst", "-sha256",
        "-sign", &leaf_key_pem.to_string_lossy(),
        "-out", &der_out.to_string_lossy(),
        &si.to_string_lossy(),
    ]));
    let der = fs::read(&der_out).unwrap();
    // DER ECDSA signature → raw r||s (32 bytes each for P-256).
    use p256::ecdsa::Signature as P256Sig;
    let sig = P256Sig::from_der(&der).expect("parse ECDSA DER");
    sig.to_bytes().to_vec()
}

fn b64url(v: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(v)
}

fn build_jws(
    alg: &str,
    leaf_der: &[u8],
    payload: &[u8],
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> String {
    let x5c = STANDARD.encode(leaf_der);
    let x5t = URL_SAFE_NO_PAD.encode(Sha256::digest(leaf_der));
    let header = serde_json::json!({
        "alg": alg,
        "typ": "JOSE",
        "x5c": [x5c],
        "x5t#S256": x5t,
        "sigT": "2025-01-15T12:34:56Z",
    });
    let header_json = serde_json::to_vec(&header).unwrap();
    let h_b64 = b64url(&header_json);
    let p_b64 = b64url(payload);
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig = sign(signing_input.as_bytes());
    let s_b64 = b64url(&sig);
    format!("{h_b64}.{p_b64}.{s_b64}")
}

#[test]
fn jades_compact_rs256_round_trip() {
    if !openssl_present() { return; }
    let pki = build_pki("RSA");

    let payload = b"JAdES B-B payload";
    let compact = build_jws("RS256", &pki.leaf_der, payload, |si| {
        jws_sign_rsa_sha256(&pki.leaf_key_pem, si)
    });

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.ca.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_jades(
        &JadesInput { bytes: compact.as_bytes(), is_json: false },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    assert_eq!(report.signatures.len(), 1);
    let sr = &report.signatures[0];
    assert_eq!(sr.status, Status::TotalPassed, "diag: {:?}", sr.diagnostics);
    assert_eq!(sr.level_reached, Level::BB);
    assert!(sr.signing_time_claimed.is_some());
    assert!(matches!(
        report.container,
        Some(eidas_core::ContainerInfo::Jws { .. })
    ));
}

#[test]
fn jades_compact_es256_round_trip() {
    if !openssl_present() { return; }
    let pki = build_pki("EC:P-256");

    let payload = b"JAdES ECDSA payload";
    let compact = build_jws("ES256", &pki.leaf_der, payload, |si| {
        jws_sign_es256(&pki.leaf_key_pem, si)
    });

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.ca.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_jades(
        &JadesInput { bytes: compact.as_bytes(), is_json: false },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    assert_eq!(report.signatures[0].status, Status::TotalPassed,
               "diag: {:?}", report.signatures[0].diagnostics);
    assert_eq!(report.signatures[0].level_reached, Level::BB);
}

#[test]
fn jades_flattened_json_round_trip() {
    if !openssl_present() { return; }
    let pki = build_pki("RSA");

    let payload = b"flattened JSON payload";
    let compact = build_jws("RS256", &pki.leaf_der, payload, |si| {
        jws_sign_rsa_sha256(&pki.leaf_key_pem, si)
    });
    let parts: Vec<&str> = compact.split('.').collect();
    let flat = serde_json::json!({
        "protected": parts[0],
        "payload": parts[1],
        "signature": parts[2],
    });
    let flat_bytes = serde_json::to_vec(&flat).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.ca.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_jades(
        &JadesInput { bytes: &flat_bytes, is_json: true },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].status, Status::TotalPassed);
}

#[test]
fn jades_detects_tampered_payload() {
    if !openssl_present() { return; }
    let pki = build_pki("RSA");
    let payload = b"original payload";
    let compact = build_jws("RS256", &pki.leaf_der, payload, |si| {
        jws_sign_rsa_sha256(&pki.leaf_key_pem, si)
    });

    // Substitute the payload with a different base64url'd blob but keep the
    // original signature — the signature must no longer validate.
    let mut parts: Vec<String> = compact.split('.').map(str::to_string).collect();
    parts[1] = URL_SAFE_NO_PAD.encode(b"tampered payload");
    let tampered = parts.join(".");

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.ca.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_jades(
        &JadesInput { bytes: tampered.as_bytes(), is_json: false },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
}

#[test]
fn jades_rejects_bad_x5t_header() {
    if !openssl_present() { return; }
    let pki = build_pki("RSA");
    let payload = b"payload";
    // Build a header where x5t#S256 is wrong (hash of something else).
    let x5c = STANDARD.encode(&pki.leaf_der);
    let wrong_x5t = URL_SAFE_NO_PAD.encode(Sha256::digest(b"not the cert"));
    let header = serde_json::json!({
        "alg": "RS256",
        "x5c": [x5c],
        "x5t#S256": wrong_x5t,
    });
    let header_json = serde_json::to_vec(&header).unwrap();
    let h = b64url(&header_json);
    let p = b64url(payload);
    let si = format!("{h}.{p}");
    let sig = jws_sign_rsa_sha256(&pki.leaf_key_pem, si.as_bytes());
    let s = b64url(&sig);
    let compact = format!("{h}.{p}.{s}");

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.ca.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_jades(
        &JadesInput { bytes: compact.as_bytes(), is_json: false },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
    let codes: Vec<_> = report.signatures[0].diagnostics.iter().map(|d| d.code.as_str()).collect();
    assert!(
        codes.iter().any(|c| c.contains("JADES") || c.contains("VERIFICATION")),
        "diagnostics: {codes:?}"
    );
}
