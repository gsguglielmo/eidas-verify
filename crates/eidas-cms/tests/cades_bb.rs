//! End-to-end CAdES B-B verification.
//!
//! Uses the `openssl` CLI for both PKI generation and CAdES signing. If
//! openssl is unavailable on PATH, each test is a no-op "skip".

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{TimeZone, Utc};
use der::Decode;
use eidas_cms::{verify_cades_bb, CadesInput};
use eidas_core::{Level, Status, ValidationTime};
use eidas_x509::chain::{ChainBuilder, TrustAnchor};
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
        "command failed: {cmd:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Pki {
    root: Certificate,
    root_pem: PathBuf,
    leaf_pem: PathBuf,
    leaf_key: PathBuf,
}

/// Build a 1-tier RSA-2048 PKI using openssl. Cert validity 2024-01-01 →
/// 2030-01-01. Unique Common Names derived from `tag` so two PKIs generated
/// in the same test don't collide.
fn build_pki(dir: &Path, tag: &str) -> Pki {
    let root_key = dir.join(format!("{tag}_root.key"));
    let root_pem = dir.join(format!("{tag}_root.pem"));
    let leaf_key = dir.join(format!("{tag}_leaf.key"));
    let leaf_csr = dir.join(format!("{tag}_leaf.csr"));
    let leaf_pem = dir.join(format!("{tag}_leaf.pem"));

    // Root key
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&root_key));

    // Root self-signed cert
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &root_key.to_string_lossy(),
        "-out", &root_pem.to_string_lossy(),
        "-subj", &format!("/CN=eidas-cms test root {tag}"),
        "-days", "3650",
        "-set_serial", "1",
    ]));

    // Leaf key
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&leaf_key));

    // Leaf CSR
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", &format!("/CN=eidas-cms test signer {tag}"),
    ]));

    // Sign leaf with root; enforce digitalSignature + nonRepudiation keyUsage.
    let ext_conf = dir.join(format!("{tag}.ext"));
    fs::write(
        &ext_conf,
        "keyUsage = critical, digitalSignature, nonRepudiation\nbasicConstraints = CA:FALSE\n",
    )
    .unwrap();
    run(Command::new("openssl").args([
        "x509", "-req",
        "-in", &leaf_csr.to_string_lossy(),
        "-CA", &root_pem.to_string_lossy(),
        "-CAkey", &root_key.to_string_lossy(),
        "-CAcreateserial",
        "-out", &leaf_pem.to_string_lossy(),
        "-days", "3650",
        "-sha256",
        "-extfile", &ext_conf.to_string_lossy(),
    ]));

    // Parse the root PEM into an `x509_cert::Certificate`.
    let root_pem_bytes = fs::read(&root_pem).unwrap();
    let root_der = pem_to_der(&root_pem_bytes);
    let root = Certificate::from_der(&root_der).unwrap();

    Pki {
        root,
        root_pem,
        leaf_pem,
        leaf_key,
    }
}

fn pem_to_der(pem_bytes: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(pem_bytes).expect("PEM must be UTF-8");
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in s.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            in_cert = true;
            continue;
        }
        if line.starts_with("-----END CERTIFICATE") {
            break;
        }
        if in_cert {
            b64.push_str(line.trim());
        }
    }
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(b64).expect("valid base64 in PEM")
}

fn openssl_cades_sign(
    data_path: &Path,
    leaf_pem: &Path,
    leaf_key: &Path,
    out_path: &Path,
    attached: bool,
) {
    let mut cmd = Command::new("openssl");
    cmd.arg("cms")
        .arg("-sign")
        .arg("-binary")
        .arg("-md").arg("sha256")
        .arg("-cades")
        .arg("-in").arg(data_path)
        .arg("-signer").arg(leaf_pem)
        .arg("-inkey").arg(leaf_key)
        .arg("-outform").arg("DER")
        .arg("-out").arg(out_path);
    if attached {
        cmd.arg("-nodetach");
    }
    run(&mut cmd);
}

/// We sign and immediately validate, so `Now` gives us a time inside the
/// freshly-issued cert's validity window.
fn now_time() -> ValidationTime {
    ValidationTime::Now
}

#[test]
fn cades_bb_rsa_attached_round_trip() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pki = build_pki(tmp.path(), "rt_attached");

    let data_path = tmp.path().join("data.txt");
    fs::write(&data_path, b"Hello, eIDAS! Attached content.").unwrap();

    let sig_path = tmp.path().join("sig.p7s");
    openssl_cades_sign(&data_path, &pki.leaf_pem, &pki.leaf_key, &sig_path, true);
    let sig = fs::read(&sig_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();

    let report = verify_cades_bb(
        &CadesInput { cms: &sig, detached_content: None },
        &builder,
        &policy,
        now_time(),
    )
    .unwrap();

    assert_eq!(report.signatures.len(), 1);
    let sr = &report.signatures[0];
    assert_eq!(
        sr.status, Status::TotalPassed,
        "got {:?}, diagnostics {:?}",
        sr.status, sr.diagnostics
    );
    assert_eq!(sr.level_reached, Level::BB);
    assert_eq!(sr.chain.len(), 2, "leaf + root");
    let _ = pki.root_pem;
}

#[test]
fn cades_bb_rsa_detached_round_trip() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pki = build_pki(tmp.path(), "rt_detached");

    let data_path = tmp.path().join("data.txt");
    let payload = b"Hello, eIDAS! Detached content.";
    fs::write(&data_path, payload).unwrap();

    let sig_path = tmp.path().join("sig.p7s");
    openssl_cades_sign(&data_path, &pki.leaf_pem, &pki.leaf_key, &sig_path, false);
    let sig = fs::read(&sig_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();

    let report = verify_cades_bb(
        &CadesInput { cms: &sig, detached_content: Some(payload) },
        &builder,
        &policy,
        now_time(),
    )
    .unwrap();

    let sr = &report.signatures[0];
    assert_eq!(
        sr.status, Status::TotalPassed,
        "diagnostics: {:?}", sr.diagnostics
    );
    assert_eq!(sr.level_reached, Level::BB);
}

#[test]
fn cades_bb_detects_tampered_content() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pki = build_pki(tmp.path(), "tampered");

    let data_path = tmp.path().join("data.txt");
    fs::write(&data_path, b"original content").unwrap();
    let sig_path = tmp.path().join("sig.p7s");
    openssl_cades_sign(&data_path, &pki.leaf_pem, &pki.leaf_key, &sig_path, false);
    let sig = fs::read(&sig_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();

    let report = verify_cades_bb(
        &CadesInput { cms: &sig, detached_content: Some(b"tampered content") },
        &builder,
        &policy,
        now_time(),
    )
    .unwrap();

    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
    let codes: Vec<_> = report.signatures[0]
        .diagnostics
        .iter()
        .map(|d| d.code.as_str())
        .collect();
    assert!(
        codes.contains(&"MESSAGE_DIGEST_MISMATCH"),
        "expected MESSAGE_DIGEST_MISMATCH, got {codes:?}"
    );
}

#[test]
fn cades_bb_fails_without_matching_trust_anchor() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pki = build_pki(tmp.path(), "signer");
    let other_pki = build_pki(tmp.path(), "unrelated");

    let data_path = tmp.path().join("data.txt");
    fs::write(&data_path, b"orig").unwrap();
    let sig_path = tmp.path().join("sig.p7s");
    openssl_cades_sign(&data_path, &pki.leaf_pem, &pki.leaf_key, &sig_path, true);
    let sig = fs::read(&sig_path).unwrap();

    // Use the *other* PKI's root as the sole anchor.
    let builder =
        ChainBuilder::new().with_anchors([TrustAnchor::new(other_pki.root.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();

    let report = verify_cades_bb(
        &CadesInput { cms: &sig, detached_content: None },
        &builder,
        &policy,
        now_time(),
    )
    .unwrap();

    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
}

fn build_ecdsa_pki(dir: &Path, tag: &str, curve: &str) -> Pki {
    let root_key = dir.join(format!("{tag}_root.key"));
    let root_pem = dir.join(format!("{tag}_root.pem"));
    let leaf_key = dir.join(format!("{tag}_leaf.key"));
    let leaf_csr = dir.join(format!("{tag}_leaf.csr"));
    let leaf_pem = dir.join(format!("{tag}_leaf.pem"));

    // Root ECDSA key
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "EC", "-pkeyopt"])
        .arg(format!("ec_paramgen_curve:{curve}"))
        .arg("-out")
        .arg(&root_key));
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &root_key.to_string_lossy(),
        "-out", &root_pem.to_string_lossy(),
        "-subj", &format!("/CN=eidas-cms test ec root {tag}"),
        "-days", "3650",
        "-set_serial", "1",
    ]));

    // Leaf ECDSA key
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "EC", "-pkeyopt"])
        .arg(format!("ec_paramgen_curve:{curve}"))
        .arg("-out")
        .arg(&leaf_key));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", &format!("/CN=eidas-cms test ec signer {tag}"),
    ]));

    let ext_conf = dir.join(format!("{tag}.ext"));
    fs::write(
        &ext_conf,
        "keyUsage = critical, digitalSignature, nonRepudiation\nbasicConstraints = CA:FALSE\n",
    )
    .unwrap();
    run(Command::new("openssl").args([
        "x509", "-req",
        "-in", &leaf_csr.to_string_lossy(),
        "-CA", &root_pem.to_string_lossy(),
        "-CAkey", &root_key.to_string_lossy(),
        "-CAcreateserial",
        "-out", &leaf_pem.to_string_lossy(),
        "-days", "3650",
        "-sha256",
        "-extfile", &ext_conf.to_string_lossy(),
    ]));

    let root_pem_bytes = fs::read(&root_pem).unwrap();
    let root = Certificate::from_der(&pem_to_der(&root_pem_bytes)).unwrap();
    Pki { root, root_pem, leaf_pem, leaf_key }
}

#[test]
fn cades_bb_ecdsa_p256_attached_round_trip() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pki = build_ecdsa_pki(tmp.path(), "ec_p256", "P-256");

    let data_path = tmp.path().join("data.txt");
    fs::write(&data_path, b"ECDSA P-256 attached content").unwrap();
    let sig_path = tmp.path().join("sig.p7s");
    openssl_cades_sign(&data_path, &pki.leaf_pem, &pki.leaf_key, &sig_path, true);
    let sig = fs::read(&sig_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();

    let report = verify_cades_bb(
        &CadesInput { cms: &sig, detached_content: None },
        &builder,
        &policy,
        now_time(),
    )
    .unwrap();

    let sr = &report.signatures[0];
    assert_eq!(
        sr.status, Status::TotalPassed,
        "diagnostics: {:?}", sr.diagnostics
    );
    assert_eq!(sr.level_reached, Level::BB);
}

#[test]
fn cades_bb_ecdsa_p384_attached_round_trip() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pki = build_ecdsa_pki(tmp.path(), "ec_p384", "P-384");

    let data_path = tmp.path().join("data.txt");
    fs::write(&data_path, b"ECDSA P-384 attached content").unwrap();
    let sig_path = tmp.path().join("sig.p7s");
    // Use SHA-384 to exercise a different digest path.
    let mut cmd = Command::new("openssl");
    cmd.args(["cms", "-sign", "-binary", "-md", "sha384", "-cades", "-nodetach",
              "-in"]).arg(&data_path)
        .arg("-signer").arg(&pki.leaf_pem)
        .arg("-inkey").arg(&pki.leaf_key)
        .arg("-outform").arg("DER")
        .arg("-out").arg(&sig_path);
    run(&mut cmd);
    let sig = fs::read(&sig_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();

    let report = verify_cades_bb(
        &CadesInput { cms: &sig, detached_content: None },
        &builder,
        &policy,
        now_time(),
    )
    .unwrap();

    let sr = &report.signatures[0];
    assert_eq!(
        sr.status, Status::TotalPassed,
        "diagnostics: {:?}", sr.diagnostics
    );
}

#[test]
fn cades_bb_rejects_when_validation_time_is_past_cert_expiry() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pki = build_pki(tmp.path(), "expired");

    let data_path = tmp.path().join("data.txt");
    fs::write(&data_path, b"orig").unwrap();
    let sig_path = tmp.path().join("sig.p7s");
    openssl_cades_sign(&data_path, &pki.leaf_pem, &pki.leaf_key, &sig_path, true);
    let sig = fs::read(&sig_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.root.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();

    // Certs are 10y from test-start; 2099-01-01 is beyond expiry.
    let report = verify_cades_bb(
        &CadesInput { cms: &sig, detached_content: None },
        &builder,
        &policy,
        ValidationTime::At(Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap()),
    )
    .unwrap();

    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
}
