//! End-to-end ASiC-S / ASiC-E container verification with CAdES.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use der::Decode;
use eidas_asic::{verify_asic, AsicInput};
use eidas_cades::CadesTrustMaterial;
use eidas_core::{Level, Status, ValidationTime};
use tempfile::TempDir;
use x509_cert::Certificate;
use zip::write::FileOptions;
use zip::CompressionMethod;

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
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(b64).unwrap()
}

struct Pki {
    ca_cert: Certificate,
    leaf_pem: PathBuf,
    leaf_key: PathBuf,
    dir: TempDir,
}

fn build_pki() -> Pki {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let ca_key = p.join("ca.key");
    let ca_pem = p.join("ca.pem");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &ca_key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &ca_key.to_string_lossy(),
        "-out", &ca_pem.to_string_lossy(),
        "-subj", "/CN=asic test CA",
        "-days", "3650",
        "-set_serial", "1",
    ]));
    let leaf_key = p.join("leaf.key");
    let leaf_csr = p.join("leaf.csr");
    let leaf_pem = p.join("leaf.pem");
    let ext = p.join("leaf.ext");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &leaf_key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", "/CN=asic test signer",
    ]));
    fs::write(
        &ext,
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
        "-extfile", &ext.to_string_lossy(),
    ]));
    let ca_cert = Certificate::from_der(&pem_to_der(&fs::read(&ca_pem).unwrap())).unwrap();
    Pki { ca_cert, leaf_pem, leaf_key, dir }
}

fn sign_detached(pki: &Pki, data: &Path, out: &Path) {
    run(Command::new("openssl").args([
        "cms", "-sign", "-binary", "-md", "sha256", "-cades",
        "-in", &data.to_string_lossy(),
        "-signer", &pki.leaf_pem.to_string_lossy(),
        "-inkey", &pki.leaf_key.to_string_lossy(),
        "-outform", "DER",
        "-out", &out.to_string_lossy(),
    ]));
}

/// Build an ASiC ZIP with the given mimetype, one data file, and one
/// `META-INF/<sig_name>` signature.
fn build_asic(
    mime: &str,
    data_name: &str,
    data: &[u8],
    sig_name: &str,
    sig_der: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);

        // mimetype: first entry, stored (no compression), per EN 319 162-1.
        let mime_opts = FileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file("mimetype", mime_opts).unwrap();
        zip.write_all(mime.as_bytes()).unwrap();

        // Data file.
        zip.start_file(
            data_name,
            FileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(data).unwrap();

        // Signature.
        zip.start_file(
            format!("META-INF/{sig_name}"),
            FileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(sig_der).unwrap();

        zip.finish().unwrap();
    }
    buf
}

#[test]
fn asic_s_cades_round_trip() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let data_path = pki.dir.path().join("hello.txt");
    fs::write(&data_path, b"ASiC-S CAdES payload").unwrap();
    let sig_path = pki.dir.path().join("sig.p7s");
    sign_detached(&pki, &data_path, &sig_path);
    let sig = fs::read(&sig_path).unwrap();
    let data = fs::read(&data_path).unwrap();

    let zip_bytes = build_asic(
        "application/vnd.etsi.asic-s+zip",
        "hello.txt",
        &data,
        "signature.p7s",
        &sig,
    );

    let trust = CadesTrustMaterial::new().with_anchors([pki.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_asic(
        &AsicInput { bytes: &zip_bytes },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    match &report.container {
        Some(eidas_core::ContainerInfo::Asic { mime_type, entries }) => {
            assert_eq!(mime_type, "application/vnd.etsi.asic-s+zip");
            assert!(entries.iter().any(|n| n == "hello.txt"));
            assert!(entries.iter().any(|n| n == "META-INF/signature.p7s"));
        }
        other => panic!("expected ASiC container info, got {other:?}"),
    }

    assert_eq!(report.signatures.len(), 1);
    let sr = &report.signatures[0];
    assert_eq!(sr.status, Status::TotalPassed, "diag: {:?}", sr.diagnostics);
    assert_eq!(sr.level_reached, Level::BB);
    let binding_msg = sr
        .diagnostics
        .iter()
        .find(|d| d.code == "ASIC_SIGNATURE_BINDING")
        .expect("must record the matched binding");
    assert!(binding_msg.message.contains("hello.txt"));
}

#[test]
fn asic_e_cades_with_multiple_candidates_matches_correct_file() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let data1_path = pki.dir.path().join("doc1.txt");
    let data2_path = pki.dir.path().join("doc2.txt");
    fs::write(&data1_path, b"wrong document").unwrap();
    fs::write(&data2_path, b"correct document").unwrap();
    // Sign doc2 only.
    let sig_path = pki.dir.path().join("sig.p7s");
    sign_detached(&pki, &data2_path, &sig_path);
    let sig = fs::read(&sig_path).unwrap();

    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let stored = FileOptions::default().compression_method(CompressionMethod::Stored);
        let deflated = FileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("mimetype", stored).unwrap();
        zip.write_all(b"application/vnd.etsi.asic-e+zip").unwrap();
        zip.start_file("doc1.txt", deflated).unwrap();
        zip.write_all(b"wrong document").unwrap();
        zip.start_file("doc2.txt", deflated).unwrap();
        zip.write_all(b"correct document").unwrap();
        zip.start_file("META-INF/signatures.p7s", stored).unwrap();
        zip.write_all(&sig).unwrap();
        zip.finish().unwrap();
    }

    let trust = CadesTrustMaterial::new().with_anchors([pki.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_asic(
        &AsicInput { bytes: &buf },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures.len(), 1);
    let sr = &report.signatures[0];
    assert_eq!(sr.status, Status::TotalPassed, "diag: {:?}", sr.diagnostics);
    let binding = sr
        .diagnostics
        .iter()
        .find(|d| d.code == "ASIC_SIGNATURE_BINDING")
        .expect("binding diag");
    assert!(binding.message.contains("doc2.txt"), "got {:?}", binding.message);
}

#[test]
fn asic_missing_signature_is_error() {
    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let stored = FileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file("mimetype", stored).unwrap();
        zip.write_all(b"application/vnd.etsi.asic-s+zip").unwrap();
        zip.start_file("doc.txt", stored).unwrap();
        zip.write_all(b"content").unwrap();
        zip.finish().unwrap();
    }
    let trust = CadesTrustMaterial::new();
    let policy = eidas_policy::etsi_119_312_2023();
    let err = verify_asic(
        &AsicInput { bytes: &buf },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .expect_err("no signature");
    assert!(matches!(err, eidas_core::Error::Zip(_)), "got {err:?}");
}

#[test]
fn asic_signature_matching_no_file_is_reported_as_failure() {
    if !openssl_present() { return; }
    let pki = build_pki();
    // Sign some data; then pack a *different* data file into the ASiC.
    let original = pki.dir.path().join("original.txt");
    fs::write(&original, b"original bytes").unwrap();
    let sig_path = pki.dir.path().join("sig.p7s");
    sign_detached(&pki, &original, &sig_path);
    let sig = fs::read(&sig_path).unwrap();

    let zip_bytes = build_asic(
        "application/vnd.etsi.asic-s+zip",
        "other.txt",
        b"completely different content",
        "signature.p7s",
        &sig,
    );

    let trust = CadesTrustMaterial::new().with_anchors([pki.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_asic(
        &AsicInput { bytes: &zip_bytes },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
}
