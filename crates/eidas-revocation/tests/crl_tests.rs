//! End-to-end CRL verification using openssl-generated fixtures.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use der::Decode;
use eidas_core::RevocationStatus;
use eidas_revocation::verify_crl;
use tempfile::TempDir;
use x509_cert::serial_number::SerialNumber;
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

fn pem_to_der(pem_bytes: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(pem_bytes).expect("PEM must be UTF-8");
    let mut in_block = false;
    let mut b64 = String::new();
    for line in s.lines() {
        if line.starts_with("-----BEGIN ") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(b64).expect("valid base64 in PEM")
}

struct CaCrlFixture {
    ca_cert: Certificate,
    leaf_serial: SerialNumber,
    revoked_serial: SerialNumber,
    crl_der: Vec<u8>,
    _dir: TempDir,
}

/// Set up a CA with an OpenSSL ca-database state, issue two leaves (one kept,
/// one revoked), then produce a signed CRL over the revoked entry.
fn build_ca_and_crl() -> CaCrlFixture {
    let dir = TempDir::new().unwrap();
    let p = dir.path();

    // --- Root CA ---
    let ca_key = p.join("ca.key");
    let ca_pem = p.join("ca.pem");
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&ca_key));
    // Use openssl.cnf with minimal sections so that `ca` subcommand works.
    let ca_cnf = p.join("ca.cnf");
    let ca_cnf_content = openssl_ca_config(p);
    fs::write(&ca_cnf, &ca_cnf_content).unwrap();

    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &ca_key.to_string_lossy(),
        "-out", &ca_pem.to_string_lossy(),
        "-subj", "/CN=eidas-revocation test CA",
        "-days", "3650",
        "-set_serial", "1",
        "-extensions", "v3_ca",
        "-config", &ca_cnf.to_string_lossy(),
    ]));
    init_ca_state(p);

    let ca_der = pem_to_der(&fs::read(&ca_pem).unwrap());
    let ca_cert = Certificate::from_der(&ca_der).unwrap();

    // --- Two leaves ---
    let leaf_serial = issue_leaf(p, &ca_cnf, "leaf-kept", 100);
    let revoked_serial = issue_leaf(p, &ca_cnf, "leaf-revoked", 200);

    // Revoke leaf-revoked
    run(Command::new("openssl").args([
        "ca", "-revoke", &p.join("leaf-revoked.pem").to_string_lossy(),
        "-config", &ca_cnf.to_string_lossy(),
    ]));

    // Generate CRL
    let crl_pem = p.join("crl.pem");
    run(Command::new("openssl").args([
        "ca", "-gencrl",
        "-out", &crl_pem.to_string_lossy(),
        "-config", &ca_cnf.to_string_lossy(),
    ]));
    let crl_der = pem_to_der(&fs::read(&crl_pem).unwrap());

    CaCrlFixture {
        ca_cert,
        leaf_serial,
        revoked_serial,
        crl_der,
        _dir: dir,
    }
}

/// Minimal openssl.cnf enabling `openssl ca` and `openssl x509 -CAserial`
/// against files under `base`.
fn openssl_ca_config(base: &Path) -> String {
    let base = base.display();
    format!(
        r#"
[ca]
default_ca = CA_default

[CA_default]
dir              = {base}
database         = $dir/index.txt
serial           = $dir/serial
new_certs_dir    = $dir/newcerts
certificate      = $dir/ca.pem
private_key      = $dir/ca.key
default_md       = sha256
policy           = policy_any
default_days     = 365
default_crl_days = 30
crlnumber        = $dir/crlnumber
x509_extensions  = usr_cert
copy_extensions  = copy
unique_subject   = no

[policy_any]
commonName = supplied

[req]
distinguished_name = req_distinguished_name
prompt             = no
default_md         = sha256

[req_distinguished_name]
CN = placeholder

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign

[usr_cert]
basicConstraints     = CA:FALSE
keyUsage             = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"#
    )
}

fn init_ca_state(base: &Path) {
    fs::create_dir_all(base.join("newcerts")).unwrap();
    fs::write(base.join("index.txt"), "").unwrap();
    fs::write(base.join("serial"), "1000\n").unwrap();
    fs::write(base.join("crlnumber"), "1000\n").unwrap();
}

fn issue_leaf(base: &Path, ca_cnf: &Path, name: &str, serial_u64: u64) -> SerialNumber {
    let leaf_key = base.join(format!("{name}.key"));
    let leaf_csr = base.join(format!("{name}.csr"));
    let leaf_pem = base.join(format!("{name}.pem"));

    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&leaf_key));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", &format!("/CN={name}"),
    ]));
    run(Command::new("openssl").args([
        "ca",
        "-batch",
        "-in", &leaf_csr.to_string_lossy(),
        "-out", &leaf_pem.to_string_lossy(),
        "-days", "365",
        "-config", &ca_cnf.to_string_lossy(),
    ]));

    // Return the real serial that openssl chose (written in its index.txt /
    // newcerts directory). We recover it by parsing the leaf cert.
    let leaf_der = pem_to_der(&fs::read(&leaf_pem).unwrap());
    let leaf_cert = Certificate::from_der(&leaf_der).unwrap();
    let _ = serial_u64; // openssl chose its own serial; ignore the caller hint
    leaf_cert.tbs_certificate.serial_number.clone()
}

#[test]
fn crl_reports_revoked_cert() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx = build_ca_and_crl();

    let check = verify_crl(
        &fx.crl_der,
        &fx.ca_cert,
        "CN=leaf-revoked",
        &fx.revoked_serial,
        Utc::now(),
    )
    .expect("CRL verification succeeds");

    match &check.info.status {
        RevocationStatus::Revoked { .. } => (),
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert!(check.fresh, "freshly-generated CRL should be within validity");
    assert_eq!(check.info.source, "CRL");
}

#[test]
fn crl_reports_good_for_non_revoked_cert() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx = build_ca_and_crl();

    let check = verify_crl(
        &fx.crl_der,
        &fx.ca_cert,
        "CN=leaf-kept",
        &fx.leaf_serial,
        Utc::now(),
    )
    .expect("CRL verification succeeds");

    assert_eq!(check.info.status, RevocationStatus::Good);
    assert!(check.fresh);
}

#[test]
fn crl_signed_by_different_ca_is_rejected() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx_signer = build_ca_and_crl();
    let fx_wrong = build_ca_and_crl();

    let err = verify_crl(
        &fx_signer.crl_der,
        &fx_wrong.ca_cert,
        "CN=leaf-kept",
        &fx_signer.leaf_serial,
        Utc::now(),
    )
    .expect_err("CRL+wrong-CA must fail");
    assert!(matches!(err, eidas_core::Error::Revocation(_)), "got {err:?}");
}

fn _unused_hide_warnings() {
    let _ = PathBuf::new();
}
