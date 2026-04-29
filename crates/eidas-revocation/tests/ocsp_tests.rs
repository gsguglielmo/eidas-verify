//! End-to-end OCSP verification using openssl-generated fixtures.
//!
//! We set up a CA with a dedicated OCSP responder cert (id-kp-OCSPSigning EKU
//! issued by the CA), issue a leaf, revoke another leaf, then ask
//! `openssl ocsp -reqout` + an in-process `openssl ocsp` responder to emit
//! DER OCSP responses we can feed into `verify_ocsp`.

use std::fs;
use std::path::Path;
use std::process::Command;

use chrono::Utc;
use der::Decode;
use eidas_core::RevocationStatus;
use eidas_revocation::verify_ocsp;
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

struct OcspFixture {
    ca_cert: Certificate,
    leaf_cert: Certificate,
    revoked_leaf_cert: Certificate,
    ocsp_for_leaf: Vec<u8>,
    ocsp_for_revoked: Vec<u8>,
    _dir: TempDir,
}

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

[ocsp_cert]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = OCSPSigning
subjectKeyIdentifier   = hash
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

fn issue_cert(
    base: &Path,
    ca_cnf: &Path,
    name: &str,
    extensions_section: Option<&str>,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let key = base.join(format!("{name}.key"));
    let csr = base.join(format!("{name}.csr"));
    let pem = base.join(format!("{name}.pem"));
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&key));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &key.to_string_lossy(),
        "-out", &csr.to_string_lossy(),
        "-subj", &format!("/CN={name}"),
    ]));
    let mut cmd = Command::new("openssl");
    cmd.args([
        "ca",
        "-batch",
        "-in", &csr.to_string_lossy(),
        "-out", &pem.to_string_lossy(),
        "-days", "365",
        "-config", &ca_cnf.to_string_lossy(),
    ]);
    if let Some(sect) = extensions_section {
        cmd.args(["-extensions", sect]);
    }
    run(&mut cmd);
    (pem, key)
}

fn build_ca_and_ocsp() -> OcspFixture {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let ca_cnf = p.join("ca.cnf");
    fs::write(&ca_cnf, openssl_ca_config(p)).unwrap();

    // CA
    let ca_key = p.join("ca.key");
    let ca_pem = p.join("ca.pem");
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&ca_key));
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &ca_key.to_string_lossy(),
        "-out", &ca_pem.to_string_lossy(),
        "-subj", "/CN=eidas-revocation ocsp CA",
        "-days", "3650",
        "-set_serial", "1",
        "-extensions", "v3_ca",
        "-config", &ca_cnf.to_string_lossy(),
    ]));
    init_ca_state(p);

    let (ocsp_pem, ocsp_key) = issue_cert(p, &ca_cnf, "ocsp-responder", Some("ocsp_cert"));
    let (leaf_pem, _leaf_key) = issue_cert(p, &ca_cnf, "leaf-kept", None);
    let (revoked_pem, _revoked_key) = issue_cert(p, &ca_cnf, "leaf-revoked", None);

    // Revoke leaf-revoked (so the OCSP response reflects the status).
    run(Command::new("openssl").args([
        "ca", "-revoke", &revoked_pem.to_string_lossy(),
        "-config", &ca_cnf.to_string_lossy(),
    ]));

    // Produce an OCSP response for each leaf using `openssl ocsp` in
    // one-shot mode (-respout writes the DER response).
    let ocsp_for_leaf = make_ocsp_response(p, &ca_cnf, &ocsp_pem, &ocsp_key, &leaf_pem);
    let ocsp_for_revoked = make_ocsp_response(p, &ca_cnf, &ocsp_pem, &ocsp_key, &revoked_pem);

    OcspFixture {
        ca_cert: Certificate::from_der(&pem_to_der(&fs::read(&ca_pem).unwrap())).unwrap(),
        leaf_cert: Certificate::from_der(&pem_to_der(&fs::read(&leaf_pem).unwrap())).unwrap(),
        revoked_leaf_cert: Certificate::from_der(&pem_to_der(&fs::read(&revoked_pem).unwrap())).unwrap(),
        ocsp_for_leaf,
        ocsp_for_revoked,
        _dir: dir,
    }
}

fn make_ocsp_response(
    base: &Path,
    ca_cnf: &Path,
    ocsp_pem: &Path,
    ocsp_key: &Path,
    leaf_pem: &Path,
) -> Vec<u8> {
    // `openssl ocsp` as a one-shot responder: -reqin points to a request,
    // -respout writes the DER response. We pass -ignore_err so freshness
    // checks don't fire on our small test DB.
    let req_path = base.join("req.der");
    let resp_path = base.join("resp.der");
    run(Command::new("openssl").args([
        "ocsp",
        "-sha256",
        "-issuer", &base.join("ca.pem").to_string_lossy(),
        "-cert", &leaf_pem.to_string_lossy(),
        "-reqout", &req_path.to_string_lossy(),
        "-no_nonce",
    ]));
    run(Command::new("openssl").args([
        "ocsp",
        "-index", &base.join("index.txt").to_string_lossy(),
        "-rsigner", &ocsp_pem.to_string_lossy(),
        "-rkey", &ocsp_key.to_string_lossy(),
        "-CA", &base.join("ca.pem").to_string_lossy(),
        "-reqin", &req_path.to_string_lossy(),
        "-respout", &resp_path.to_string_lossy(),
        "-ndays", "30",
        "-no_nonce",
        "-rmd", "sha256",
    ]));
    let _ = ca_cnf; // not needed for the one-shot responder
    fs::read(&resp_path).unwrap()
}

#[test]
fn ocsp_reports_good_status_for_valid_leaf() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx = build_ca_and_ocsp();
    let check = verify_ocsp(
        &fx.ocsp_for_leaf,
        &fx.leaf_cert,
        &fx.ca_cert,
        Utc::now(),
    )
    .expect("OCSP verify succeeds");
    assert_eq!(check.info.status, RevocationStatus::Good);
    assert!(check.fresh);
    assert_eq!(check.info.source, "OCSP");
}

#[test]
fn ocsp_reports_revoked_for_revoked_leaf() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx = build_ca_and_ocsp();
    let check = verify_ocsp(
        &fx.ocsp_for_revoked,
        &fx.revoked_leaf_cert,
        &fx.ca_cert,
        Utc::now(),
    )
    .expect("OCSP verify succeeds");
    match &check.info.status {
        RevocationStatus::Revoked { .. } => (),
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[test]
fn ocsp_signed_by_unauthorised_responder_is_rejected() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    // Two independent CAs — pair fx_a's OCSP response with fx_b's CA.
    let fx_a = build_ca_and_ocsp();
    let fx_b = build_ca_and_ocsp();
    let err = verify_ocsp(
        &fx_a.ocsp_for_leaf,
        &fx_a.leaf_cert,
        &fx_b.ca_cert,
        Utc::now(),
    )
    .expect_err("OCSP+wrong-CA must fail");
    assert!(matches!(err, eidas_core::Error::Revocation(_)), "got {err:?}");
}
