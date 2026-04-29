//! End-to-end TimeStampToken verification using openssl's `ts` subcommand.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use der::Decode;
use eidas_timestamp::{verify_time_stamp_token, TimestampKind};
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

struct TsaFixture {
    ca_cert: Certificate,
    tsa_pem: PathBuf,
    tsa_key: PathBuf,
    ts_config: PathBuf,
    #[allow(dead_code)]
    dir: TempDir,
}

/// Build a CA that issues a TSA certificate (`id-kp-timeStamping` EKU, critical).
fn build_tsa() -> TsaFixture {
    let dir = TempDir::new().unwrap();
    let p = dir.path();

    // --- Root CA ---
    let ca_key = p.join("ca.key");
    let ca_pem = p.join("ca.pem");
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&ca_key));
    // Minimal openssl.cnf enabling `ca` subcommand + timestamp extensions.
    let ca_cnf = p.join("ca.cnf");
    fs::write(&ca_cnf, openssl_ca_config(p)).unwrap();

    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &ca_key.to_string_lossy(),
        "-out", &ca_pem.to_string_lossy(),
        "-subj", "/CN=eidas-timestamp test CA",
        "-days", "3650",
        "-set_serial", "1",
        "-extensions", "v3_ca",
        "-config", &ca_cnf.to_string_lossy(),
    ]));
    init_ca_state(p);

    // --- TSA cert ---
    let tsa_key = p.join("tsa.key");
    let tsa_csr = p.join("tsa.csr");
    let tsa_pem = p.join("tsa.pem");
    run(Command::new("openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&tsa_key));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &tsa_key.to_string_lossy(),
        "-out", &tsa_csr.to_string_lossy(),
        "-subj", "/CN=eidas-timestamp test TSA",
    ]));
    run(Command::new("openssl").args([
        "ca",
        "-batch",
        "-in", &tsa_csr.to_string_lossy(),
        "-out", &tsa_pem.to_string_lossy(),
        "-days", "3650",
        "-config", &ca_cnf.to_string_lossy(),
        "-extensions", "tsa_cert",
    ]));

    let ca_der = pem_to_der(&fs::read(&ca_pem).unwrap());
    let ca_cert = Certificate::from_der(&ca_der).unwrap();

    // `ts` subcommand config (used by `openssl ts -reply`).
    let ts_config = p.join("tsa.cnf");
    fs::write(&ts_config, openssl_ts_config(p)).unwrap();

    TsaFixture { ca_cert, tsa_pem, tsa_key, ts_config, dir }
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
default_days     = 3650
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

[tsa_cert]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
extendedKeyUsage       = critical, timeStamping
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
"#
    )
}

fn openssl_ts_config(base: &Path) -> String {
    let base = base.display();
    // openssl `ts -reply` needs a tsa section. `tsa_policy1` is the default
    // policy OID openssl ships with.
    format!(
        r#"
oid_section = new_oids

[new_oids]
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

[tsa]
default_tsa = tsa_config1

[tsa_config1]
dir              = {base}
serial           = $dir/tsa_serial
crypto_device    = builtin
signer_cert      = $dir/tsa.pem
certs            = $dir/ca.pem
signer_key       = $dir/tsa.key
signer_digest    = sha256
default_policy   = tsa_policy1
other_policies   = tsa_policy2, tsa_policy3
digests          = sha256, sha384, sha512
accuracy         = secs:1, millisecs:500, microsecs:100
clock_precision_digits = 0
ordering         = no
tsa_name         = no
ess_cert_id_chain = no
ess_cert_id_alg  = sha256
"#
    )
}

fn init_ca_state(base: &Path) {
    fs::create_dir_all(base.join("newcerts")).unwrap();
    fs::write(base.join("index.txt"), "").unwrap();
    fs::write(base.join("serial"), "1000\n").unwrap();
    fs::write(base.join("crlnumber"), "1000\n").unwrap();
    fs::write(base.join("tsa_serial"), "1000\n").unwrap();
}

fn make_timestamp_token(fx: &TsaFixture, data_path: &Path, out_token: &Path) {
    let base = fx.dir.path();
    let query_path = base.join("query.tsq");

    // 1. Generate a timestamp query over `data_path` using SHA-256.
    run(Command::new("openssl").args([
        "ts", "-query",
        "-data", &data_path.to_string_lossy(),
        "-sha256",
        "-cert",
        "-out", &query_path.to_string_lossy(),
    ]));
    // 2. Generate the reply (TimeStampResp), then extract the token.
    let reply_path = base.join("reply.tsr");
    run(Command::new("openssl").args([
        "ts", "-reply",
        "-queryfile", &query_path.to_string_lossy(),
        "-out", &reply_path.to_string_lossy(),
        "-config", &fx.ts_config.to_string_lossy(),
        "-section", "tsa_config1",
    ]));
    // 3. Extract just the TimeStampToken (the inner CMS ContentInfo).
    run(Command::new("openssl").args([
        "ts", "-reply",
        "-in", &reply_path.to_string_lossy(),
        "-token_out",
        "-out", &out_token.to_string_lossy(),
    ]));
    let _ = (fx.tsa_pem.as_path(), fx.tsa_key.as_path());
}

#[test]
fn tst_verification_round_trip() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx = build_tsa();

    let data_path = fx.dir.path().join("data.txt");
    let payload = b"Hello RFC 3161 timestamping!";
    fs::write(&data_path, payload).unwrap();
    let token_path = fx.dir.path().join("token.p7s");
    make_timestamp_token(&fx, &data_path, &token_path);
    let token = fs::read(&token_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(fx.ca_cert.clone())]);
    let result = verify_time_stamp_token(&token, payload, &builder, TimestampKind::Unbound)
        .expect("TST verification succeeds");

    assert!(result.info.valid);
    assert_eq!(result.info.kind, "unbound");
    assert!(
        result.info.tsa_subject.as_deref().unwrap().contains("test TSA"),
        "{}", result.info.tsa_subject.as_deref().unwrap_or("<none>")
    );
    assert_eq!(result.chain.chain.len(), 2);
}

#[test]
fn tst_detects_tampered_data() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx = build_tsa();

    let data_path = fx.dir.path().join("data.txt");
    fs::write(&data_path, b"original payload").unwrap();
    let token_path = fx.dir.path().join("token.p7s");
    make_timestamp_token(&fx, &data_path, &token_path);
    let token = fs::read(&token_path).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(fx.ca_cert.clone())]);
    let err = verify_time_stamp_token(&token, b"tampered payload", &builder, TimestampKind::Unbound)
        .expect_err("tampered payload must fail messageImprint check");
    assert!(
        matches!(err, eidas_core::Error::Timestamp(_)),
        "got {err:?}"
    );
}

#[test]
fn tst_fails_without_matching_trust_anchor() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let fx = build_tsa();
    let other_fx = build_tsa();

    let data_path = fx.dir.path().join("data.txt");
    fs::write(&data_path, b"payload").unwrap();
    let token_path = fx.dir.path().join("token.p7s");
    make_timestamp_token(&fx, &data_path, &token_path);
    let token = fs::read(&token_path).unwrap();

    let builder = ChainBuilder::new()
        .with_anchors([TrustAnchor::new(other_fx.ca_cert.clone())]);
    let err = verify_time_stamp_token(&token, b"payload", &builder, TimestampKind::Unbound)
        .expect_err("wrong-CA must fail chain build");
    assert!(matches!(err, eidas_core::Error::Timestamp(_)), "got {err:?}");
}
