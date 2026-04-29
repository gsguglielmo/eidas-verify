//! End-to-end CAdES B-T verification.
//!
//! We produce a CAdES B-B signature with openssl, request a timestamp over
//! its `SignerInfo.signature` bytes, and splice the timestamp token into the
//! signature's unsigned attributes so the result is CAdES-T.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use der::{Decode, Encode};
use eidas_cades::{verify_cades, CadesTrustMaterial};
use eidas_cms::CadesInput;
use eidas_core::{Level, Status, ValidationTime};
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
    let s = std::str::from_utf8(pem_bytes).expect("PEM");
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
    STANDARD.decode(b64).unwrap()
}

/// One CA, one signer cert, one TSA cert. All signed by the same CA so a
/// single anchor suffices.
struct Bt {
    ca_cert: Certificate,
    signer_pem: PathBuf,
    signer_key: PathBuf,
    tsa_cfg: PathBuf,
    dir: TempDir,
}

fn build_bt() -> Bt {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let ca_cnf = p.join("ca.cnf");
    fs::write(&ca_cnf, ca_config(p)).unwrap();

    // Root
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
        "-subj", "/CN=eidas-cades-bt test CA",
        "-days", "3650",
        "-set_serial", "1",
        "-extensions", "v3_ca",
        "-config", &ca_cnf.to_string_lossy(),
    ]));
    init_ca_state(p);

    // Signer
    issue(p, &ca_cnf, "signer", None);
    // TSA
    issue(p, &ca_cnf, "tsa", Some("tsa_cert"));

    let ca_cert = Certificate::from_der(&pem_to_der(&fs::read(&ca_pem).unwrap())).unwrap();

    let tsa_cfg = p.join("tsa.cnf");
    fs::write(&tsa_cfg, ts_config(p)).unwrap();

    Bt {
        ca_cert,
        signer_pem: p.join("signer.pem"),
        signer_key: p.join("signer.key"),
        tsa_cfg,
        dir,
    }
}

fn issue(p: &Path, cnf: &Path, name: &str, exts: Option<&str>) {
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &p.join(format!("{name}.key")).to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &p.join(format!("{name}.key")).to_string_lossy(),
        "-out", &p.join(format!("{name}.csr")).to_string_lossy(),
        "-subj", &format!("/CN=eidas-cades-bt {name}"),
    ]));
    let mut cmd = Command::new("openssl");
    cmd.args([
        "ca", "-batch",
        "-in", &p.join(format!("{name}.csr")).to_string_lossy(),
        "-out", &p.join(format!("{name}.pem")).to_string_lossy(),
        "-days", "3650",
        "-config", &cnf.to_string_lossy(),
    ]);
    if let Some(e) = exts {
        cmd.args(["-extensions", e]);
    }
    run(&mut cmd);
}

fn ca_config(base: &Path) -> String {
    let b = base.display();
    format!(
        r#"
[ca]
default_ca = CA_default
[CA_default]
dir              = {b}
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
distinguished_name = req_dn
prompt = no
default_md = sha256
[req_dn]
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

fn ts_config(base: &Path) -> String {
    let b = base.display();
    format!(
        r#"
oid_section = new_oids
[new_oids]
tsa_policy1 = 1.2.3.4.1
[tsa]
default_tsa = tsa_config1
[tsa_config1]
dir              = {b}
serial           = $dir/tsa_serial
crypto_device    = builtin
signer_cert      = $dir/tsa.pem
certs            = $dir/ca.pem
signer_key       = $dir/tsa.key
signer_digest    = sha256
default_policy   = tsa_policy1
digests          = sha256, sha384, sha512
accuracy         = secs:1
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

fn cades_bb_sign(bt: &Bt, data: &Path, out: &Path) {
    run(Command::new("openssl").args([
        "cms", "-sign", "-binary", "-md", "sha256", "-cades", "-nodetach",
        "-in", &data.to_string_lossy(),
        "-signer", &bt.signer_pem.to_string_lossy(),
        "-inkey", &bt.signer_key.to_string_lossy(),
        "-outform", "DER",
        "-out", &out.to_string_lossy(),
    ]));
}

fn make_tst_over(bt: &Bt, data: &Path, out: &Path) {
    let q = bt.dir.path().join("tst.tsq");
    let r = bt.dir.path().join("tst.tsr");
    run(Command::new("openssl").args([
        "ts", "-query",
        "-data", &data.to_string_lossy(),
        "-sha256",
        "-cert",
        "-out", &q.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "ts", "-reply",
        "-queryfile", &q.to_string_lossy(),
        "-out", &r.to_string_lossy(),
        "-config", &bt.tsa_cfg.to_string_lossy(),
        "-section", "tsa_config1",
    ]));
    run(Command::new("openssl").args([
        "ts", "-reply",
        "-in", &r.to_string_lossy(),
        "-token_out",
        "-out", &out.to_string_lossy(),
    ]));
}

/// Add an `id-aa-signatureTimeStampToken` unsigned attribute to a CAdES B-B
/// CMS blob. Returns the rewritten DER.
///
/// Strategy: re-decode `ContentInfo` → `SignedData` → first `SignerInfo`,
/// construct an `Attribute { oid: 1.2.840.113549.1.9.16.2.14, values: [token] }`,
/// put it in the SignerInfo's `unsignedAttrs` (creating the optional field
/// if it was absent), and re-encode the whole thing.
fn splice_signature_timestamp(cms_der: &[u8], token_der: &[u8]) -> Vec<u8> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::asn1::{Any, ObjectIdentifier, SetOfVec};
    use x509_cert::attr::Attribute;

    let mut ci = ContentInfo::from_der(cms_der).unwrap();
    let sd_bytes = ci.content.to_der().unwrap();
    let mut sd = SignedData::from_der(&sd_bytes).unwrap();

    // Take ownership of the first signer-info.
    let mut signers = sd.signer_infos.0.clone().into_vec();
    let mut signer = signers.remove(0);

    // Build the attribute.
    let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
    let token_any = Any::from_der(token_der).unwrap();
    let mut values = SetOfVec::new();
    values.insert(token_any).unwrap();
    let attr = Attribute { oid, values };

    match signer.unsigned_attrs.as_mut() {
        Some(existing) => {
            existing.insert(attr).unwrap();
        }
        None => {
            let mut new_attrs = SetOfVec::new();
            new_attrs.insert(attr).unwrap();
            signer.unsigned_attrs = Some(new_attrs);
        }
    }

    // Rebuild SignerInfos. The cms crate exposes `SignerInfos(SetOfVec<SignerInfo>)`
    // and provides no public constructor from a Vec; use TryFrom<Vec>.
    let mut rebuilt = vec![signer];
    rebuilt.extend(signers);
    sd.signer_infos = cms::signed_data::SignerInfos::try_from(rebuilt).unwrap();

    // Re-encode SignedData back into the ContentInfo's `content: Any`.
    let new_sd_der = sd.to_der().unwrap();
    let new_any = Any::from_der(&new_sd_der).unwrap();
    ci.content = new_any;
    ci.to_der().unwrap()
}

#[test]
fn cades_bt_round_trip_lifts_level_to_bt() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let bt = build_bt();
    let data = bt.dir.path().join("data.txt");
    fs::write(&data, b"CAdES-T payload").unwrap();

    // B-B signature
    let bb = bt.dir.path().join("bb.p7s");
    cades_bb_sign(&bt, &data, &bb);
    let bb_bytes = fs::read(&bb).unwrap();

    // Extract the signer.signature bytes that the timestamp must cover.
    let signer_signature = {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        let ci = ContentInfo::from_der(&bb_bytes).unwrap();
        let sd = SignedData::from_der(&ci.content.to_der().unwrap()).unwrap();
        sd.signer_infos.0.iter().next().unwrap().signature.clone()
    };

    // Write signature bytes to a file and timestamp them.
    let sig_path = bt.dir.path().join("sig.bin");
    fs::write(&sig_path, signer_signature.as_bytes()).unwrap();
    let tok_path = bt.dir.path().join("tok.p7s");
    make_tst_over(&bt, &sig_path, &tok_path);
    let token = fs::read(&tok_path).unwrap();

    // Splice into CMS.
    let spliced = splice_signature_timestamp(&bb_bytes, &token);

    // Verify.
    let trust = CadesTrustMaterial::new().with_anchors([bt.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_cades(
        &CadesInput { cms: &spliced, detached_content: None },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    assert_eq!(report.signatures.len(), 1);
    let sr = &report.signatures[0];
    assert_eq!(sr.status, Status::TotalPassed, "diagnostics: {:?}", sr.diagnostics);
    assert_eq!(sr.level_reached, Level::BT, "expected B-T, got {:?}", sr.level_reached);
    assert_eq!(sr.timestamps.len(), 1);
    assert_eq!(sr.timestamps[0].kind, "signature");
    assert!(sr.signing_time_best.is_some());
}

#[test]
fn cades_bb_without_timestamp_stays_at_bb() {
    // Regression test: un-timestamped signature must keep Level::BB
    // and not bleed into BT just because unsigned_attrs is absent.
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let bt = build_bt();
    let data = bt.dir.path().join("data.txt");
    fs::write(&data, b"plain B-B payload").unwrap();
    let bb = bt.dir.path().join("bb.p7s");
    cades_bb_sign(&bt, &data, &bb);
    let bb_bytes = fs::read(&bb).unwrap();

    let trust = CadesTrustMaterial::new().with_anchors([bt.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_cades(
        &CadesInput { cms: &bb_bytes, detached_content: None },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].level_reached, Level::BB);
    assert_eq!(report.signatures[0].status, Status::TotalPassed);
}

#[test]
fn cades_bt_invalid_timestamp_keeps_bb_with_warning() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let bt = build_bt();
    let data = bt.dir.path().join("data.txt");
    fs::write(&data, b"payload").unwrap();
    let bb = bt.dir.path().join("bb.p7s");
    cades_bb_sign(&bt, &data, &bb);
    let bb_bytes = fs::read(&bb).unwrap();

    // Timestamp over *wrong* data — won't match the real signer.signature.
    let wrong = bt.dir.path().join("wrong.bin");
    fs::write(&wrong, b"wrong data").unwrap();
    let tok = bt.dir.path().join("wrong.tok");
    make_tst_over(&bt, &wrong, &tok);
    let token = fs::read(&tok).unwrap();
    let spliced = splice_signature_timestamp(&bb_bytes, &token);

    let trust = CadesTrustMaterial::new().with_anchors([bt.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_cades(
        &CadesInput { cms: &spliced, detached_content: None },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    let sr = &report.signatures[0];
    // B-B still valid; timestamp rejected so level doesn't lift.
    assert_eq!(sr.status, Status::TotalPassed);
    assert_eq!(sr.level_reached, Level::BB);
    let codes: Vec<_> = sr.diagnostics.iter().map(|d| d.code).collect();
    assert!(
        codes.contains(&"SIGNATURE_TIMESTAMP_INVALID"),
        "expected SIGNATURE_TIMESTAMP_INVALID, got {codes:?}"
    );
}
