//! End-to-end CAdES B-LT verification.
//!
//! Extends the B-T fixture with an embedded CRL in
//! `id-aa-ets-revocationValues` and confirms the verifier lifts to Level::BLT.

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

struct Lt {
    ca_cert: Certificate,
    crl_der: Vec<u8>,
    signer_pem: PathBuf,
    signer_key: PathBuf,
    tsa_cfg: PathBuf,
    dir: TempDir,
}

fn build_lt() -> Lt {
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
        "-subj", "/CN=eidas-cades-lt test CA",
        "-days", "3650",
        "-set_serial", "1",
        "-extensions", "v3_ca",
        "-config", &ca_cnf.to_string_lossy(),
    ]));
    init_ca_state(p);

    issue(p, &ca_cnf, "signer", None);
    issue(p, &ca_cnf, "tsa", Some("tsa_cert"));

    // Generate a CRL — no revoked certs, just an empty one that covers the signer.
    let crl_pem = p.join("crl.pem");
    run(Command::new("openssl").args([
        "ca", "-gencrl",
        "-out", &crl_pem.to_string_lossy(),
        "-config", &ca_cnf.to_string_lossy(),
    ]));
    let crl_der = pem_to_der(&fs::read(&crl_pem).unwrap());

    let ca_cert = Certificate::from_der(&pem_to_der(&fs::read(&ca_pem).unwrap())).unwrap();
    let tsa_cfg = p.join("tsa.cnf");
    fs::write(&tsa_cfg, ts_config(p)).unwrap();

    Lt {
        ca_cert,
        crl_der,
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
        "-subj", &format!("/CN=eidas-cades-lt {name}"),
    ]));
    let mut cmd = Command::new("openssl");
    cmd.args([
        "ca", "-batch",
        "-in", &p.join(format!("{name}.csr")).to_string_lossy(),
        "-out", &p.join(format!("{name}.pem")).to_string_lossy(),
        "-days", "3650",
        "-config", &cnf.to_string_lossy(),
    ]);
    if let Some(e) = exts { cmd.args(["-extensions", e]); }
    run(&mut cmd);
}

fn ca_config(base: &Path) -> String {
    let b = base.display();
    format!(r#"
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
"#)
}

fn ts_config(base: &Path) -> String {
    let b = base.display();
    format!(r#"
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
"#)
}

fn init_ca_state(base: &Path) {
    fs::create_dir_all(base.join("newcerts")).unwrap();
    fs::write(base.join("index.txt"), "").unwrap();
    fs::write(base.join("serial"), "1000\n").unwrap();
    fs::write(base.join("crlnumber"), "1000\n").unwrap();
    fs::write(base.join("tsa_serial"), "1000\n").unwrap();
}

fn cades_sign(lt: &Lt, data: &Path, out: &Path) {
    run(Command::new("openssl").args([
        "cms", "-sign", "-binary", "-md", "sha256", "-cades", "-nodetach",
        "-in", &data.to_string_lossy(),
        "-signer", &lt.signer_pem.to_string_lossy(),
        "-inkey", &lt.signer_key.to_string_lossy(),
        "-outform", "DER",
        "-out", &out.to_string_lossy(),
    ]));
}

fn make_tst(lt: &Lt, data: &Path, out: &Path) {
    let q = lt.dir.path().join("tst.tsq");
    let r = lt.dir.path().join("tst.tsr");
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
        "-config", &lt.tsa_cfg.to_string_lossy(),
        "-section", "tsa_config1",
    ]));
    run(Command::new("openssl").args([
        "ts", "-reply",
        "-in", &r.to_string_lossy(),
        "-token_out",
        "-out", &out.to_string_lossy(),
    ]));
}

/// Add a signature-time-stamp AND revocation-values attribute to a B-B CMS.
fn splice_bt_plus_lt(cms_der: &[u8], token_der: &[u8], crl_der: &[u8]) -> Vec<u8> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::asn1::{Any, ObjectIdentifier, SetOfVec};
    use der::{Header, Length, Reader, Tag, TagNumber};
    use x509_cert::attr::Attribute;

    let mut ci = ContentInfo::from_der(cms_der).unwrap();
    let mut sd = SignedData::from_der(&ci.content.to_der().unwrap()).unwrap();

    let mut signers = sd.signer_infos.0.clone().into_vec();
    let mut signer = signers.remove(0);

    // signature-time-stamp
    let ts_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
    let token_any = Any::from_der(token_der).unwrap();
    let mut ts_values = SetOfVec::new();
    ts_values.insert(token_any).unwrap();
    let ts_attr = Attribute { oid: ts_oid, values: ts_values };

    // ets-revocationValues:
    //   SEQUENCE {
    //     [0] SEQUENCE OF CertificateList  -- crlVals
    //   }
    //
    // Build the inner SEQUENCE OF CertificateList first, then wrap in [0] IMPLICIT,
    // then wrap in the outer SEQUENCE.
    let seq_of_crls = {
        let mut body = Vec::new();
        body.extend_from_slice(crl_der);
        let mut out = Vec::new();
        let hdr = Header::new(Tag::Sequence, Length::new(body.len() as u16)).unwrap();
        hdr.encode(&mut out).unwrap();
        out.extend_from_slice(&body);
        out
    };
    let crls_tagged = {
        // [0] IMPLICIT SEQUENCE OF X replaces the SEQUENCE tag with [0] —
        // we keep the body but re-tag. Find the body offset by decoding the
        // existing outer SEQUENCE header.
        let (body_start, body_len) = {
            let mut r = der::SliceReader::new(&seq_of_crls).unwrap();
            let h = Header::decode(&mut r).unwrap();
            let consumed = u32::from(r.position()) as usize;
            (consumed, u32::from(h.length) as usize)
        };
        let content = &seq_of_crls[body_start..body_start + body_len];
        // Now emit a context-specific [0] constructed wrapper around `content`.
        let mut out = Vec::new();
        let tag = Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        };
        let hdr = Header::new(tag, Length::new(content.len() as u16)).unwrap();
        hdr.encode(&mut out).unwrap();
        out.extend_from_slice(content);
        out
    };
    let rev_values_sequence = {
        // Outer SEQUENCE over just the [0] element (no ocspVals, no other).
        let mut out = Vec::new();
        let hdr = Header::new(Tag::Sequence, Length::new(crls_tagged.len() as u16)).unwrap();
        hdr.encode(&mut out).unwrap();
        out.extend_from_slice(&crls_tagged);
        out
    };
    let rev_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");
    let rev_any = Any::from_der(&rev_values_sequence).unwrap();
    let mut rev_values = SetOfVec::new();
    rev_values.insert(rev_any).unwrap();
    let rev_attr = Attribute { oid: rev_oid, values: rev_values };

    // Insert both attributes.
    match signer.unsigned_attrs.as_mut() {
        Some(existing) => {
            existing.insert(ts_attr).unwrap();
            existing.insert(rev_attr).unwrap();
        }
        None => {
            let mut set = SetOfVec::new();
            set.insert(ts_attr).unwrap();
            set.insert(rev_attr).unwrap();
            signer.unsigned_attrs = Some(set);
        }
    }

    let mut rebuilt = vec![signer];
    rebuilt.extend(signers);
    sd.signer_infos = cms::signed_data::SignerInfos::try_from(rebuilt).unwrap();
    ci.content = Any::from_der(&sd.to_der().unwrap()).unwrap();
    ci.to_der().unwrap()
}

#[test]
fn cades_blt_round_trip_lifts_level_to_blt() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let lt = build_lt();
    let data = lt.dir.path().join("data.txt");
    fs::write(&data, b"CAdES-LT payload").unwrap();

    let bb = lt.dir.path().join("bb.p7s");
    cades_sign(&lt, &data, &bb);
    let bb_bytes = fs::read(&bb).unwrap();

    // Build TST over signer.signature.
    let sig_bytes = {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        let ci = ContentInfo::from_der(&bb_bytes).unwrap();
        let sd = SignedData::from_der(&ci.content.to_der().unwrap()).unwrap();
        sd.signer_infos.0.iter().next().unwrap().signature.as_bytes().to_vec()
    };
    let sig_path = lt.dir.path().join("sig.bin");
    fs::write(&sig_path, &sig_bytes).unwrap();
    let tok = lt.dir.path().join("tok.p7s");
    make_tst(&lt, &sig_path, &tok);
    let token = fs::read(&tok).unwrap();

    let spliced = splice_bt_plus_lt(&bb_bytes, &token, &lt.crl_der);

    let trust = CadesTrustMaterial::new().with_anchors([lt.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_cades(
        &CadesInput { cms: &spliced, detached_content: None },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    let sr = &report.signatures[0];
    assert_eq!(
        sr.status, Status::TotalPassed,
        "diagnostics: {:?}", sr.diagnostics
    );
    assert_eq!(
        sr.level_reached, Level::BLT,
        "expected B-LT, got {:?}; diagnostics: {:?}",
        sr.level_reached, sr.diagnostics
    );
    assert!(!sr.revocation.is_empty(), "expected embedded revocation entries");
    assert_eq!(sr.revocation[0].source, "CRL");
}
