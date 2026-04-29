//! End-to-end qualification engine tests.
//!
//! Builds a PKI (root CA + leaf signer), writes a minimal TSL listing the
//! root CA as a CA/QC service, then exercises the engine for each of:
//! - listed CA/QC + QCWithQSCD qualifier → QES
//! - listed CA/QC + QCNoQSCD qualifier → AdES-QC
//! - listed CA/QC + QCQSCDStatusAsInCert + cert QcSSCD → QES
//! - listed CA/QC + QCQSCDStatusAsInCert without cert QcSSCD → AdES-QC
//! - withdrawn service → NotAdES
//! - no TSL match → baseline AdES

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{TimeZone, Utc};
use der::Decode;
use eidas_core::Qualification;
use eidas_qualify::{qualify_signer, QualificationInput};
use eidas_trust::qualify::{qualifier, service_type, status};
use eidas_trust::{parse_trusted_list, TrustedLists};
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

fn b64(v: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(v)
}

struct Pki {
    ca_der: Vec<u8>,
    leaf_der_plain: Vec<u8>,
    leaf_der_qc_sscd: Vec<u8>,
    leaf_der_qc_no_sscd: Vec<u8>,
    _dir: TempDir,
}

fn build_pki() -> Pki {
    let dir = TempDir::new().unwrap();
    let p = dir.path();

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
        "-subj", "/CN=qualify test CA",
        "-days", "3650",
        "-set_serial", "1",
    ]));

    let leaf_plain = issue_leaf(p, &ca_pem, &ca_key, "plain", &[]);
    let leaf_qc_sscd =
        issue_leaf(p, &ca_pem, &ca_key, "qc-sscd", &[("QcCompliance", "0.4.0.1862.1.1"), ("QcSSCD", "0.4.0.1862.1.4")]);
    issue_leaf(p, &ca_pem, &ca_key, "qc-no-sscd", &[("QcCompliance", "0.4.0.1862.1.1")]);

    Pki {
        ca_der: pem_to_der(&fs::read(&ca_pem).unwrap()),
        leaf_der_plain: pem_to_der(&fs::read(p.join("plain.pem")).unwrap()),
        leaf_der_qc_sscd: pem_to_der(&fs::read(p.join("qc-sscd.pem")).unwrap()),
        leaf_der_qc_no_sscd: pem_to_der(&fs::read(p.join("qc-no-sscd.pem")).unwrap()),
        _dir: dir,
    }
}

/// Issue a leaf cert with optional qcStatements OIDs. OpenSSL config lets us
/// declare `qcStatements = DER:…` but building the DER manually is simpler:
/// we use the `ASN1:SEQUENCE:…` config syntax.
fn issue_leaf(
    p: &Path,
    ca_pem: &Path,
    ca_key: &Path,
    name: &str,
    qc_oids: &[(&str, &str)],
) -> Vec<u8> {
    let key = p.join(format!("{name}.key"));
    let csr = p.join(format!("{name}.csr"));
    let pem = p.join(format!("{name}.pem"));

    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &key.to_string_lossy(),
        "-out", &csr.to_string_lossy(),
        "-subj", &format!("/CN=qualify test {name}"),
    ]));

    // Build an openssl.cnf fragment describing the qcStatements extension.
    let ext = p.join(format!("{name}.ext"));
    if qc_oids.is_empty() {
        fs::write(
            &ext,
            "keyUsage = critical, digitalSignature, nonRepudiation\nbasicConstraints = CA:FALSE\n",
        )
        .unwrap();
    } else {
        // Build via ASN1 generator syntax — each qcStatement is a SEQUENCE
        // with just the OID (no params).
        let mut conf = String::from("keyUsage = critical, digitalSignature, nonRepudiation\nbasicConstraints = CA:FALSE\n");
        conf.push_str("1.3.6.1.5.5.7.1.3 = ASN1:SEQUENCE:qcs\n\n[qcs]\n");
        for (i, (_name, _oid)) in qc_oids.iter().enumerate() {
            conf.push_str(&format!("s{i} = SEQUENCE:qcs_{i}\n"));
        }
        for (i, (_name, oid)) in qc_oids.iter().enumerate() {
            conf.push_str(&format!("\n[qcs_{i}]\nstmt = OID:{oid}\n"));
        }
        fs::write(&ext, conf).unwrap();
    }

    run(Command::new("openssl").args([
        "x509", "-req",
        "-in", &csr.to_string_lossy(),
        "-CA", &ca_pem.to_string_lossy(),
        "-CAkey", &ca_key.to_string_lossy(),
        "-CAcreateserial",
        "-out", &pem.to_string_lossy(),
        "-days", "3650",
        "-sha256",
        "-extfile", &ext.to_string_lossy(),
    ]));

    pem_to_der(&fs::read(&pem).unwrap())
}

fn tsl_xml_with(
    ca_der: &[u8],
    service_status: &str,
    qualifier_uris: &[&str],
) -> String {
    let ca = b64(ca_der);
    let qualifiers_xml: String = qualifier_uris
        .iter()
        .map(|u| format!(r#"<Qualifier uri="{u}"/>"#))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeType><URI>http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUgeneric</URI></SchemeType>
    <SchemeTerritory>DE</SchemeTerritory>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Acme</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>{svc_type}</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Acme QC CA</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>{ca}</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>{service_status}</ServiceStatus>
            <StatusStartingTime>2023-01-01T00:00:00Z</StatusStartingTime>
            <ServiceInformationExtensions>
              <Extension Critical="true">
                <Qualifications>
                  <QualificationElement>
                    <Qualifiers>{qualifiers_xml}</Qualifiers>
                  </QualificationElement>
                </Qualifications>
              </Extension>
            </ServiceInformationExtensions>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>
"#,
        svc_type = service_type::CA_QC,
    )
}

fn run_engine(
    signer: &Certificate,
    chain: &[Certificate],
    tsl_xml: &str,
) -> eidas_qualify::QualificationOutput {
    let tl = parse_trusted_list(tsl_xml.as_bytes()).unwrap();
    let tls = TrustedLists { lists: vec![tl] };
    let at = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();
    qualify_signer(&QualificationInput {
        signer,
        chain,
        trusted_lists: &tls,
        at,
        baseline: Qualification::AdES,
    })
}

#[test]
fn qes_when_service_has_qcwithqscd_qualifier() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let ca = Certificate::from_der(&pki.ca_der).unwrap();
    let leaf = Certificate::from_der(&pki.leaf_der_qc_sscd).unwrap();
    let chain = vec![leaf.clone(), ca.clone()];
    let xml = tsl_xml_with(&pki.ca_der, status::GRANTED, &[qualifier::QC_WITH_QSCD]);
    let out = run_engine(&leaf, &chain, &xml);
    assert_eq!(out.qualification, Qualification::QES, "diagnostics: {:?}", out.diagnostics);
    assert_eq!(out.territory.as_deref(), Some("DE"));
}

#[test]
fn ades_qc_when_service_has_qcnoqscd() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let ca = Certificate::from_der(&pki.ca_der).unwrap();
    let leaf = Certificate::from_der(&pki.leaf_der_qc_sscd).unwrap();
    let chain = vec![leaf.clone(), ca.clone()];
    let xml = tsl_xml_with(&pki.ca_der, status::GRANTED, &[qualifier::QC_NO_QSCD]);
    let out = run_engine(&leaf, &chain, &xml);
    assert_eq!(out.qualification, Qualification::AdESqc, "diagnostics: {:?}", out.diagnostics);
}

#[test]
fn qes_when_status_as_in_cert_and_cert_has_qcsscd() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let ca = Certificate::from_der(&pki.ca_der).unwrap();
    let leaf = Certificate::from_der(&pki.leaf_der_qc_sscd).unwrap();
    let chain = vec![leaf.clone(), ca.clone()];
    let xml = tsl_xml_with(&pki.ca_der, status::GRANTED, &[qualifier::QC_QSCD_STATUS_AS_IN_CERT]);
    let out = run_engine(&leaf, &chain, &xml);
    assert_eq!(out.qualification, Qualification::QES, "diagnostics: {:?}", out.diagnostics);
}

#[test]
fn ades_qc_when_status_as_in_cert_but_cert_has_no_qcsscd() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let ca = Certificate::from_der(&pki.ca_der).unwrap();
    let leaf = Certificate::from_der(&pki.leaf_der_qc_no_sscd).unwrap();
    let chain = vec![leaf.clone(), ca.clone()];
    let xml = tsl_xml_with(&pki.ca_der, status::GRANTED, &[qualifier::QC_QSCD_STATUS_AS_IN_CERT]);
    let out = run_engine(&leaf, &chain, &xml);
    assert_eq!(out.qualification, Qualification::AdESqc, "diagnostics: {:?}", out.diagnostics);
}

#[test]
fn not_ades_when_service_is_withdrawn() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let ca = Certificate::from_der(&pki.ca_der).unwrap();
    let leaf = Certificate::from_der(&pki.leaf_der_qc_sscd).unwrap();
    let chain = vec![leaf.clone(), ca.clone()];
    let xml = tsl_xml_with(&pki.ca_der, status::WITHDRAWN, &[qualifier::QC_WITH_QSCD]);
    let out = run_engine(&leaf, &chain, &xml);
    assert_eq!(out.qualification, Qualification::NotAdES, "diagnostics: {:?}", out.diagnostics);
}

#[test]
fn baseline_ades_when_no_tsl_match() {
    if !openssl_present() { return; }
    let pki = build_pki();
    // Use plain leaf and chain against a TSL built for a *different* CA.
    let other_dir = TempDir::new().unwrap();
    let other_ca_key = other_dir.path().join("ca.key");
    let other_ca_pem = other_dir.path().join("ca.pem");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &other_ca_key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &other_ca_key.to_string_lossy(),
        "-out", &other_ca_pem.to_string_lossy(),
        "-subj", "/CN=unrelated CA",
        "-days", "3650",
        "-set_serial", "99",
    ]));
    let unrelated_ca_der = pem_to_der(&fs::read(&other_ca_pem).unwrap());
    let xml = tsl_xml_with(&unrelated_ca_der, status::GRANTED, &[qualifier::QC_WITH_QSCD]);

    let ca = Certificate::from_der(&pki.ca_der).unwrap();
    let leaf = Certificate::from_der(&pki.leaf_der_plain).unwrap();
    let chain = vec![leaf.clone(), ca.clone()];
    let out = run_engine(&leaf, &chain, &xml);
    assert_eq!(out.qualification, Qualification::AdES, "diagnostics: {:?}", out.diagnostics);
    assert!(out.territory.is_none());
}

#[test]
fn cert_qc_statements_are_parsed() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let leaf = Certificate::from_der(&pki.leaf_der_qc_sscd).unwrap();
    let qc = eidas_qualify::qcstatements::parse_qc_statements(&leaf).unwrap();
    assert!(qc.qc_compliance);
    assert!(qc.qc_sscd);
}

// Silence unused-PathBuf warning.
#[allow(dead_code)]
fn _t(_p: PathBuf) {}
