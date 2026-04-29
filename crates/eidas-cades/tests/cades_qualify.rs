//! End-to-end: CAdES B-B signature is qualified as QES when the chain's CA
//! is listed in a supplied TSL as `CA/QC` with the `QCWithQSCD` qualifier.

#![cfg(feature = "ts-119-615")]

use std::fs;
use std::process::Command;

use der::Decode;
use eidas_cades::{verify_cades, CadesTrustMaterial};
use eidas_cms::CadesInput;
use eidas_core::{Level, Qualification, Status, ValidationTime};
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

#[test]
fn cades_is_qualified_as_qes_when_ca_listed_with_qscd() {
    if !openssl_present() { return; }
    let dir = TempDir::new().unwrap();
    let p = dir.path();

    // CA
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
        "-subj", "/CN=qualify cades CA",
        "-days", "3650",
        "-set_serial", "1",
    ]));
    let ca_der = pem_to_der(&fs::read(&ca_pem).unwrap());

    // Leaf
    let leaf_key = p.join("leaf.key");
    let leaf_csr = p.join("leaf.csr");
    let leaf_pem = p.join("leaf.pem");
    let leaf_ext = p.join("leaf.ext");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &leaf_key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", "/CN=qualify cades signer",
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

    // Data + CAdES B-B
    let data = p.join("data.txt");
    fs::write(&data, b"qualification test payload").unwrap();
    let sig = p.join("sig.p7s");
    run(Command::new("openssl").args([
        "cms", "-sign", "-binary", "-md", "sha256", "-cades", "-nodetach",
        "-in", &data.to_string_lossy(),
        "-signer", &leaf_pem.to_string_lossy(),
        "-inkey", &leaf_key.to_string_lossy(),
        "-outform", "DER",
        "-out", &sig.to_string_lossy(),
    ]));
    let cms_bytes = fs::read(&sig).unwrap();

    // Build TSL listing the CA as CA/QC with QCWithQSCD.
    let tsl = format!(
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
      <TSPInformation><TSPName><Name xml:lang="en">Acme</Name></TSPName></TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>{svc_type}</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Acme QC CA</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>{ca}</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>{granted}</ServiceStatus>
            <StatusStartingTime>2023-01-01T00:00:00Z</StatusStartingTime>
            <ServiceInformationExtensions>
              <Extension Critical="true">
                <Qualifications>
                  <QualificationElement>
                    <Qualifiers>
                      <Qualifier uri="{qforesig}"/>
                      <Qualifier uri="{qwithqscd}"/>
                    </Qualifiers>
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
        granted = status::GRANTED,
        qforesig = qualifier::QC_FOR_ESIG,
        qwithqscd = qualifier::QC_WITH_QSCD,
        ca = b64(&ca_der),
    );
    let tl = parse_trusted_list(tsl.as_bytes()).unwrap();
    let tls = TrustedLists { lists: vec![tl] };

    let ca = Certificate::from_der(&ca_der).unwrap();
    let trust = CadesTrustMaterial::new()
        .with_anchors([ca])
        .with_trusted_lists(tls);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_cades(
        &CadesInput { cms: &cms_bytes, detached_content: None },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    let sr = &report.signatures[0];
    assert_eq!(sr.status, Status::TotalPassed, "diag: {:?}", sr.diagnostics);
    assert_eq!(sr.level_reached, Level::BB);
    assert_eq!(sr.qualification, Qualification::QES, "diag: {:?}", sr.diagnostics);
}
