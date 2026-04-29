//! End-to-end TrustedList parsing test.
//!
//! Builds a minimal TSL XML fixture (schema-shaped — not schema-perfect) with
//! one TSP and one CA/QC service, feeds it through `parse_trusted_list`, and
//! confirms the typed output and qualification lookup both behave as expected.

use std::process::Command;

use chrono::{TimeZone, Utc};
use der::Decode;
use eidas_trust::qualify::{qualification_for, qualifier, service_type, status};
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

fn make_cert() -> (Vec<u8>, TempDir) {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("ca.key");
    let pem = dir.path().join("ca.pem");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &key.to_string_lossy(),
        "-out", &pem.to_string_lossy(),
        "-subj", "/CN=TSL test CA",
        "-days", "3650",
        "-set_serial", "1",
    ]));
    let der = pem_to_der(&std::fs::read(&pem).unwrap());
    (der, dir)
}

fn b64(v: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(v)
}

fn build_minimal_tsl_xml(ca_der: &[u8]) -> String {
    let ca_b64 = b64(ca_der);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList
    xmlns="http://uri.etsi.org/02231/v2#"
    xmlns:tslx="http://uri.etsi.org/02231/v2/additionaltypes#"
    xmlns:ecc="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>42</TSLSequenceNumber>
    <SchemeType>
      <URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUgeneric</URI>
    </SchemeType>
    <SchemeTerritory>DE</SchemeTerritory>
    <ListIssueDateTime>2024-06-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate>
      <dateTime>2024-12-01T00:00:00Z</dateTime>
    </NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName>
          <Name xml:lang="en">Acme Trust Services</Name>
        </TSPName>
        <TSPTradeName>
          <Name xml:lang="en">Acme</Name>
        </TSPTradeName>
        <TSPAddress>
          <PostalAddresses>
            <PostalAddress xml:lang="en">
              <StreetAddress>1 Trust Way</StreetAddress>
              <Locality>Berlin</Locality>
              <CountryName>DE</CountryName>
            </PostalAddress>
          </PostalAddresses>
        </TSPAddress>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>{service_type}</ServiceTypeIdentifier>
            <ServiceName>
              <Name xml:lang="en">Acme Qualified CA</Name>
            </ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>{ca}</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>{status}</ServiceStatus>
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
        service_type = service_type::CA_QC,
        status = status::GRANTED,
        qforesig = qualifier::QC_FOR_ESIG,
        qwithqscd = qualifier::QC_WITH_QSCD,
        ca = ca_b64,
    )
}

#[test]
fn parses_minimal_tsl_scheme_information() {
    if !openssl_present() {
        eprintln!("skipping: openssl not found");
        return;
    }
    let (ca_der, _dir) = make_cert();
    let xml = build_minimal_tsl_xml(&ca_der);
    let tl = parse_trusted_list(xml.as_bytes()).unwrap();
    assert_eq!(tl.territory.as_deref(), Some("DE"));
    assert_eq!(tl.sequence_number, Some(42));
    assert!(tl.list_issue_datetime.is_some());
    assert!(tl.next_update.is_some());
}

#[test]
fn parses_minimal_tsl_provider_and_service() {
    if !openssl_present() {
        eprintln!("skipping: openssl not found");
        return;
    }
    let (ca_der, _dir) = make_cert();
    let xml = build_minimal_tsl_xml(&ca_der);
    let tl = parse_trusted_list(xml.as_bytes()).unwrap();

    assert_eq!(tl.providers.len(), 1);
    let tsp = &tl.providers[0];
    assert_eq!(tsp.name.as_deref(), Some("Acme Trust Services"));
    assert_eq!(tsp.trade_name.as_deref(), Some("Acme"));
    assert_eq!(tsp.country.as_deref(), Some("DE"));

    assert_eq!(tsp.services.len(), 1);
    let svc = &tsp.services[0];
    assert_eq!(
        svc.service_type_identifier.as_deref(),
        Some(service_type::CA_QC)
    );
    assert_eq!(svc.current_status.as_deref(), Some(status::GRANTED));
    assert_eq!(svc.certificates.len(), 1, "exactly one X.509 cert parsed");
    assert!(svc.qualifiers.contains(&qualifier::QC_FOR_ESIG.to_string()));
    assert!(svc.qualifiers.contains(&qualifier::QC_WITH_QSCD.to_string()));
}

#[test]
fn qualification_for_matches_listed_cert_by_spki() {
    if !openssl_present() {
        eprintln!("skipping: openssl not found");
        return;
    }
    let (ca_der, _dir) = make_cert();
    let xml = build_minimal_tsl_xml(&ca_der);
    let tl = parse_trusted_list(xml.as_bytes()).unwrap();
    let tls = TrustedLists { lists: vec![tl] };

    let target = Certificate::from_der(&ca_der).unwrap();
    let at = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();
    let m = qualification_for(&tls, &target, at).expect("matches listed service");
    assert_eq!(m.territory.as_deref(), Some("DE"));
    assert_eq!(m.status_at.as_deref(), Some(status::GRANTED));
    assert!(m.service.qualifiers.contains(&qualifier::QC_FOR_ESIG.to_string()));
}

#[test]
fn qualification_for_misses_when_cert_not_in_any_list() {
    if !openssl_present() {
        eprintln!("skipping: openssl not found");
        return;
    }
    let (ca_der, dir_a) = make_cert();
    let xml = build_minimal_tsl_xml(&ca_der);
    let tl = parse_trusted_list(xml.as_bytes()).unwrap();
    let tls = TrustedLists { lists: vec![tl] };

    let (other_der, _dir_b) = make_cert();
    let other = Certificate::from_der(&other_der).unwrap();
    let at = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();
    assert!(qualification_for(&tls, &other, at).is_none());
    let _ = dir_a;
}
