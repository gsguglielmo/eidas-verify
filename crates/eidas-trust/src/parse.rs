//! TSL XML → Rust structs.
//!
//! We deliberately do not model every TSL sub-element. Only the fields the
//! qualification engine (ETSI TS 119 615) needs are captured. Everything
//! else is skipped silently — a smaller surface to test and harden.

use chrono::{DateTime, Utc};
use der::Decode;
use eidas_core::{Error, Result};
use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;
use x509_cert::Certificate;

use crate::model::{ServiceStatus, TrustService, TrustServiceProvider, TrustedList};

/// Parse a single ETSI TS 119 612 TrustServiceStatusList XML.
pub fn parse_trusted_list(xml: &[u8]) -> Result<TrustedList> {
    let mut reader = Reader::from_reader(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut out = TrustedList {
        source_xml: xml.to_vec(),
        ..TrustedList::default()
    };

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("read event: {e}")))?
        {
            Event::Eof => break,
            Event::Start(ref e) => {
                let name = local(e.name());
                match name.as_str() {
                    "SchemeInformation" => parse_scheme_information(&mut reader, &mut out)?,
                    "TrustServiceProviderList" => {
                        parse_provider_list(&mut reader, &mut out.providers)?;
                    }
                    _ => {} // skip unknown top-level siblings (Signature, etc.)
                }
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(out)
}

fn parse_scheme_information(
    reader: &mut Reader<&[u8]>,
    out: &mut TrustedList,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("scheme info: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "SchemeInformation" => break,
            Event::Start(ref e) => {
                let name = local(e.name());
                match name.as_str() {
                    "SchemeTerritory" => {
                        out.territory = Some(read_text(reader, "SchemeTerritory")?);
                    }
                    "SchemeTypeCommunityRules" | "SchemeType" => {
                        // We don't distinguish LOTL vs. MS TL here; keep
                        // whichever URI shows up first.
                        out.scheme_type
                            .get_or_insert_with(|| read_text_inside(reader, &name).unwrap_or_default());
                    }
                    "TSLSequenceNumber" => {
                        let txt = read_text(reader, "TSLSequenceNumber")?;
                        out.sequence_number = txt.trim().parse().ok();
                    }
                    "ListIssueDateTime" => {
                        let txt = read_text(reader, "ListIssueDateTime")?;
                        out.list_issue_datetime = parse_datetime(&txt);
                    }
                    "NextUpdate" => {
                        // Inner <dateTime>…</dateTime>
                        let txt = read_text_inside(reader, "NextUpdate").unwrap_or_default();
                        out.next_update = parse_datetime(&txt);
                    }
                    _ => skip_element(reader, &name)?,
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_provider_list(
    reader: &mut Reader<&[u8]>,
    providers: &mut Vec<TrustServiceProvider>,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("provider list: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "TrustServiceProviderList" => break,
            Event::Start(ref e) if local(e.name()) == "TrustServiceProvider" => {
                let tsp = parse_tsp(reader)?;
                providers.push(tsp);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_tsp(reader: &mut Reader<&[u8]>) -> Result<TrustServiceProvider> {
    let mut tsp = TrustServiceProvider::default();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("TSP: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "TrustServiceProvider" => break,
            Event::Start(ref e) => {
                let name = local(e.name());
                match name.as_str() {
                    "TSPInformation" => parse_tsp_information(reader, &mut tsp)?,
                    "TSPServices" => parse_tsp_services(reader, &mut tsp.services)?,
                    _ => skip_element(reader, &name)?,
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(tsp)
}

fn parse_tsp_information(
    reader: &mut Reader<&[u8]>,
    tsp: &mut TrustServiceProvider,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("TSPInformation: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "TSPInformation" => break,
            Event::Start(ref e) => {
                let name = local(e.name());
                match name.as_str() {
                    "TSPName" => {
                        tsp.name = Some(read_first_name(reader, "TSPName")?);
                    }
                    "TSPTradeName" => {
                        tsp.trade_name = Some(read_first_name(reader, "TSPTradeName")?);
                    }
                    "TSPAddress" => {
                        // Inner PostalAddresses/PostalAddress/CountryName.
                        tsp.country = find_country(reader, "TSPAddress")?;
                    }
                    _ => skip_element(reader, &name)?,
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_tsp_services(
    reader: &mut Reader<&[u8]>,
    services: &mut Vec<TrustService>,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("TSPServices: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "TSPServices" => break,
            Event::Start(ref e) if local(e.name()) == "TSPService" => {
                let svc = parse_tsp_service(reader)?;
                services.push(svc);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_tsp_service(reader: &mut Reader<&[u8]>) -> Result<TrustService> {
    let mut svc = TrustService::default();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("TSPService: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "TSPService" => break,
            Event::Start(ref e) => {
                let name = local(e.name());
                match name.as_str() {
                    "ServiceInformation" => parse_service_information(reader, &mut svc)?,
                    "ServiceHistory" => parse_service_history(reader, &mut svc.history)?,
                    _ => skip_element(reader, &name)?,
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(svc)
}

fn parse_service_information(
    reader: &mut Reader<&[u8]>,
    svc: &mut TrustService,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("ServiceInformation: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "ServiceInformation" => break,
            Event::Start(ref e) => {
                let name = local(e.name());
                match name.as_str() {
                    "ServiceTypeIdentifier" => {
                        svc.service_type_identifier =
                            Some(read_text(reader, "ServiceTypeIdentifier")?);
                    }
                    "ServiceName" => {
                        svc.service_name = Some(read_first_name(reader, "ServiceName")?);
                    }
                    "ServiceStatus" => {
                        svc.current_status = Some(read_text(reader, "ServiceStatus")?);
                    }
                    "StatusStartingTime" => {
                        let t = read_text(reader, "StatusStartingTime")?;
                        svc.status_starting_time = parse_datetime(&t);
                    }
                    "ServiceDigitalIdentity" => {
                        svc.certificates
                            .extend(parse_digital_identity(reader, "ServiceDigitalIdentity")?);
                    }
                    "ServiceInformationExtensions" => {
                        svc.qualifiers
                            .extend(parse_qualifiers(reader, "ServiceInformationExtensions")?);
                    }
                    _ => skip_element(reader, &name)?,
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_service_history(
    reader: &mut Reader<&[u8]>,
    history: &mut Vec<ServiceStatus>,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("ServiceHistory: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == "ServiceHistory" => break,
            Event::Start(ref e) if local(e.name()) == "ServiceHistoryInstance" => {
                let mut entry = ServiceStatus::default();
                let mut inner = Vec::new();
                loop {
                    match reader
                        .read_event_into(&mut inner)
                        .map_err(|e| Error::Xml(format!("history instance: {e}")))?
                    {
                        Event::End(ref e)
                            if local(e.name()) == "ServiceHistoryInstance" =>
                        {
                            break
                        }
                        Event::Start(ref e) => {
                            let name = local(e.name());
                            match name.as_str() {
                                "ServiceTypeIdentifier" => {
                                    entry.service_type_identifier =
                                        Some(read_text(reader, "ServiceTypeIdentifier")?);
                                }
                                "ServiceStatus" => {
                                    entry.status = Some(read_text(reader, "ServiceStatus")?);
                                }
                                "StatusStartingTime" => {
                                    let t = read_text(reader, "StatusStartingTime")?;
                                    entry.starting_time = parse_datetime(&t);
                                }
                                "ServiceDigitalIdentity" => {
                                    entry.certificates.extend(parse_digital_identity(
                                        reader,
                                        "ServiceDigitalIdentity",
                                    )?);
                                }
                                "ServiceInformationExtensions" => {
                                    entry.qualifiers.extend(parse_qualifiers(
                                        reader,
                                        "ServiceInformationExtensions",
                                    )?);
                                }
                                _ => skip_element(reader, &name)?,
                            }
                        }
                        Event::Eof => break,
                        _ => {}
                    }
                    inner.clear();
                }
                history.push(entry);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_digital_identity(
    reader: &mut Reader<&[u8]>,
    closing: &str,
) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("digital identity: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == closing => break,
            Event::Start(ref e) if local(e.name()) == "X509Certificate" => {
                let b64 = read_text(reader, "X509Certificate")?;
                let cleaned: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                use base64::{engine::general_purpose::STANDARD, Engine};
                let der = STANDARD
                    .decode(cleaned.as_bytes())
                    .map_err(|e| Error::Xml(format!("X509Certificate base64: {e}")))?;
                let cert = Certificate::from_der(&der)
                    .map_err(|e| Error::Asn1(format!("X509Certificate DER: {e}")))?;
                out.push(cert);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn parse_qualifiers(
    reader: &mut Reader<&[u8]>,
    closing: &str,
) -> Result<Vec<String>> {
    // Qualifiers live under: ServiceInformationExtensions/Extension/Qualifications/QualificationElement/Qualifiers/Qualifier@uri
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("qualifiers: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == closing => break,
            Event::Start(ref e) | Event::Empty(ref e)
                if local(e.name()) == "Qualifier" =>
            {
                for attr in e.attributes().flatten() {
                    if local(attr.key) == "uri" {
                        if let Ok(s) = attr.unescape_value() {
                            out.push(s.into_owned());
                        }
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

// ---------- small utilities ----------

fn local(name: QName<'_>) -> String {
    // quick-xml's `local_name()` returns `LocalName`; decode lossily for match.
    let ln = name.local_name();
    std::str::from_utf8(ln.as_ref())
        .unwrap_or("")
        .to_string()
}

/// Read all text events until the matching `</closing>` and return the
/// concatenated contents.
fn read_text(reader: &mut Reader<&[u8]>, closing: &str) -> Result<String> {
    let mut buf = Vec::new();
    let mut out = String::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("read text: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == closing => break,
            Event::Text(t) => {
                out.push_str(
                    &t.unescape()
                        .map_err(|e| Error::Xml(format!("unescape: {e}")))?,
                );
            }
            Event::CData(c) => {
                out.push_str(std::str::from_utf8(&c).unwrap_or(""));
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

/// Recursively read text under `closing`, walking into any child elements.
fn read_text_inside(reader: &mut Reader<&[u8]>, closing: &str) -> Option<String> {
    let mut buf = Vec::new();
    let mut depth = 1usize;
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(_) => depth += 1,
            Event::End(ref e) if local(e.name()) == closing => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Event::End(_) => depth -= 1,
            Event::Text(t) => {
                if let Ok(s) = t.unescape() {
                    out.push_str(&s);
                }
            }
            Event::CData(c) => {
                out.push_str(std::str::from_utf8(&c).unwrap_or(""));
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Some(out)
}

/// Inside `<SomeName>`, find the first child `<Name>…</Name>` and return its text.
fn read_first_name(reader: &mut Reader<&[u8]>, closing: &str) -> Result<String> {
    let mut buf = Vec::new();
    let mut found: Option<String> = None;
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("first name: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == closing => break,
            Event::Start(ref e) if local(e.name()) == "Name" && found.is_none() => {
                found = Some(read_text(reader, "Name")?);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(found.unwrap_or_default())
}

/// Inside an address block, pull out `CountryName` if present.
fn find_country(reader: &mut Reader<&[u8]>, closing: &str) -> Result<Option<String>> {
    let mut buf = Vec::new();
    let mut country: Option<String> = None;
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("find country: {e}")))?
        {
            Event::End(ref e) if local(e.name()) == closing => break,
            Event::Start(ref e) if local(e.name()) == "CountryName" && country.is_none() => {
                country = Some(read_text(reader, "CountryName")?);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(country)
}

fn skip_element(reader: &mut Reader<&[u8]>, _closing: &str) -> Result<()> {
    let mut depth = 1usize;
    let mut buf = Vec::new();
    while depth > 0 {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::Xml(format!("skip: {e}")))?
        {
            Event::Start(_) => depth += 1,
            Event::End(_) => {
                depth -= 1;
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    // ETSI TS 119 612 uses xsd:dateTime.
    DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
}
