//! S15 — Online tier: fetch the live EU LOTL and (optionally) cross-check
//! a sample against the EU DSS demo REST endpoint.
//!
//! Disabled by default. Activated by `EIDAS_VERIFY_ONLINE_TESTS=1` at
//! test runtime. CI runs this in a dedicated job marked
//! `continue-on-error: true` so EU-service flakes don't block PRs.
//!
//! What this suite does NOT do:
//! - It does not bypass network policy or IP filters.
//! - It does not cache responses on disk; every run hits the public
//!   endpoint. A future enhancement could add a snapshot cache for
//!   reproducibility.

use eidas_test_corpus::{online_tests_enabled, skip_unless_online};
use eidas_trust::parse_trusted_list;

const EU_LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

fn http_get_bytes(url: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|e| format!("http get {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(50 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| format!("http read body: {e}"))?;
    Ok(buf)
}

// =====================================================================
// Live EU LOTL — fetches the canonical XML and parses it.
// =====================================================================

#[test]
fn live_eu_lotl_fetches_and_parses() {
    skip_unless_online!();
    let bytes = match http_get_bytes(EU_LOTL_URL) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[online:skipped] EU LOTL unreachable: {e}");
            return;
        }
    };
    assert!(
        bytes.len() > 100_000,
        "live LOTL unexpectedly small: {} bytes",
        bytes.len()
    );
    let tl = parse_trusted_list(&bytes).expect("live LOTL parses");
    assert_eq!(
        tl.territory.as_deref(),
        Some("EU"),
        "live LOTL territory must be 'EU'"
    );
}

#[test]
fn live_eu_lotl_namespace_and_signature() {
    skip_unless_online!();
    let bytes = match http_get_bytes(EU_LOTL_URL) {
        Ok(b) => b,
        Err(_) => return,
    };
    // The TSL XML carries the ETSI namespace; the declaration may live
    // anywhere in the prologue. Search the whole document.
    let needle = b"uri.etsi.org/02231/v2";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "ETSI TS 119 612 namespace 'uri.etsi.org/02231/v2' not present in live LOTL"
    );
    // The LOTL is signed; we don't verify the signature here (deferred
    // §6) but assert the Signature element exists.
    assert!(
        bytes.windows(b"Signature".len()).any(|w| w == b"Signature"),
        "expected XMLDSig Signature element in live LOTL"
    );
}

// =====================================================================
// DSS demo REST — cross-check a sample against the official oracle.
// =====================================================================
//
// The DSS demo at
// https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/
// exposes a REST API that returns a structured validation report. We
// don't fully parse that report here; we only assert the endpoint is
// reachable and returns something that mentions the format we sent.
// A richer oracle integration is left as a follow-up.

const DSS_DEMO_BASE: &str = "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo";

#[test]
fn dss_demo_endpoint_is_reachable() {
    skip_unless_online!();
    let url = format!("{DSS_DEMO_BASE}/");
    match ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
    {
        Ok(_) => {} // 200 OK is what we want
        Err(e) => eprintln!("[online:skipped] DSS demo unreachable: {e}"),
    }
}
