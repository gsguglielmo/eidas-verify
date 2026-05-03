//! Locates the DSS, PKITS and Wycheproof corpora used by integration tests
//! across the workspace, and loads our expectation tables for each DSS
//! sample.
//!
//! Tests that consume this crate enable the matching `corpus-*` feature in
//! the consumer's `[dev-dependencies]` line and then call
//! `skip_if_corpus_missing!()` at the top of each `#[test]`. When the
//! corpus is absent (clean clone, no `tools/sync-corpus.sh` run yet) the
//! test logs a single line and returns instead of failing — that is what
//! lets `cargo test --workspace --no-default-features` stay green on
//! contributor machines.
//!
//! The reason for a separate crate (instead of `tests/common/mod.rs` per
//! crate): Cargo's integration-test layout makes module sharing across
//! crates brittle, and we have eleven crates that need the same lookups.

#![allow(clippy::module_name_repetitions)]

use std::env;
use std::path::{Path, PathBuf};

/// Repository root, resolved at test time.
///
/// We walk up from `CARGO_MANIFEST_DIR` (pointing at the consuming crate)
/// until we find the workspace `Cargo.toml` that declares `[workspace]`. This
/// avoids hard-coding `../..` and works whether the consumer is at
/// `crates/eidas-cms/` or somewhere deeper.
#[must_use]
pub fn workspace_root() -> PathBuf {
    let manifest = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR set by Cargo at test time");
    let mut p = manifest.as_path();
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.is_file() {
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return p.to_path_buf();
                }
            }
        }
        p = p.parent().expect("walked off filesystem looking for workspace root");
    }
}

/// Path to the DSS corpus root (`tests/vectors/dss-corpus/`).
#[must_use]
pub fn dss_corpus_root() -> PathBuf {
    workspace_root().join("tests/vectors/dss-corpus")
}

/// Path to a sample inside a DSS module's `src/test/resources/` tree.
///
/// Example: `dss_sample("dss-pades", "validation/PAdES-LT.pdf")` returns
/// `<repo>/tests/vectors/dss-corpus/dss-pades/src/test/resources/validation/PAdES-LT.pdf`.
#[must_use]
pub fn dss_sample(module: &str, relative: &str) -> PathBuf {
    dss_corpus_root()
        .join(module)
        .join("src/test/resources")
        .join(relative)
}

/// Path to NIST PKITS root (`tests/vectors/pkits/`).
#[must_use]
pub fn pkits_root() -> PathBuf {
    workspace_root().join("tests/vectors/pkits")
}

/// Path to the expectations table for a given format.
///
/// `format` is one of `"cades"`, `"pades"`, `"xades"`, `"jades"`, `"asic"`.
#[must_use]
pub fn expectations_path(format: &str) -> PathBuf {
    workspace_root()
        .join("tests/vectors/expectations")
        .join(format!("{format}.toml"))
}

/// True if the DSS corpus has been bootstrapped (any sample present).
#[must_use]
pub fn dss_corpus_present() -> bool {
    let marker = dss_corpus_root().join("dss-pades/src/test/resources/validation");
    marker.is_dir() && marker.read_dir().is_ok_and(|mut r| r.next().is_some())
}

/// True if the NIST PKITS bundle has been extracted.
#[must_use]
pub fn pkits_present() -> bool {
    let certs = pkits_root().join("certs");
    certs.is_dir() && certs.read_dir().is_ok_and(|mut r| r.next().is_some())
}

/// True if `EIDAS_VERIFY_ONLINE_TESTS=1` is set.
#[must_use]
pub fn online_tests_enabled() -> bool {
    matches!(env::var("EIDAS_VERIFY_ONLINE_TESTS").as_deref(), Ok("1") | Ok("true"))
}

/// Skip this test if the DSS corpus has not been bootstrapped.
///
/// Logs a single line ("DSS corpus missing — run tools/sync-corpus.sh")
/// and returns from the test function. Use this *only* in tests that
/// genuinely cannot run without the corpus; for tests that have a
/// synthetic fallback, branch explicitly on [`dss_corpus_present`].
#[macro_export]
macro_rules! skip_if_corpus_missing {
    () => {
        if !$crate::dss_corpus_present() {
            eprintln!(
                "[skipped: {}::{}] DSS corpus missing — run tools/sync-corpus.sh",
                std::module_path!(),
                $crate::__current_test_name()
            );
            return;
        }
    };
}

/// Skip if PKITS bundle is missing.
#[macro_export]
macro_rules! skip_if_pkits_missing {
    () => {
        if !$crate::pkits_present() {
            eprintln!(
                "[skipped: {}::{}] NIST PKITS missing — run tools/sync-corpus.sh",
                std::module_path!(),
                $crate::__current_test_name()
            );
            return;
        }
    };
}

/// Skip unless `EIDAS_VERIFY_ONLINE_TESTS=1`.
#[macro_export]
macro_rules! skip_unless_online {
    () => {
        if !$crate::online_tests_enabled() {
            eprintln!(
                "[skipped: {}::{}] online tier off — set EIDAS_VERIFY_ONLINE_TESTS=1",
                std::module_path!(),
                $crate::__current_test_name()
            );
            return;
        }
    };
}

/// Implementation detail of `skip_if_*` macros — best-effort test name.
///
/// Cargo's test harness names threads after the test function, so on stable
/// Rust this returns the test name. On platforms that don't, it returns
/// `<unknown>`.
#[doc(hidden)]
pub fn __current_test_name() -> String {
    std::thread::current().name().unwrap_or("<unknown>").to_string()
}

/// Encoding of the expected verdict for one corpus sample.
///
/// Mirrors a subset of `eidas_core::report::SignatureReport` — kept as
/// strings so the expectation TOML can sit next to the corpus without
/// pulling `eidas-core` in as a dep here.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SampleExpectation {
    /// Path inside the DSS corpus, e.g. `"dss-pades/src/test/resources/validation/PAdES-LT.pdf"`.
    pub path: String,
    /// `"TotalPassed"`, `"IndeterminateSub"`, `"TotalFailedSub"`, or `"Skip"`.
    pub status: String,
    /// `"BB"`, `"BT"`, `"BLT"`, `"BLTA"`, `"Unknown"`, or `null` if don't-care.
    #[serde(default)]
    pub level: Option<String>,
    /// Number of signatures expected in the report (None = don't-check).
    #[serde(default)]
    pub signature_count: Option<usize>,
    /// Diagnostic codes that MUST appear in the report.
    #[serde(default)]
    pub require_diagnostics: Vec<String>,
    /// Diagnostic codes that MUST NOT appear in the report.
    #[serde(default)]
    pub forbid_diagnostics: Vec<String>,
    /// If set, ignore this test with the given message. Used for samples
    /// awaiting deferred-feature implementation.
    #[serde(default)]
    pub ignore: Option<String>,
    /// Free-text rationale, included in failure messages so triage is
    /// easy. Encouraged on every row.
    #[serde(default)]
    pub note: Option<String>,
}

/// All expectations for one signature format.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct ExpectationTable {
    #[serde(default)]
    pub sample: Vec<SampleExpectation>,
}

impl ExpectationTable {
    /// Load expectations for `format` from `tests/vectors/expectations/<format>.toml`.
    ///
    /// Returns an empty table (rather than erroring) if the file does not
    /// exist — useful while suites are being written.
    pub fn load(format: &str) -> Self {
        let p = expectations_path(format);
        match std::fs::read_to_string(&p) {
            Ok(s) => toml::from_str::<Self>(&s).unwrap_or_else(|e| {
                panic!("invalid expectations file {p:?}: {e}")
            }),
            Err(_) => Self::default(),
        }
    }

    /// Look up the expectation for a given relative path.
    #[must_use]
    pub fn get(&self, relative_path: &str) -> Option<&SampleExpectation> {
        self.sample.iter().find(|e| e.path == relative_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_contains_cargo_toml() {
        let root = workspace_root();
        assert!(root.join("Cargo.toml").is_file());
        assert!(root.join("crates").is_dir());
    }

    #[test]
    fn dss_corpus_root_under_workspace() {
        let r = dss_corpus_root();
        assert!(r.starts_with(workspace_root()));
        assert!(r.ends_with("tests/vectors/dss-corpus"));
    }

    #[test]
    fn online_flag_reads_env() {
        // We only check the read path. Mutating process-wide env from
        // tests requires `unsafe` on Rust 2024 and conflicts with the
        // workspace `unsafe_code = forbid` lint, so the round-trip test
        // is skipped; the function is trivial enough that the read-path
        // smoke check is sufficient.
        let observed = online_tests_enabled();
        let from_env = env::var("EIDAS_VERIFY_ONLINE_TESTS");
        match (observed, from_env.as_deref()) {
            (true, Ok("1") | Ok("true")) => {}
            (false, Err(_) | Ok(_)) => {}
            (got, env) => panic!("flag/env disagree: got={got} env={env:?}"),
        }
    }

    #[test]
    fn missing_expectations_file_yields_empty() {
        let t = ExpectationTable::load("does-not-exist-format");
        assert!(t.sample.is_empty());
    }
}

// Suppress unused warning when `Path` is not referenced in some configs.
#[allow(dead_code)]
fn _silence_unused_path(_: &Path) {}
