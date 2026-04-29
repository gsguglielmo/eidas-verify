# eidas-verify

Pure-Rust library for verifying EU electronic signatures under the eIDAS
regulation.

**Status: early, test-driven.** The workspace is structured around the 12
phases in [`plans/serialized-roaming-tiger.md`](plans/serialized-roaming-tiger.md).
Every phase ships with integration tests that exercise real openssl-produced
signatures end-to-end.

> System-level documentation — architecture, data-flow sequence diagrams,
> type model, verification-level cascade, qualification engine, security
> model — lives in **[`docs/`](docs/README.md)**. Start there if you're
> integrating, reviewing, or contributing.

## What it verifies

| Format | Support | Notes |
|--------|---------|-------|
| **CAdES** (CMS / PKCS#7) | B-B / B-T / B-LT | Detached + attached. B-LTA: TSA signature + chain verified, archive imprint over canonical CAdES bytes deferred (explicit diagnostic). |
| **PAdES** (PDF) | B-B / B-T / B-LT | Byte-range scanner + embedded CMS dispatch; multiple signatures per PDF; SubFilter `adbe.pkcs7.detached`, `ETSI.CAdES.detached`, `ETSI.RFC3161`. |
| **ASiC-S / ASiC-E** | CAdES | ZIP container parsing, signature-to-file binding. XAdES-in-ASiC lands with full XAdES. |
| **JAdES** (JWS) | B-B | RS256/384/512, ES256/384 (raw r\|\|s per RFC 7518). `x5t#S256` binding enforced. `sigT` as claimed time. `sigTst` parsed and flagged, full B-T lift pending. |
| **XAdES** (XML) | B-B, narrow profile | `xades` feature, off by default. Enveloped signatures, exc-c14n only, `{rsa,ecdsa}-sha{256,384,512}` signature methods. Anything outside the narrow profile is rejected with explicit diagnostics. |

| Building block | Support |
|----------------|---------|
| RFC 3161 timestamps | Full verification (TSA cert + chain, imprint, `id-kp-timeStamping` EKU). |
| CRL + OCSP revocation | Offline only — caller supplies bytes or they're pulled from `id-aa-ets-revocationValues`. |
| ETSI TS 119 612 Trusted Lists | Structural parsing into typed Rust; signature verification on the TSL's own XMLDSig is **deferred** to when the libxml2 backend lands. |
| ETSI TS 119 615 qualification | AdES / AdES-QC / QES decision consuming chain + TSL + `qcStatements`. |
| Algorithm policy | ETSI TS 119 312 (2023 revision). Versioned so upgrades are explicit. |

## Non-goals

- **No network I/O.** Trust list download, CRL / OCSP fetch, TSA requests are
  the caller's problem. This library verifies what you hand it.
- **No signing.** Verification only.

## Public facade

Everything you need for the common case lives in the `eidas_verify` crate.
The API is organised in three layers: **builder**, **input**, **report**.
You hand the verifier trust material once via the builder, then feed it one
or more `VerificationInput`s and inspect the resulting `VerificationReport`.

### Quick start

```rust
use eidas_verify::{
    ContainerHint, DetachedFormat, ValidationTime, VerificationInput, Verifier,
};

let verifier = Verifier::builder()
    .trust_anchors([ca_cert])               // one or more x509_cert::Certificate
    .validation_time(ValidationTime::Now)   // or ::At(DateTime<Utc>), ::BestSignatureTime
    .build()?;

// Verify a PAdES PDF:
let pdf = std::fs::read("signed.pdf")?;
let report = verifier.verify(VerificationInput::Container {
    bytes: &pdf,
    hint: Some(ContainerHint::Pdf),
})?;

// Verify a detached CAdES signature:
let sig = std::fs::read("sig.p7s")?;
let data = std::fs::read("data.bin")?;
let report = verifier.verify(VerificationInput::Detached {
    signature: &sig,
    signed_data: &data,
    format: DetachedFormat::Cades,
})?;

for sr in &report.signatures {
    println!("{:?} @ {:?}: {:?}", sr.status, sr.level_reached, sr.qualification);
}
```

### `Verifier::builder()` → `VerifierBuilder`

| Method | What it does |
|--------|--------------|
| `trust_anchors(iter)` | Roots-of-trust. **Required** — `build()` fails with `Error::Config` if empty. Accepts `IntoIterator<Item = x509_cert::Certificate>`. |
| `intermediate_certificates(iter)` | Extra intermediate CAs available for path-building. Signatures that embed intermediates in `SignedData.certificates`, `x5c`, or XAdES `KeyInfo` do not need these. |
| `policy(AlgorithmPolicy)` | Algorithm policy override. Defaults to [`policy::etsi_119_312_2023()`](#policy) if omitted. |
| `validation_time(ValidationTime)` | See [ValidationTime](#validationtime). Defaults to `ValidationTime::Now`. |
| `build()` | Returns `Result<Verifier, Error>`. |

### `VerificationInput<'a>`

The enum the verifier accepts. `Container` is self-contained (signature and
document packaged together); `Detached` is two separate byte streams.

```rust
pub enum VerificationInput<'a> {
    Container { bytes: &'a [u8], hint: Option<ContainerHint> },
    Detached { signature: &'a [u8], signed_data: &'a [u8], format: DetachedFormat },
}
```

#### `ContainerHint`

Tells the verifier which format the container carries. Pass `None` for a
bare CMS SignedData blob (attached CAdES).

| Variant | Dispatches to | Feature |
|---------|---------------|---------|
| `Pdf` | `eidas_pades::verify_pades` | `pades` |
| `Asic` | `eidas_asic::verify_asic` | `asic` |
| `JadesCompact` | `eidas_jades::verify_jades` (compact JWS) | `jades` |
| `JadesJson` | `eidas_jades::verify_jades` (flattened JSON) | `jades` |
| `XadesEnveloped` | `eidas_xades::verify_xades` (narrow profile) | `xades` |
| `None` | CAdES attached (bare CMS SignedData) | `cades` |

#### `DetachedFormat`

| Variant | Dispatches to | Feature | Status |
|---------|---------------|---------|--------|
| `Cades` | `eidas_cades::verify_cades` (detached) | `cades` | ✓ |
| `XadesDetached` | — | — | Not yet implemented (returns `Error::Unsupported`) |
| `JadesDetached` | — | — | Not yet implemented |

### `VerificationReport`

`Verifier::verify()` returns `Result<VerificationReport, Error>`. Format-
parse or configuration errors bubble up through `Result`; crypto or chain
failures are recorded **inside** the report as `TotalFailedSub` / an error
diagnostic on the individual `SignatureReport`.

```rust
pub struct VerificationReport {
    pub signatures: Vec<SignatureReport>,
    pub container: Option<ContainerInfo>,
}
```

#### `SignatureReport`

```rust
pub struct SignatureReport {
    pub status: Status,                         // TotalPassed | IndeterminateSub | TotalFailedSub
    pub level_reached: Level,                   // Unknown | BB | BT | BLT | BLTA
    pub qualification: Qualification,           // NotAdES | AdES | AdESqc | QES
    pub qualifiers: Vec<QualificationQualifier>,
    pub signer: Option<CertificateInfo>,
    pub chain: Vec<CertificateInfo>,
    pub signing_time_claimed: Option<DateTime<Utc>>,  // from signed-attrs / sigT / etc.
    pub signing_time_best: Option<DateTime<Utc>>,     // from trusted timestamps
    pub algorithm: Option<AlgorithmId>,
    pub timestamps: Vec<TimestampInfo>,
    pub revocation: Vec<RevocationInfo>,
    pub diagnostics: Vec<DiagnosticMessage>,
}
```

`DiagnosticMessage` is the mechanism every stage uses to surface information
to the caller. Each diagnostic carries a stable `code: String` (e.g.
`MESSAGE_DIGEST_MISMATCH`, `ALG_POLICY_REJECTED`, `REVOCATION_REVOKED`,
`ATS_IMPRINT_NOT_VERIFIED`, `XADES_NARROW_PROFILE`), a `severity`
(`Info` / `Warning` / `Error`), and a human-readable `message`.

### `ContainerInfo`

Populated for container inputs so the caller can cross-check what was found:

```rust
pub enum ContainerInfo {
    Pdf { revisions: usize },
    Asic { mime_type: String, entries: Vec<String> },
    Jws { encoding: String },
    // ...
}
```

### `ValidationTime`

Controls the reference time at which chains, revocation, and algorithm
policy are evaluated. Required for historical validation of long-term
signatures whose certs have since expired.

```rust
pub enum ValidationTime {
    Now,                                // system clock when verify() runs
    At(DateTime<Utc>),                  // caller-supplied fixed instant
    BestSignatureTime,                  // latest trustworthy embedded TST
}
```

### Errors

`Error` is a non-exhaustive enum. The variants callers typically match on:

| Variant | When you see it |
|---------|-----------------|
| `Config(String)` | Builder misuse (no anchors, missing input). |
| `Unsupported(String)` | Input format combination not wired up (e.g. `DetachedFormat::XadesDetached` today). |
| `Asn1`, `Xml`, `Json`, `Pdf`, `Zip` | Top-level parse failures. |
| `Chain`, `Crypto`, `Revocation`, `Timestamp`, `TrustList`, `Policy` | Primitive-level failures that bubbled up past a phase's own error-trapping. |

Most genuine verification failures do **not** land as `Err`; they become a
`Status::TotalFailedSub` signature report with an error-severity diagnostic.
This makes multi-signature containers (a PDF with three signatures, one
broken) work ergonomically — `Verifier::verify()` returns a single `Ok`
with three reports.

### Advanced: working directly with the sub-crates

The facade's `Verifier` covers the common case. If you need more control
(e.g. attaching a `TrustedLists` for TS 119 615 qualification, driving
CRL/OCSP checks yourself, or using one of the format-specific entry
points), call the sub-crates directly through their re-exports on
`eidas_verify`:

```rust
// ETSI TS 119 615 qualification with an attached TrustedList bundle:
let tl = eidas_verify::trust::parse_trusted_list(xml_bytes)?;
let tls = eidas_verify::trust::TrustedLists { lists: vec![tl] };
let trust = eidas_verify::cades::CadesTrustMaterial::new()
    .with_anchors([ca_cert])
    .with_trusted_lists(tls);                         // needs feature = "cades-qualify"

let report = eidas_verify::cades::verify_cades(
    &eidas_verify::cades::CadesInput {                // re-exported from eidas-cms
        cms: &sig_bytes,
        detached_content: None,
    },
    &trust,
    &eidas_verify::policy::etsi_119_312_2023(),
    eidas_verify::ValidationTime::Now,
)?;
```

Module shortcuts re-exported on the facade (each gated on a feature flag):

| Path | Module | Feature |
|------|--------|---------|
| `eidas_verify::cades` | CAdES orchestrator (`verify_cades`, `CadesTrustMaterial`) | `cades` |
| `eidas_verify::pades` | PAdES (`verify_pades`, `PadesInput`) | `pades` |
| `eidas_verify::asic` | ASiC (`verify_asic`, `AsicInput`) | `asic` |
| `eidas_verify::jades` | JAdES (`verify_jades`, `JadesInput`, `JwsHeader`) | `jades` |
| `eidas_verify::xades` | XAdES (`verify_xades`, `XadesInput`) | `xades` |
| `eidas_verify::trust` | TrustedList parsing + `qualification_for` | `trust-list` |
| `eidas_verify::qualify` | TS 119 615 engine (`qualify_signer`, `QualificationInput`) | `ts-119-615` |
| `eidas_verify::timestamp` | RFC 3161 (`verify_time_stamp_token`, `TstInfo`) | always |
| `eidas_verify::revocation` | CRL + OCSP (`verify_crl`, `verify_ocsp`) | always |
| `eidas_verify::policy` | `etsi_119_312_2023()` and companions | always |
| `eidas_verify::{ChainBuilder, TrustAnchor}` | X.509 chain builder primitives | always |

### Command-line example

A runnable demo lives at `crates/eidas-verify/examples/verify.rs`:

```
cargo run --example verify -- --cms sig.p7s --data data.txt --anchor ca.pem
cargo run --example verify -- --pdf signed.pdf --anchor ca.pem
```

It accepts multiple `--anchor` flags, reads PEM or DER, and prints each
signature report with its diagnostics.

## Architecture

Workspace of 14 crates. Public API is the `eidas-verify` facade; the rest
are internals you can depend on directly if you want finer control.

```
eidas-verify           facade — Verifier, re-exports, feature flags
├── eidas-core         shared types: ValidationTime, Policy, Report, Error
├── eidas-policy       ETSI TS 119 312 algorithm tables
├── eidas-x509         X.509 chain building
├── eidas-cms          CMS / SignedData primitives
├── eidas-revocation   CRL + OCSP verification (offline)
├── eidas-timestamp    RFC 3161 TSTInfo verification
├── eidas-cades        CAdES B-B / B-T / B-LT / B-LTA orchestrator
├── eidas-pades        PAdES (PDF byte-range scanner)
├── eidas-jades        JAdES (JWS variants)
├── eidas-asic         ASiC container dispatch
├── eidas-xades        XAdES (narrow profile, `xades` feature)
├── eidas-trust        ETSI TS 119 612 TrustedList parsing
└── eidas-qualify      ETSI TS 119 615 qualification engine
```

## Feature flags (on `eidas-verify`)

Default: `cades`, `pades`, `asic`, `jades`, `trust-list`, `ts-119-615`,
`cades-qualify`.

Opt-in: `xades` (narrow pure-Rust profile — see the crate docs for
scope limits).

## Running the tests

```
cargo test --workspace
cargo test --workspace --all-features    # also exercises opt-in serde + xades
```

Tests invoke `openssl` from PATH for PKI + signature generation. Every test
skips gracefully with `eprintln!` if `openssl` is missing.

## License

MIT OR Apache-2.0.
