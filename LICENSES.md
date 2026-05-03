# Licenses

`eidas-verify` itself is `MIT OR Apache-2.0` (see SPDX `MIT OR Apache-2.0`
declared in every workspace member's `Cargo.toml`).

The verifier links exclusively against `MIT OR Apache-2.0` /
`BSD-2-Clause` / `Apache-2.0 WITH LLVM-exception` Rust crates. No GPL or
LGPL code enters the production dependency graph; `cargo deny check
licenses` enforces this in CI (see `.github/workflows/ci.yml` and
`deny.toml`).

The sections below cover *test corpora* and *dev-only dependencies*. None of
their files are shipped in published crates (they live under
`tests/vectors/` and are excluded by `Cargo.toml`'s default `include`
list); all are pulled on demand by `tools/sync-corpus.sh` or as
`[dev-dependencies]`.

## Test corpora

### EU DSS (`tests/vectors/dss-corpus/`)

- **Source:** https://github.com/esig/dss
- **License:** LGPL-2.1
- **Content used:** signed sample documents (CAdES `.p7s/.p7m`, PAdES
  `.pdf`, XAdES `.xml`, JAdES `.json`, ASiC `.asice/.asics`), trust list
  samples (`eu-lotl*.xml`, per-Member-State TLs, `fi-v5/v6` variants),
  RFC 3161 timestamp tokens (`*.tsr/.tst`), OCSP responses
  (`peru_ocsp.bin`), certificate fixtures (`certificates/`, `qwac/`).
- **How used:** read at test time only; never linked, never repackaged.
  The directory is in `.gitignore` and not part of any published
  artefact. Per LGPL-2.1 §5, mere aggregation of independently licensed
  data alongside unrelated source code does not subject our code to LGPL
  terms; nevertheless we keep the corpus out of the main tree out of an
  abundance of caution.

### NIST PKITS (`tests/vectors/pkits/`)

- **Source:** https://csrc.nist.gov/projects/pki-testing
- **License:** Work of the United States Government — public domain in the
  US, freely usable worldwide.
- **Content used:** Public Key Interoperability Test Suite v1.07 — ~250
  X.509 conformance test certificates, CRLs, and signed S/MIME samples
  driving RFC 5280 path-validation logic.

### Wycheproof signature vectors (via `wycheproof` crate)

- **Source:** https://github.com/google/wycheproof, distributed by
  Google, re-packaged in the [`wycheproof`](https://crates.io/crates/wycheproof)
  crate on crates.io.
- **License:** Apache-2.0
- **Content used:** RSA-PKCS#1 v1.5, RSA-PSS, ECDSA P-256/P-384/P-521
  test vectors with attacker-crafted edge cases (signature malleability,
  leading zeros, point-encoding tricks, etc.).
- **How used:** dev-dependency only; not in any binary published from
  this workspace.

## Dev-dependencies of note

- `rcgen` (MPL-2.0 OR Apache-2.0): synthetic certificate fixtures.
- `insta` (Apache-2.0): snapshot tests.
- `proptest` (MIT OR Apache-2.0): property tests.
- `rstest` (MIT OR Apache-2.0): table-driven tests.
- `tempfile` (MIT OR Apache-2.0): scratch dirs for openssl-driven
  fixtures.
- `pretty_assertions` (MIT OR Apache-2.0): readable diffs.

## Online tests

The opt-in online tier (`EIDAS_VERIFY_ONLINE_TESTS=1`) fetches the live
EU LOTL from `https://ec.europa.eu/tools/lotl/eu-lotl.xml` and posts
samples to the EU's [DSS demo REST endpoint](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/).
These services are operated by the European Commission as a
public-sector information resource. We make no claim of endorsement and
limit the request rate to a level appropriate for occasional CI runs.

## Reporting a license concern

If you believe any test fixture or dependency is misattributed here,
open an issue at the repository's tracker. We will investigate and,
where warranted, remove the affected material.
