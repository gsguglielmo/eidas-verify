# Test corpora

This directory holds the third-party signature samples that the integration
tests under `crates/*/tests/dss_corpus_*.rs`, `pkits_path_validation.rs`, and
`wycheproof_primitives.rs` consume. None of the contents are committed to this
repo — every corpus is fetched on demand because (a) the licenses differ from
ours (MIT OR Apache-2.0) and we want clean separation, and (b) the bundles are
large enough to bloat clones.

## Layout

```
tests/vectors/
├── dss-corpus/              # esig/dss test resources (LGPL-2.1)
│   └── (populated by tools/sync-corpus.sh)
├── pkits/                   # NIST PKITS X.509 path-validation suite (US public domain)
│   └── (populated by tools/sync-corpus.sh)
├── expectations/            # our verdicts table for each DSS sample (this repo)
│   ├── cades.toml
│   ├── pades.toml
│   ├── xades.toml
│   ├── jades.toml
│   └── asic.toml
├── dss-corpus.sparse        # sparse-checkout paths for the DSS clone
├── dss-corpus.commit        # pinned commit / branch in esig/dss (or "master")
└── README.md                # this file
```

The Wycheproof signature vectors are bundled with the `wycheproof` crate
(Apache-2.0) pulled in via `Cargo.toml`, so they need no separate fetch.

## Bootstrap

```sh
./tools/sync-corpus.sh
```

This is idempotent. It performs:

1. A `--filter=blob:none` partial clone of `esig/dss` into
   `tests/vectors/dss-corpus/`, then narrows the working tree via
   `git sparse-checkout` to the paths listed in `dss-corpus.sparse`.
   It is **not** a git submodule — `tests/vectors/dss-corpus/` is
   gitignored and never enters the parent repo's history.
2. A download of NIST PKITS into `tests/vectors/pkits/`. Public domain,
   small, also gitignored.

`--reset` wipes both directories and starts fresh.

## Running tests

```sh
# Offline: existing synthetic + Wycheproof-bundled tests
cargo test --workspace

# With external corpora
cargo test --workspace --features corpus-dss,corpus-pkits,corpus-wycheproof

# With the optional online tier (DSS demo REST oracle, live EU LOTL fetch)
EIDAS_VERIFY_ONLINE_TESTS=1 cargo test --workspace --features online-tests
```

Tests that depend on the corpus call `eidas_test_corpus::skip_if_corpus_missing!()`
at the top of each `#[test]`. If `tools/sync-corpus.sh` has not been
run yet, those tests log a single "corpus missing" line and exit
cleanly — they do not fail the build. CI runs `tools/sync-corpus.sh`
once per workflow before invoking `cargo test`.

## Pinning a new DSS commit

```sh
git -C tests/vectors/dss-corpus log -1 --format=%H | tee tests/vectors/dss-corpus.commit
```

Then re-run the tests, refresh any `tests/vectors/expectations/*.toml` rows
whose verdicts changed, commit `dss-corpus.commit` and the expectation
deltas.

## Licenses

| Corpus | License | Source |
|---|---|---|
| `dss-corpus/**` | LGPL-2.1 | https://github.com/esig/dss |
| `pkits/**` | US Federal public domain | https://csrc.nist.gov/projects/pki-testing |
| Wycheproof JSON (via crate) | Apache-2.0 | https://github.com/google/wycheproof |

The full attribution lives in `LICENSES.md` at repo root.
