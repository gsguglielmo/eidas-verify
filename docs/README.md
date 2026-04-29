# eidas-verify — architecture documentation

This folder is the system-level reference for the library. The top-level
[`../README.md`](../README.md) is the *user's* entry point (quick start,
public facade, running the tests). Everything here is for contributors,
integrators, and security reviewers who need to reason about how the
pieces fit together.

## Reading order

1. [**Overview**](01-overview.md) — what the library is, what it is not,
   the eIDAS + ETSI standards it implements, and the scope boundaries.
2. [**Architecture**](02-architecture.md) — the 14-crate workspace layout,
   dependency graph, layer diagram.
3. [**Data flow**](03-data-flow.md) — end-to-end sequence diagrams for each
   format (CAdES, PAdES, ASiC, JAdES, XAdES) showing exactly which types
   cross which boundary.
4. [**Type model**](04-types.md) — the core data types, their
   relationships, and where each field gets populated.
5. [**Verification levels**](05-verification-levels.md) — the B-B → B-T →
   B-LT → B-LTA state machine, best-signature-time cascade, and the
   historical-validation clock.
6. [**Qualification (TS 119 615)**](06-qualification.md) — AdES / AdES-QC /
   QES decision, TrustedList lookup, QCStatement parsing.
7. [**Features and extension points**](07-features-and-extension.md) —
   feature-flag matrix, sub-crate re-exports, how to plug in your own
   algorithm policy / revocation fetcher.
8. [**Security model**](08-security-model.md) — trust boundaries, offline
   guarantees, what the library does *not* check, known soft spots.
9. [**Deferred work**](09-deferred-work.md) — what the hardening pass
   did not deliver, why, and what the next sprint should build
   (fuzzing, MIRI, DSS corpus, archive-timestamp imprint, full XMLDSig,
   algorithm expansion).

## Diagram conventions

Every document uses [Mermaid](https://mermaid.js.org/) for diagrams. GitHub
renders them natively; most IDE previewers do too. If you need PDFs,
`mmdc` (mermaid-cli) can convert them.

- **Boxes** are Rust types, modules, or sub-crates.
- **Solid arrows** mean a direct Rust dependency (`use`, field type, call).
- **Dashed arrows** mean a runtime dispatch or feature-gated edge.
- **Colours** (used sparingly) encode layer:
  - <span style="color:#4a90e2">blue</span> — public facade.
  - <span style="color:#7ed321">green</span> — format verifiers.
  - <span style="color:#f5a623">amber</span> — crypto/parsing primitives.
  - <span style="color:#9013fe">purple</span> — policy + TSL + qualification.

## Cross-reference with the codebase

Every diagram in this folder references real file paths under
`crates/<crate-name>/src/`. When in doubt, trust the code — ping the file
path in the diagram caption, grep the identifier, read the implementation.
