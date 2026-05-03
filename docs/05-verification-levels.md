# Verification levels

ETSI AdES signatures come in four conformance levels: **B-B** (basic),
**B-T** (timestamped), **B-LT** (long-term), **B-LTA** (long-term with
archive). Each adds a layer of evidence on top of the previous one.

This document describes how `eidas-verify` climbs that ladder for a CAdES
signature. PAdES and ASiC inherit the same cascade by dispatching into
CAdES. JAdES and XAdES currently stop at B-B — see the overview doc for
the deferred level-lift work.

## The level ladder

```mermaid
stateDiagram-v2
    [*] --> Unknown

    Unknown --> BB: B-B checks pass
    BB --> BT: valid signature-time-stamp
    BT --> BLT: embedded revocation data<br/>covers every chain cert
    BLT --> BLTA: valid archive-timestamp-v3

    BB: Level::BB
    BB: messageDigest OK<br/>signingCertificateV2 OK<br/>CMS signature OK<br/>chain builds<br/>policy accepts
    BT: Level::BT
    BT: + adds best_signature_time
    BLT: Level::BLT
    BLT: + embedded revocation proofs
    BLTA: Level::BLTA
    BLTA: + archive-timestamp (imprint deferred)

    Unknown: Level::Unknown
    Unknown: any B-B check failed
```

Any downgrade (a revocation error at B-LT, an invalid TST at B-T) does
**not** cascade back — once the crypto-core passes, failing auxiliary
evidence is recorded in diagnostics and the level stays at whatever was
last reached. This mirrors EN 319 102-1's "indeterminate doesn't mean
invalid" philosophy.

## B-B — the mandatory core

Source: `crates/eidas-cades/src/verify.rs::run_bb_core`.

```mermaid
flowchart TB
    start([SignerInfo + trust material]) --> sa{signed_attrs<br/>present?}
    sa -- no --> fail[Err: Crypto]
    sa -- yes --> md[compute digest of content]
    md --> mdc{md attr == computed?}
    mdc -- no --> fail2[TotalFailedSub<br/>MESSAGE_DIGEST_MISMATCH]
    mdc -- yes --> ct[read contentType attr]
    ct --> scv[verify signingCertificateV2 hash]
    scv -- hash mismatch --> fail3[Err: Crypto]
    scv -- OK --> sig[verify CMS signature over<br/>re-encoded SET OF signedAttrs]
    sig -- bad sig --> fail4[Err: Crypto]
    sig -- OK --> classify[classify AlgorithmId]
    classify --> ok([reach Level::BB])
```

Key detail — **`signedAttrs` re-encoding**: RFC 5652 §5.4 says the bytes
the signer hashes are `signedAttrs` re-tagged as `SET OF Attribute`, not
the IMPLICIT `[0]` form that appears on the wire. `eidas_cms::attrs::to_signed_der`
handles that by calling `to_der()` on the `SetOfVec<Attribute>`, which
emits the universal `SET` tag `0x31`.

## B-T — the signature timestamp

After B-B passes, the CAdES orchestrator walks the
`id-aa-signatureTimeStampToken` unsigned attribute. Each token is a full
RFC 3161 TimeStampToken whose imprint covers `signerInfo.signature`
(i.e. the signature value itself, not the signed attributes).

```mermaid
sequenceDiagram
    participant CadesVerify
    participant TST as eidas_timestamp::verify_time_stamp_token

    loop for each signature-time-stamp token
        CadesVerify->>TST: verify(token, signerInfo.signature bytes)
        alt OK
            TST-->>CadesVerify: TstVerification { gen_time, chain, info }
            Note over CadesVerify: best_signature_time<br/>= max(best_signature_time,<br/>       gen_time)<br/>Level::BT (first time)
        else fail
            TST-->>CadesVerify: Err
            Note over CadesVerify: SIGNATURE_TIMESTAMP_INVALID<br/>(level stays at B-B)
        end
    end
```

### Best-signature-time cascade

`best_signature_time` — the latest trustworthy instant we believe the
signature existed at — drives subsequent evaluation. Its sources, in
ascending trust order:

```mermaid
flowchart LR
    classDef untrust fill:#f5d4d4,stroke:#d0021b
    classDef semi fill:#fbe7bb,stroke:#f5a623
    classDef trust fill:#d4f5d8,stroke:#7ed321

    claimed[signing-time<br/>signed attr]:::untrust
    claimed -. untrusted .-> best

    sigtst[signature-time-stamp<br/>unsigned attr]:::trust
    sigtst -. trusted .-> best

    ctst[content-time-stamp<br/>signed attr]:::semi
    ctst -. trusted .-> best

    ats[archive-timestamp-v3<br/>unsigned attr]:::trust
    ats -. trusted .-> best

    best([best_signature_time])
```

Only timestamps that fully verify — TSA chain OK, imprint matches, TSA
cert has `id-kp-timeStamping` EKU — feed `best_signature_time`. The
`signing-time` signed attribute is surfaced as `signing_time_claimed`
for reporting but is never trusted for policy decisions.

When `ValidationTime::BestSignatureTime` is in play, `reference_time`
becomes `best_signature_time.unwrap_or_else(Utc::now)` so chain and
policy run against the historical instant.

## B-LT — embedded revocation

The `id-aa-ets-certValues` + `id-aa-ets-revocationValues` unsigned
attributes carry a self-contained bundle of certificates and CRL/OCSP
responses. Presence of both ≠ B-LT; they must actually prove
non-revocation of every non-anchor chain cert at the reference time.

```mermaid
flowchart TB
    start([unsigned attrs extracted]) --> have{rev_values present?}
    have -- no --> stay[stay at current level]
    have -- yes --> walk[for each chain cert except anchor]
    walk --> ocsp[try each OCSP response]
    ocsp -- match + Good --> good[record RevocationInfo Good]
    ocsp -- match + Revoked --> rev[TotalFailedSub<br/>REVOCATION_REVOKED]
    ocsp -- no match --> crl[try each CRL]
    crl -- match + Good --> good
    crl -- match + Revoked --> rev
    crl -- no match --> nomat[REVOCATION_NO_EVIDENCE diagnostic]
    good --> more{more certs?}
    nomat --> more
    more -- yes --> walk
    more -- no --> allgood{any Revoked?}
    allgood -- yes --> rev
    allgood -- no --> hasbt{Level #gt;= BT?}
    hasbt -- yes --> lift[Level::BLT]
    hasbt -- no --> info[LT_MATERIAL_WITHOUT_TIMESTAMP]
```

Key implementation detail — **OCSP wrapping**:
`id-aa-ets-revocationValues.ocspVals` carries `BasicOcspResponse` DER,
not the outer `OcspResponse` wrapper. `eidas-cades::verify::wrap_basic_as_ocsp_response`
synthesises the envelope so the existing
`eidas_revocation::verify_ocsp` primitive can consume it unchanged.

## B-LTA — archive timestamps

`id-aa-ets-archiveTimestampV3` is a TST over canonicalised CAdES bytes
constructed per EN 319 122-1 §5.5.3. The canonicalisation algorithm is
non-trivial — it assembles a byte sequence from:

1. Selected DER-encoded `SignedData` fields,
2. Each `SignerInfo`'s `signature`,
3. Every preceding archive timestamp, in order,
4. `SignedData.certificates` and `crls` (if any).

Today `eidas-verify` parses and validates the TST's CMS structure and
the TSA's chain, but does **not** recompute the canonical imprint.

```mermaid
flowchart TB
    start([archive-timestamp-v3 attr]) --> tst[verify_tst against raw signature]
    tst -- imprint mismatch --> fallback[verify_ats_best_effort]
    fallback --> sigcheck[verify TSA CMS signature<br/>+ TSA chain at gen_time]
    sigcheck -- OK --> warn[emit ATS_IMPRINT_NOT_VERIFIED]
    sigcheck -- fail --> atsfail[ATS_INVALID diagnostic]
    warn --> lift{at B-LT?}
    lift -- yes --> blta[Level::BLTA]
    lift -- no --> stay[stay at B-LT / B-T]
    tst -- OK --> ok[rare: trivially matching imprint]
    ok --> blta
```

The `ATS_IMPRINT_NOT_VERIFIED` warning is the library's way of being
honest about a trust-boundary gap: the TSA's *signature* is trustworthy,
but we haven't cryptographically re-bound it to the signed data. A
security review should downgrade such reports.

## Level-aware `qualification`

The qualification engine ignores `level_reached` — it only looks at the
chain, the TSL service status, and the signer cert's `qcStatements`.
That keeps the two axes independent: a B-B signature to a qualified
certificate is `QES` the same way a B-LTA one is, provided it passes
the B-B crypto checks.

## Test vectors

Every level transition is covered by integration tests:

| Test | Level reached | File |
|------|---------------|------|
| `cades_bb_rsa_attached_round_trip` | B-B | `crates/eidas-cms/tests/cades_bb.rs` |
| `cades_bt_round_trip_lifts_level_to_bt` | B-T | `crates/eidas-cades/tests/cades_bt.rs` |
| `cades_bb_without_timestamp_stays_at_bb` | B-B | `crates/eidas-cades/tests/cades_bt.rs` |
| `cades_bt_invalid_timestamp_keeps_bb_with_warning` | B-B | `crates/eidas-cades/tests/cades_bt.rs` |
| `cades_blt_round_trip_lifts_level_to_blt` | B-LT | `crates/eidas-cades/tests/cades_lt.rs` |

B-LTA does not yet have a positive integration test — canonicalising
CAdES bytes to pass the ATS imprint check is the same problem the
verifier itself defers. A DSS-corpus-based test arrives alongside the
full ATS implementation.
