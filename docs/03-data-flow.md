# Data flow

End-to-end sequence diagrams showing exactly which type crosses which
boundary during a `Verifier::verify()` call. One section per format.

## Common prelude: `Verifier::verify()` dispatch

Every call enters at the facade and is routed by
`VerificationInput` + `ContainerHint`/`DetachedFormat` (`crates/eidas-verify/src/verifier.rs`):

```mermaid
flowchart TB
    start(["verify(input)"]) --> match{match input}

    match -- "Detached { Cades }" --> cades[eidas_cades::verify_cades]
    match -- "Container { None }" --> cades
    match -- "Container { Pdf }" --> pades[eidas_pades::verify_pades]
    match -- "Container { Asic }" --> asic[eidas_asic::verify_asic]
    match -- "Container { JadesCompact }" --> jades_c[eidas_jades::verify_jades<br/>is_json=false]
    match -- "Container { JadesJson }" --> jades_j[eidas_jades::verify_jades<br/>is_json=true]
    match -- "Container { XadesEnveloped }" --> xades[eidas_xades::verify_xades]

    match -- otherwise --> err[Err(Unsupported)]

    cades --> report[VerificationReport]
    pades --> report
    asic --> report
    jades_c --> report
    jades_j --> report
    xades --> report
```

The trust material passed to each engine is reconstructed on every call
via `cades_trust_material()`, which snapshots the anchors and
intermediates cached on the `Verifier`.

## CAdES

Attached **or** detached. Detached adds `detached_content: Some(bytes)`
at the top of the flow; attached gets it from `SignedData.encap_content_info.eContent`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant CadesVerify as eidas_cades::verify_cades
    participant Envelope as eidas_cms::parse_cms_envelope
    participant Unsigned as eidas_cades::unsigned
    participant SigVerify as eidas_cms::signature_verify
    participant Chain as eidas_x509::ChainBuilder
    participant Policy as eidas_policy
    participant Revocation as eidas_revocation
    participant Timestamp as eidas_timestamp
    participant Qualify as eidas_qualify

    C->>CadesVerify: CadesInput + trust + policy + time
    CadesVerify->>Envelope: parse CMS bytes
    Envelope-->>CadesVerify: ParsedCms { SignedData, embedded_certs, content_bytes }

    loop for each SignerInfo
        CadesVerify->>Unsigned: extract unsigned attrs
        Unsigned-->>CadesVerify: UnsignedAttrs { sig_tst, rev_values, cert_values, ats }

        Note over CadesVerify: locate signer cert<br/>(embedded + ets-certValues)

        CadesVerify->>CadesVerify: check message-digest attr
        CadesVerify->>CadesVerify: verify signing-certificate-v2 ESSCertIDv2
        CadesVerify->>SigVerify: verify(signer_cert, alg, signed_attrs, sig)
        SigVerify-->>CadesVerify: Ok / Err

        loop for each signature-time-stamp token
            CadesVerify->>Timestamp: verify_tst(token, signer.signature)
            Timestamp-->>CadesVerify: TstVerification → best_signature_time
        end

        CadesVerify->>CadesVerify: resolve reference_time<br/>(ValidationTime + best_signature_time)

        CadesVerify->>Chain: build(signer_cert, reference_time)
        Chain-->>CadesVerify: ChainValidationResult

        CadesVerify->>Policy: evaluate(algorithm, reference_time)
        Policy-->>CadesVerify: PolicyDecision

        alt revocation-values present
            loop for each chain cert (non-anchor)
                CadesVerify->>Revocation: try_ocsp / try_crl
                Revocation-->>CadesVerify: RevocationInfo
            end
            Note over CadesVerify: any Revoked → TotalFailedSub<br/>all Good + B-T → lift to B-LT
        end

        alt archive-timestamp-v3 present
            CadesVerify->>Timestamp: verify_tst(ats, signer.signature)
            Note over CadesVerify: imprint-mismatch fallback path →<br/>verify_ats_best_effort (skip imprint)<br/>emit ATS_IMPRINT_NOT_VERIFIED
        end

        opt trusted_lists attached
            CadesVerify->>Qualify: qualify_signer(chain, tls, at)
            Qualify-->>CadesVerify: QualificationOutput
        end

        CadesVerify-->>C: SignatureReport
    end
```

Key files:
- `crates/eidas-cades/src/verify.rs` — the orchestrator.
- `crates/eidas-cades/src/unsigned.rs` — unsigned-attr parsing.
- `crates/eidas-cms/src/envelope.rs` — shared CMS envelope parse.

## PAdES

PAdES is "detached CAdES inside a PDF". The PDF layer is a byte-range
scanner; every signature it finds is fanned out to CAdES.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant PadesVerify as eidas_pades::verify_pades
    participant Scan as eidas_pades::scan::find_signatures
    participant CadesVerify as eidas_cades::verify_cades

    C->>PadesVerify: PadesInput { pdf }
    PadesVerify->>Scan: find_signatures(pdf)
    Scan->>Scan: locate all /ByteRange<br/>+ adjacent /Contents
    Scan-->>PadesVerify: Vec#lt;PdfSignatureLocation#gt;

    loop for each signature location
        Note over PadesVerify: check /SubFilter is supported
        PadesVerify->>PadesVerify: signed_bytes = pdf[a..a+b] ++ pdf[c..c+d]
        PadesVerify->>CadesVerify: CadesInput { cms, detached = signed_bytes }
        CadesVerify-->>PadesVerify: SignatureReport
        PadesVerify->>PadesVerify: annotate with<br/>PADES_SIGNATURE_FOUND + ByteRange
    end

    PadesVerify-->>C: VerificationReport +<br/>ContainerInfo::Pdf { revisions }
```

PAdES accepts `/SubFilter` values `adbe.pkcs7.detached`,
`ETSI.CAdES.detached`, `ETSI.RFC3161`. Unknown SubFilters yield a
`PADES_UNSUPPORTED_SUB_FILTER` failure report rather than an `Err`.

Key files:
- `crates/eidas-pades/src/scan.rs` — byte-level `/ByteRange` / `/Contents` scanner.
- `crates/eidas-pades/src/verify.rs` — dispatch.

## ASiC

ASiC unpacks a ZIP. Each signature under `META-INF/` is paired with each
top-level data file until one pairing verifies. No manifest parsing yet
(the brute-force pairing correctly handles the common single-signature-per-document case).

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant AsicVerify as eidas_asic::verify_asic
    participant Zip as zip crate
    participant CadesVerify as eidas_cades::verify_cades

    C->>AsicVerify: AsicInput { bytes }
    AsicVerify->>Zip: open ZipArchive
    Zip-->>AsicVerify: entries

    AsicVerify->>AsicVerify: split entries:<br/>mimetype / signatures / data_files

    loop for each signature META-INF/*.p7s
        loop for each data file
            AsicVerify->>CadesVerify: verify(cms=sig, detached=data)
            alt passes
                CadesVerify-->>AsicVerify: TotalPassed report
                Note over AsicVerify: annotate with<br/>ASIC_SIGNATURE_BINDING<br/>sig_name → data_name<br/>break inner loop
            else fails
                CadesVerify-->>AsicVerify: TotalFailedSub
                Note over AsicVerify: keep as last_failure,<br/>try next data
            end
        end
        alt no pairing matched
            AsicVerify->>AsicVerify: emit ASIC_SIGNATURE_UNMATCHED
        end
    end

    AsicVerify-->>C: VerificationReport +<br/>ContainerInfo::Asic { mime_type, entries }
```

Key file: `crates/eidas-asic/src/verify.rs`.

## JAdES

JWS — RFC 7515 — with ETSI-specific headers. Self-contained: `eidas-jades`
does its own parsing and crypto without going through `eidas-cms`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant JadesVerify as eidas_jades::verify_jades
    participant Jws as eidas_jades::jws::JwsSignature
    participant Chain as eidas_x509::ChainBuilder

    C->>JadesVerify: JadesInput { bytes, is_json }
    alt is_json
        JadesVerify->>Jws: from_flattened_json
    else
        JadesVerify->>Jws: from_compact
    end
    Jws-->>JadesVerify: JwsSignature { header, payload_b64, signature, ... }

    JadesVerify->>Jws: signer_certificate()<br/>= x5c[0] (base64 DER, not b64url)
    Jws-->>JadesVerify: Certificate

    Note over JadesVerify: enforce x5t#S256<br/>SHA-256(cert DER)<br/>== claimed header.x5t_s256

    JadesVerify->>JadesVerify: alg dispatch
    alt RS256 / RS384 / RS512
        JadesVerify->>JadesVerify: rsa PKCS#1v1.5 verify<br/>over "h.p" ASCII bytes
    else ES256 / ES384
        JadesVerify->>JadesVerify: ECDSA verify<br/>raw r||s signature,<br/>prehash = SHA(h.p)
    else other
        JadesVerify-->>C: Err(Unsupported)
    end

    JadesVerify->>JadesVerify: parse sigT<br/>→ signing_time_claimed

    Note over JadesVerify: push x5c[1..] as intermediates
    JadesVerify->>Chain: build(signer, reference_time)
    Chain-->>JadesVerify: ChainValidationResult

    alt sigTst header present
        Note over JadesVerify: emit JADES_SIG_TST_NOT_VERIFIED<br/>(full B-T lift deferred)
    end

    JadesVerify-->>C: SignatureReport + ContainerInfo::Jws
```

**Critical note on signature format:** JWS ECDSA signatures are **raw
r||s** (RFC 7518 §3.4), unlike CAdES's DER-encoded r+s. Crossing the
streams is a common integration bug; `eidas-jades::verify::ecdsa_verify_p256`
uses `p256::ecdsa::Signature::try_from(raw_bytes)` rather than
`::from_der`.

Key files:
- `crates/eidas-jades/src/jws.rs` — parse + header typing.
- `crates/eidas-jades/src/verify.rs` — crypto + chain.

## XAdES (narrow profile, opt-in)

Enveloped XMLDSig only. Canonicalisation method must be Exclusive C14N 1.0.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant XadesVerify as eidas_xades::verify_xades
    participant Parse as eidas_xades::parse
    participant C14n as eidas_xades::c14n
    participant Chain as eidas_x509::ChainBuilder

    C->>XadesVerify: XadesInput { xml }
    XadesVerify->>Parse: parse_xml_signature(xml)
    Parse-->>XadesVerify: ParsedSignature {<br/>  canonicalization_method,<br/>  signature_method,<br/>  reference_digest_method + value,<br/>  transforms,<br/>  signature_value,<br/>  signer_cert }

    XadesVerify->>XadesVerify: enforce profile:<br/>exc-c14n + {enveloped-sig, exc-c14n}<br/>+ known digest/sig algs

    Note over XadesVerify: Step 1 — Reference digest
    XadesVerify->>C14n: exc_c14n(xml, strip=Signature)
    C14n-->>XadesVerify: canonicalised document bytes
    XadesVerify->>XadesVerify: hash → compare to Reference/DigestValue
    alt mismatch
        XadesVerify-->>C: TotalFailedSub<br/>REFERENCE_DIGEST_MISMATCH
    end

    Note over XadesVerify: Step 2 — SignedInfo signature
    XadesVerify->>C14n: exc_c14n(#lt;SignedInfo#gt; subtree)
    C14n-->>XadesVerify: canonicalised SignedInfo
    XadesVerify->>XadesVerify: RSA/ECDSA verify<br/>(ECDSA is raw r||s, same as JWS)

    XadesVerify->>Chain: build(signer, reference_time)
    Chain-->>XadesVerify: ChainValidationResult

    Note over XadesVerify: always emit<br/>XADES_NARROW_PROFILE diag
    XadesVerify-->>C: SignatureReport
```

Key files:
- `crates/eidas-xades/src/parse.rs` — quick-xml event-driven walk of
  `<ds:Signature>`.
- `crates/eidas-xades/src/c14n.rs` — Exclusive C14N 1.0 narrow subset
  (attribute sorting, enveloped-signature strip, escape rules).
- `crates/eidas-xades/src/verify.rs` — orchestration + crypto.

## Crypto signature verification (shared)

All format crates reduce down to one of these primitives:

```mermaid
flowchart LR
    classDef shared fill:#fde9c8,stroke:#f5a623

    style cms fill:#fff

    subgraph cms [eidas_cms::signature_verify]
      vv[verify_cms_signature<br/>(cert, sig_alg, digest_hint, data, sig)]:::shared
      resolve[resolve_sig_alg]
      rsa[rsa_pkcs1v15_verify]
      p256[ecdsa_p256_verify]
      p384[ecdsa_p384_verify]
      vv --> resolve
      resolve --> rsa
      resolve --> p256
      resolve --> p384
    end

    jades_rsa[eidas_jades::verify::rsa_verify] --> rsa
    jades_p256[eidas_jades::verify::ecdsa_verify_p256] -.->|JWS raw r#124;#124;s| p256
    xades_rsa[eidas_xades::verify::rsa_verify] --> rsa
    xades_p256[eidas_xades::verify::ecdsa_p256_verify] -.->|XMLDSig raw r#124;#124;s| p256
```

CAdES signatures come in as DER-encoded ECDSA (`p256::ecdsa::Signature::from_der`).
JAdES and XAdES come in as raw r||s (`Signature::try_from(&[u8])`).
The format crates pick the right decoder; the primitive itself doesn't
know which encoding is in play.
