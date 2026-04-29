//! End-to-end XAdES B-B verification.
//!
//! We synthesise a signed enveloped XMLDSig document using our own
//! canonicaliser for digest and signed-info normalisation, then sign with
//! openssl. This exercises the verifier end-to-end without depending on
//! xmlsec1 being installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine};
use der::Decode;
use eidas_core::{Level, Status, ValidationTime};
use eidas_xades::{verify_xades, XadesInput};
use eidas_x509::chain::{ChainBuilder, TrustAnchor};
use sha2::{Digest, Sha256};
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
        if line.starts_with("-----BEGIN ") { in_block = true; continue; }
        if line.starts_with("-----END ") { break; }
        if in_block { b64.push_str(line.trim()); }
    }
    STANDARD.decode(b64).unwrap()
}

struct Pki {
    ca: Certificate,
    leaf_der: Vec<u8>,
    leaf_key_pem: PathBuf,
    dir: TempDir,
}

fn build_pki() -> Pki {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let ca_key = p.join("ca.key");
    let ca_pem = p.join("ca.pem");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &ca_key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new", "-x509",
        "-key", &ca_key.to_string_lossy(),
        "-out", &ca_pem.to_string_lossy(),
        "-subj", "/CN=XAdES test CA",
        "-days", "3650",
        "-set_serial", "1",
    ]));
    let leaf_key = p.join("leaf.key");
    let leaf_csr = p.join("leaf.csr");
    let leaf_pem = p.join("leaf.pem");
    let leaf_ext = p.join("leaf.ext");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &leaf_key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", "/CN=XAdES test signer",
    ]));
    fs::write(
        &leaf_ext,
        "keyUsage = critical, digitalSignature, nonRepudiation\nbasicConstraints = CA:FALSE\n",
    )
    .unwrap();
    run(Command::new("openssl").args([
        "x509", "-req",
        "-in", &leaf_csr.to_string_lossy(),
        "-CA", &ca_pem.to_string_lossy(),
        "-CAkey", &ca_key.to_string_lossy(),
        "-CAcreateserial",
        "-out", &leaf_pem.to_string_lossy(),
        "-days", "3650",
        "-sha256",
        "-extfile", &leaf_ext.to_string_lossy(),
    ]));
    Pki {
        ca: Certificate::from_der(&pem_to_der(&fs::read(&ca_pem).unwrap())).unwrap(),
        leaf_der: pem_to_der(&fs::read(&leaf_pem).unwrap()),
        leaf_key_pem: leaf_key,
        dir,
    }
}

fn rsa_sha256_sign(leaf_key_pem: &Path, signing_input: &[u8]) -> Vec<u8> {
    let dir = leaf_key_pem.parent().unwrap();
    let si = dir.join("si.bin");
    fs::write(&si, signing_input).unwrap();
    let out = dir.join("sig.bin");
    run(Command::new("openssl").args([
        "dgst", "-sha256",
        "-sign", &leaf_key_pem.to_string_lossy(),
        "-out", &out.to_string_lossy(),
        &si.to_string_lossy(),
    ]));
    fs::read(&out).unwrap()
}

/// Build an enveloped XMLDSig-XAdES document over a fixed body. Uses our own
/// c14n to compute both the Reference digest (over the root canonicalised
/// with enveloped-signature transform) and the SignedInfo canonical form.
fn build_signed_doc(pki: &Pki) -> Vec<u8> {
    use eidas_xades::c14n::{exc_c14n_with_envelope_strip, EnvelopeTarget};

    // --- Step 1: root template with an empty Signature placeholder. We'll
    //     compute the Reference digest by canonicalising the root with the
    //     enveloped-signature transform (strips Signature).
    //
    // The signature lives inside the root so the Reference URI is the empty
    // string ("root element"); for consistency we wrap in a top-level
    // element that is our "document".
    //
    // We first build a document with a placeholder `<Signature/>` so that
    // the enveloped-signature transform sees a Signature to strip. The
    // digest only depends on the *non-signature* subtree content.
    let doc_with_placeholder = br#"<Document><Data>important business</Data><Signature/></Document>"#;

    // Canonicalise with enveloped-signature stripping → byte input for the
    // Reference digest.
    let ref_input = exc_c14n_with_envelope_strip(
        doc_with_placeholder,
        Some(EnvelopeTarget { local: b"Signature", namespace: None }),
    )
    .unwrap();
    let ref_digest = Sha256::digest(&ref_input);
    let ref_digest_b64 = STANDARD.encode(ref_digest);

    // --- Step 2: construct SignedInfo and canonicalise it. We hand-craft
    //     a string that our canonicaliser will emit identically (no extra
    //     whitespace, no default namespace declarations).
    let signed_info = format!(
        r#"<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod><DigestValue>{ref_digest_b64}</DigestValue></Reference></SignedInfo>"#
    );
    let signed_info_c14n = exc_c14n_with_envelope_strip(signed_info.as_bytes(), None).unwrap();

    // --- Step 3: sign the canonicalised SignedInfo bytes with RSA-SHA256.
    let sig_bytes = rsa_sha256_sign(&pki.leaf_key_pem, &signed_info_c14n);
    let sig_b64 = STANDARD.encode(&sig_bytes);

    // --- Step 4: assemble the final document replacing the placeholder.
    let cert_b64 = STANDARD.encode(&pki.leaf_der);
    let signature_xml = format!(
        r#"<Signature><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod><DigestValue>{ref_digest_b64}</DigestValue></Reference></SignedInfo><SignatureValue>{sig_b64}</SignatureValue><KeyInfo><X509Data><X509Certificate>{cert_b64}</X509Certificate></X509Data></KeyInfo></Signature>"#
    );

    let mut final_doc = Vec::new();
    final_doc.extend_from_slice(b"<Document><Data>important business</Data>");
    final_doc.extend_from_slice(signature_xml.as_bytes());
    final_doc.extend_from_slice(b"</Document>");
    final_doc
}

#[test]
fn xades_enveloped_rsa_sha256_round_trip() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let xml = build_signed_doc(&pki);
    fs::write(pki.dir.path().join("signed.xml"), &xml).unwrap();

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.ca.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_xades(
        &XadesInput { xml: &xml },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    assert_eq!(report.signatures.len(), 1);
    let sr = &report.signatures[0];
    assert_eq!(sr.status, Status::TotalPassed, "diag: {:?}", sr.diagnostics);
    assert_eq!(sr.level_reached, Level::BB);
    // The narrow-profile warning must always be present.
    let codes: Vec<_> = sr.diagnostics.iter().map(|d| d.code.as_str()).collect();
    assert!(
        codes.iter().any(|c| *c == "XADES_NARROW_PROFILE"),
        "expected narrow-profile diag, got {codes:?}"
    );
}

#[test]
fn xades_detects_tampered_data() {
    if !openssl_present() { return; }
    let pki = build_pki();
    let mut xml = build_signed_doc(&pki);
    // Change "important business" to "tampered business"
    let idx = xml.windows(9).position(|w| w == b"important").unwrap();
    xml[idx..idx + 9].copy_from_slice(b"tampered!");

    let builder = ChainBuilder::new().with_anchors([TrustAnchor::new(pki.ca.clone())]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_xades(
        &XadesInput { xml: &xml },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
    let codes: Vec<_> = report.signatures[0]
        .diagnostics
        .iter()
        .map(|d| d.code.as_str())
        .collect();
    assert!(
        codes.iter().any(|c| *c == "REFERENCE_DIGEST_MISMATCH"),
        "expected digest mismatch, got {codes:?}"
    );
}

#[test]
fn xades_rejects_unsupported_c14n() {
    // Canonicalisation method other than exc-c14n must be flagged.
    let fake_xml = br#"<Document><Signature><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AAAA</DigestValue></Reference></SignedInfo><SignatureValue>AAAA</SignatureValue></Signature></Document>"#;
    let builder = ChainBuilder::new();
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_xades(
        &XadesInput { xml: fake_xml },
        &builder,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
    let msg = &report.signatures[0].diagnostics[0].message;
    assert!(
        msg.contains("CanonicalizationMethod") || msg.contains("narrow"),
        "expected profile rejection, got `{msg}`"
    );
}
