//! End-to-end PAdES B-B verification.
//!
//! We hand-craft a minimal PDF containing a signature dictionary with a
//! fixed-size `/Contents` hex placeholder, compute the ByteRange, sign the
//! concatenated ranges with openssl CMS, and splice the DER into the
//! placeholder.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use der::Decode;
use eidas_cades::CadesTrustMaterial;
use eidas_core::{Level, Status, ValidationTime};
use eidas_pades::{verify_pades, PadesInput};
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
        if line.starts_with("-----BEGIN ") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(b64).unwrap()
}

struct Pki {
    ca_cert: Certificate,
    signer_pem: PathBuf,
    signer_key: PathBuf,
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
        "-subj", "/CN=pades test CA",
        "-days", "3650",
        "-set_serial", "1",
    ]));

    let leaf_key = p.join("leaf.key");
    let leaf_csr = p.join("leaf.csr");
    let leaf_pem = p.join("leaf.pem");
    run(Command::new("openssl").args([
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", &leaf_key.to_string_lossy(),
    ]));
    run(Command::new("openssl").args([
        "req", "-new",
        "-key", &leaf_key.to_string_lossy(),
        "-out", &leaf_csr.to_string_lossy(),
        "-subj", "/CN=pades test signer",
    ]));
    let ext = p.join("leaf.ext");
    fs::write(
        &ext,
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
        "-extfile", &ext.to_string_lossy(),
    ]));

    let ca_cert = Certificate::from_der(&pem_to_der(&fs::read(&ca_pem).unwrap())).unwrap();
    Pki { ca_cert, signer_pem: leaf_pem, signer_key: leaf_key, dir }
}

/// Build a minimal PDF with a placeholder signature dictionary, sign the
/// pre-placeholder byte ranges, and splice the resulting CMS DER into the
/// `/Contents` hex blob.
fn build_signed_pdf(pki: &Pki) -> Vec<u8> {
    // Step 1: generate a template PDF with a zeroed Contents placeholder of
    // a fixed size. We use a 16 KiB placeholder (8192 hex chars); real
    // signatures fit comfortably.
    const CONTENTS_HEX_LEN: usize = 16_384; // 16 KiB of hex = 8 KiB binary
    let placeholder = "0".repeat(CONTENTS_HEX_LEN);

    // A minimal-but-valid PDF 1.7 with one page and a signature annotation.
    // The ByteRange entries are filled in *after* serialising so we can
    // compute the exact offsets.
    //
    // We emit ByteRange as `/ByteRange [0                      **********]`
    // with 10-digit placeholders per entry; we'll overwrite them afterwards.
    let br_placeholder = "/ByteRange [0000000000 0000000000 0000000000 0000000000]";

    // Construct object bodies. We'll use manual offsets for the xref.
    let header = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";

    // Object 1: Catalog -> Pages (2), AcroForm points to Sig field (object 5).
    let obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /SigFlags 3 >> >>\nendobj\n";
    // Object 2: Pages
    let obj2 = "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n";
    // Object 3: Page with a signature annotation
    let obj3 = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R] >>\nendobj\n";
    // Object 4: empty content stream
    let obj4 = "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n";

    // Object 5 is the signature form field + widget annotation; its /V
    // references object 6, which is the signature dictionary itself.
    let obj5 = "5 0 obj\n<< /FT /Sig /Type /Annot /Subtype /Widget /F 4 /Rect [0 0 0 0] /T (Signature1) /V 6 0 R /P 3 0 R >>\nendobj\n";

    // Object 6: the signature dictionary with the placeholder.
    // Intentionally use a fixed /ByteRange placeholder we'll rewrite.
    let obj6 = format!(
        "6 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached {br_placeholder} /Contents <{placeholder}> >>\nendobj\n"
    );

    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(header);
    let off1 = bytes.len();
    bytes.extend_from_slice(obj1.as_bytes());
    let off2 = bytes.len();
    bytes.extend_from_slice(obj2.as_bytes());
    let off3 = bytes.len();
    bytes.extend_from_slice(obj3.as_bytes());
    let off4 = bytes.len();
    bytes.extend_from_slice(obj4.as_bytes());
    let off5 = bytes.len();
    bytes.extend_from_slice(obj5.as_bytes());
    let off6 = bytes.len();
    bytes.extend_from_slice(obj6.as_bytes());

    // xref
    let xref_offset = bytes.len();
    let xref = format!(
        "xref\n0 7\n0000000000 65535 f \n{:010} 00000 n \n{:010} 00000 n \n{:010} 00000 n \n{:010} 00000 n \n{:010} 00000 n \n{:010} 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
        off1, off2, off3, off4, off5, off6, xref_offset
    );
    bytes.extend_from_slice(xref.as_bytes());

    // --- Compute real ByteRange values ---
    //
    // Signature covers: [0 .. start_of_<] ++ [end_of_> .. EOF]
    //
    // Find the '<' and '>' of the signature /Contents.
    // Find the `/Contents <` hex blob specifically. The opening `<` of the
    // dictionary itself is `<<` (two bytes), so we look for the `/Contents`
    // key and then the first `<` that is NOT followed by another `<`.
    let gt_abs = {
        let needle = b"/Contents";
        let idx = bytes[off6..]
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap()
            + off6;
        let after = idx + needle.len();
        // Skip whitespace, then expect '<' followed by a hex char (not '<').
        let lt = {
            let mut i = after;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            assert_eq!(bytes[i], b'<', "expected '<' after /Contents");
            i
        };
        // End: first `>` that isn't followed by another `>`.
        let gt = {
            let mut i = lt + 1;
            while i < bytes.len() {
                if bytes[i] == b'>' && bytes.get(i + 1) != Some(&b'>') {
                    break;
                }
                i += 1;
            }
            i
        };
        (lt, gt)
    };
    let contents_lt = gt_abs.0;
    let contents_gt = gt_abs.1;

    let a = 0usize;
    let b = contents_lt; // length up to (and including the `<` is at contents_lt)
    let c = contents_gt + 1;
    let d = bytes.len() - c;

    let real_br = format!(
        "/ByteRange [{:<10} {:<10} {:<10} {:<10}]",
        a, b, c, d
    );
    // The placeholder and real string are the same length (55 chars), so
    // we can overwrite in place.
    assert_eq!(br_placeholder.len(), real_br.len());
    let br_start = bytes
        .windows(br_placeholder.len())
        .position(|w| w == br_placeholder.as_bytes())
        .expect("br placeholder must exist");
    bytes[br_start..br_start + real_br.len()].copy_from_slice(real_br.as_bytes());

    // --- Now produce the CMS signature over the signed ranges. ---
    let data_to_sign: Vec<u8> = {
        let mut v = Vec::with_capacity(b + d);
        v.extend_from_slice(&bytes[a..a + b]);
        v.extend_from_slice(&bytes[c..c + d]);
        v
    };
    let data_path = pki.dir.path().join("pdf_signed_ranges.bin");
    fs::write(&data_path, &data_to_sign).unwrap();
    let sig_path = pki.dir.path().join("pdf.p7s");
    run(Command::new("openssl").args([
        "cms", "-sign", "-binary", "-md", "sha256", "-cades",
        "-in", &data_path.to_string_lossy(),
        "-signer", &pki.signer_pem.to_string_lossy(),
        "-inkey", &pki.signer_key.to_string_lossy(),
        "-outform", "DER",
        "-out", &sig_path.to_string_lossy(),
    ]));
    let sig_der = fs::read(&sig_path).unwrap();
    assert!(
        sig_der.len() * 2 <= CONTENTS_HEX_LEN,
        "CMS too big for placeholder: {} > {}",
        sig_der.len() * 2,
        CONTENTS_HEX_LEN
    );

    // Encode as hex (uppercase, no separators) and write into placeholder.
    let hex_sig: String = sig_der.iter().map(|b| format!("{b:02x}")).collect();
    let hex_bytes = hex_sig.as_bytes();
    // The hex blob between `<` and `>` starts at contents_lt+1.
    let placeholder_start = contents_lt + 1;
    // The total hex slot is CONTENTS_HEX_LEN chars (no separators in our placeholder).
    bytes[placeholder_start..placeholder_start + hex_bytes.len()]
        .copy_from_slice(hex_bytes);
    // Keep trailing '0' padding after the signature bytes so the placeholder
    // stays the same length.

    bytes
}

#[test]
fn pades_bb_round_trip() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let pki = build_pki();
    let pdf = build_signed_pdf(&pki);
    // Persist to disk so test failures can be diagnosed.
    fs::write(pki.dir.path().join("signed.pdf"), &pdf).unwrap();
    let trust = CadesTrustMaterial::new().with_anchors([pki.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_pades(
        &PadesInput { pdf: &pdf },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();

    assert!(
        matches!(
            report.container,
            Some(eidas_core::ContainerInfo::Pdf { revisions: 1 })
        ),
        "container = {:?}",
        report.container
    );
    assert_eq!(report.signatures.len(), 1);
    let sr = &report.signatures[0];
    assert_eq!(sr.status, Status::TotalPassed, "diagnostics: {:?}", sr.diagnostics);
    assert_eq!(sr.level_reached, Level::BB);
}

#[test]
fn pades_reports_no_signatures_on_plain_pdf() {
    let tmp = TempDir::new().unwrap();
    // A minimal PDF with no signature dictionary.
    let plain = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000010 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n59\n%%EOF\n";
    fs::write(tmp.path().join("plain.pdf"), plain).unwrap();
    let trust = CadesTrustMaterial::new();
    let policy = eidas_policy::etsi_119_312_2023();
    let err = verify_pades(
        &PadesInput { pdf: plain },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .expect_err("plain PDF must report no signatures");
    assert!(matches!(err, eidas_core::Error::Pdf(_)));
}

#[test]
fn pades_detects_tampered_body() {
    if !openssl_present() {
        eprintln!("skipping: openssl CLI not found");
        return;
    }
    let pki = build_pki();
    let mut pdf = build_signed_pdf(&pki);
    // Flip a single byte near the end of the file (outside the signature
    // placeholder but inside a signed range).
    let target = pdf.len() - 10;
    pdf[target] ^= 0xFF;

    let trust = CadesTrustMaterial::new().with_anchors([pki.ca_cert.clone()]);
    let policy = eidas_policy::etsi_119_312_2023();
    let report = verify_pades(
        &PadesInput { pdf: &pdf },
        &trust,
        &policy,
        ValidationTime::Now,
    )
    .unwrap();
    assert_eq!(report.signatures[0].status, Status::TotalFailedSub);
}
