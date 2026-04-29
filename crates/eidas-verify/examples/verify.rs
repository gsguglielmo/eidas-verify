//! Minimal command-line verifier.
//!
//! Usage:
//!   cargo run --example verify -- --cms sig.p7s --data data.txt --anchor ca.pem
//!   cargo run --example verify -- --pdf signed.pdf --anchor ca.pem
//!
//! The anchor argument points at a PEM-encoded X.509 certificate. Multiple
//! `--anchor` arguments can be supplied.

use std::env;
use std::fs;
use std::process::ExitCode;

use base64::{engine::general_purpose::STANDARD, Engine};
use der::Decode;
use eidas_verify::{
    cades::CadesTrustMaterial, ContainerHint, DetachedFormat, ValidationTime,
    VerificationInput, Verifier,
};
use x509_cert::Certificate;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut cms = None;
    let mut data = None;
    let mut pdf = None;
    let mut anchors: Vec<Certificate> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--cms" => {
                cms = Some(args[i + 1].clone());
                i += 2;
            }
            "--data" => {
                data = Some(args[i + 1].clone());
                i += 2;
            }
            "--pdf" => {
                pdf = Some(args[i + 1].clone());
                i += 2;
            }
            "--anchor" => {
                let bytes = match fs::read(&args[i + 1]) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("cannot read anchor {}: {e}", args[i + 1]);
                        return ExitCode::from(2);
                    }
                };
                let der = pem_to_der(&bytes);
                match Certificate::from_der(&der) {
                    Ok(c) => anchors.push(c),
                    Err(e) => {
                        eprintln!("cannot parse anchor {}: {e}", args[i + 1]);
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                return ExitCode::from(2);
            }
        }
    }

    if anchors.is_empty() {
        eprintln!("at least one --anchor is required");
        return ExitCode::from(2);
    }

    let verifier = match Verifier::builder()
        .trust_anchors(anchors)
        .validation_time(ValidationTime::Now)
        .build()
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("builder error: {e}");
            return ExitCode::from(2);
        }
    };

    let report = if let Some(path) = pdf {
        let bytes = fs::read(&path).expect("read pdf");
        verifier.verify(VerificationInput::Container {
            bytes: &bytes,
            hint: Some(ContainerHint::Pdf),
        })
    } else if let (Some(cms_path), Some(data_path)) = (cms.clone(), data) {
        let sig_bytes = fs::read(&cms_path).expect("read cms");
        let data_bytes = fs::read(&data_path).expect("read data");
        verifier.verify(VerificationInput::Detached {
            signature: &sig_bytes,
            signed_data: &data_bytes,
            format: DetachedFormat::Cades,
        })
    } else if let Some(cms_path) = cms {
        let sig_bytes = fs::read(&cms_path).expect("read cms");
        verifier.verify(VerificationInput::Container {
            bytes: &sig_bytes,
            hint: None,
        })
    } else {
        eprintln!("supply --pdf or --cms (with optional --data for detached)");
        return ExitCode::from(2);
    };

    let report = match report {
        Ok(r) => r,
        Err(e) => {
            eprintln!("verification error: {e}");
            return ExitCode::FAILURE;
        }
    };

    for (i, sig) in report.signatures.iter().enumerate() {
        println!(
            "signature {i}: status={:?} level={:?} qualification={:?}",
            sig.status, sig.level_reached, sig.qualification
        );
        if let Some(c) = &sig.signer {
            println!("  signer: {}", c.subject);
        }
        for d in &sig.diagnostics {
            println!("  {d}");
        }
    }
    let _ = CadesTrustMaterial::new; // keep the re-export referenced

    if report.signatures.iter().all(|s| s.status == eidas_verify::Status::TotalPassed) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_help() {
    eprintln!("eidas-verify — EU electronic signature verifier (demo)\n");
    eprintln!("  --cms <file.p7s>    CMS signature (CAdES)");
    eprintln!("  --data <file>       detached signed data (with --cms)");
    eprintln!("  --pdf <file.pdf>    PAdES-signed PDF");
    eprintln!("  --anchor <ca.pem>   trust anchor (repeat for multiple)");
}

fn pem_to_der(pem_bytes: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(pem_bytes).expect("PEM must be UTF-8");
    if !s.contains("-----BEGIN ") {
        // Already DER.
        return pem_bytes.to_vec();
    }
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
    STANDARD.decode(b64).expect("valid PEM base64")
}
