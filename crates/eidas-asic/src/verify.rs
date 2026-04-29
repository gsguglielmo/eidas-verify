//! Verify each CAdES signature in an ASiC container.

use std::io::Read;

use eidas_cades::{verify_cades, CadesTrustMaterial};
use eidas_cms::CadesInput;
use eidas_core::{
    AlgorithmPolicy, ContainerInfo, DiagnosticMessage, Error, Result, SignatureReport, Status,
    ValidationTime, VerificationReport,
};
use zip::ZipArchive;

/// Input: the raw bytes of an ASiC ZIP container.
pub struct AsicInput<'a> {
    pub bytes: &'a [u8],
}

/// Verify every CAdES signature found under `META-INF/` in the ASiC.
///
/// Each signature is attempted against each top-level signed file; the first
/// pair that yields a passing CAdES report is recorded. Signatures that match
/// no file are reported as `TotalFailedSub` with an explicit diagnostic.
pub fn verify_asic(
    input: &AsicInput<'_>,
    trust: &CadesTrustMaterial,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<VerificationReport> {
    let cursor = std::io::Cursor::new(input.bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| Error::Zip(format!("ASiC ZIP open: {e}")))?;

    let (mime_type, signatures, data_files, entry_names) = collect_entries(&mut archive)?;

    if signatures.is_empty() {
        return Err(Error::Zip(
            "ASiC container has no signatures under META-INF/".into(),
        ));
    }
    if data_files.is_empty() {
        return Err(Error::Zip(
            "ASiC container has no top-level data files".into(),
        ));
    }

    let mut reports: Vec<SignatureReport> = Vec::new();
    for (sig_name, cms_der) in &signatures {
        let mut matched = false;
        let mut last_failure: Option<SignatureReport> = None;
        for (data_name, data_bytes) in &data_files {
            match verify_cades(
                &CadesInput {
                    cms: cms_der,
                    detached_content: Some(data_bytes),
                },
                trust,
                policy,
                validation_time,
            ) {
                Ok(r) => {
                    for mut sr in r.signatures {
                        sr.diagnostics.push(DiagnosticMessage::info(
                            "ASIC_SIGNATURE_BINDING",
                            format!("{sig_name} -> {data_name}"),
                        ));
                        let passing = sr.status == Status::TotalPassed;
                        if passing {
                            reports.push(sr);
                            matched = true;
                        } else {
                            last_failure = Some(sr);
                        }
                    }
                    if matched {
                        break;
                    }
                }
                Err(e) => {
                    last_failure = Some(SignatureReport::failed(
                        "ASIC_CADES_DISPATCH_FAILED",
                        format!("{sig_name} -> {data_name}: {e}"),
                    ));
                }
            }
        }
        if !matched {
            reports.push(last_failure.unwrap_or_else(|| {
                SignatureReport::failed(
                    "ASIC_SIGNATURE_UNMATCHED",
                    format!("signature {sig_name} did not verify against any data entry"),
                )
            }));
        }
    }

    Ok(VerificationReport {
        signatures: reports,
        container: Some(ContainerInfo::Asic {
            mime_type: mime_type.unwrap_or_else(|| "application/zip".into()),
            entries: entry_names,
        }),
    })
}

/// Walk the ZIP central directory and split entries into buckets.
///
/// Returns:
/// - the `mimetype` file's contents, if present,
/// - every signature blob under `META-INF/` matching our CAdES filename conventions,
/// - every non-META-INF, non-mimetype file (treated as signed data),
/// - the full list of entry names (for `ContainerInfo`).
#[allow(clippy::type_complexity)]
fn collect_entries(
    archive: &mut ZipArchive<std::io::Cursor<&[u8]>>,
) -> Result<(
    Option<String>,
    Vec<(String, Vec<u8>)>,
    Vec<(String, Vec<u8>)>,
    Vec<String>,
)> {
    let mut mime_type = None;
    let mut signatures = Vec::new();
    let mut data_files = Vec::new();
    let mut names = Vec::with_capacity(archive.len());

    for idx in 0..archive.len() {
        let mut file = archive
            .by_index(idx)
            .map_err(|e| Error::Zip(format!("ASiC entry {idx}: {e}")))?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        names.push(name.clone());
        let mut buf = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut buf)
            .map_err(|e| Error::Zip(format!("ASiC read '{name}': {e}")))?;

        if name == "mimetype" {
            mime_type = Some(
                String::from_utf8(buf.clone())
                    .map_err(|e| Error::Zip(format!("mimetype not UTF-8: {e}")))?
                    .trim()
                    .to_string(),
            );
            continue;
        }
        if name.starts_with("META-INF/") {
            // CAdES signatures are .p7s files. XAdES and manifests live here
            // too but we deliberately ignore them in Phase 9.
            if is_cades_signature_name(&name) {
                signatures.push((name, buf));
            }
            continue;
        }
        // Top-level (or sub-folder) data entry.
        data_files.push((name, buf));
    }
    Ok((mime_type, signatures, data_files, names))
}

/// Match both ASiC-S (`META-INF/signature.p7s`) and ASiC-E
/// (`META-INF/signatures.p7s`, optionally numbered) conventions.
fn is_cades_signature_name(n: &str) -> bool {
    let base = n.strip_prefix("META-INF/").unwrap_or(n);
    if !base.ends_with(".p7s") {
        return false;
    }
    // Accept `signature.p7s`, `signatures.p7s`, `signatures001.p7s`, etc.
    let stem = &base[..base.len() - ".p7s".len()];
    matches!(stem, "signature" | "signatures")
        || (stem.starts_with("signatures") && stem[10..].chars().all(|c| c.is_ascii_digit()))
        || (stem.starts_with("signature") && stem[9..].chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_name_matches_common_conventions() {
        assert!(is_cades_signature_name("META-INF/signature.p7s"));
        assert!(is_cades_signature_name("META-INF/signatures.p7s"));
        assert!(is_cades_signature_name("META-INF/signatures001.p7s"));
        assert!(is_cades_signature_name("META-INF/signature42.p7s"));
        assert!(!is_cades_signature_name("META-INF/ASiCManifest.xml"));
        assert!(!is_cades_signature_name("META-INF/signatures.xml"));
        assert!(!is_cades_signature_name("META-INF/other.p7s"));
    }
}
