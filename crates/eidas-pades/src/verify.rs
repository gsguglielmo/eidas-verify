//! Dispatch each PAdES signature to the CAdES engine.

use eidas_cades::{verify_cades, CadesTrustMaterial};
use eidas_cms::CadesInput;
use eidas_core::{
    AlgorithmPolicy, ContainerInfo, DiagnosticMessage, Error, Result, ValidationTime,
    VerificationReport,
};

use crate::scan::{find_signatures, signed_bytes};

/// Caller-supplied PAdES input.
pub struct PadesInput<'a> {
    pub pdf: &'a [u8],
}

/// Accepted PAdES SubFilter values (ETSI EN 319 142-1 §5.2.4).
fn is_supported_sub_filter(name: &str) -> bool {
    matches!(
        name,
        "adbe.pkcs7.detached"
            | "ETSI.CAdES.detached"
            | "ETSI.RFC3161" // Document Time-stamp
    )
}

/// Verify every PAdES signature in the PDF.
pub fn verify_pades(
    input: &PadesInput<'_>,
    trust: &CadesTrustMaterial,
    policy: &AlgorithmPolicy,
    validation_time: ValidationTime,
) -> Result<VerificationReport> {
    let locations = find_signatures(input.pdf)?;
    if locations.is_empty() {
        return Err(Error::Pdf("no PAdES signatures found in PDF".into()));
    }

    let mut all_signatures = Vec::new();
    for (idx, loc) in locations.iter().enumerate() {
        // Sanity: warn on unexpected SubFilter names before handing off.
        let sub_filter_ok = loc
            .sub_filter
            .as_deref()
            .map_or(true, is_supported_sub_filter);
        if !sub_filter_ok {
            all_signatures.push(eidas_core::SignatureReport::failed(
                "PADES_UNSUPPORTED_SUB_FILTER",
                format!(
                    "signature {idx}: /SubFilter = {:?} not supported",
                    loc.sub_filter
                ),
            ));
            continue;
        }

        let signed_data = signed_bytes(input.pdf, loc);
        let report = match verify_cades(
            &CadesInput {
                cms: &loc.cms_der,
                detached_content: Some(&signed_data),
            },
            trust,
            policy,
            validation_time,
        ) {
            Ok(r) => r,
            Err(e) => {
                all_signatures.push(eidas_core::SignatureReport::failed(
                    "PADES_CMS_DISPATCH_FAILED",
                    format!("signature {idx}: {e}"),
                ));
                continue;
            }
        };

        for mut sr in report.signatures {
            // Annotate with PAdES-specific diagnostics.
            sr.diagnostics.push(DiagnosticMessage::info(
                "PADES_SIGNATURE_FOUND",
                format!(
                    "signature {idx} at offset {}; ByteRange [{} {} {} {}]; SubFilter={}",
                    loc.byte_range_offset,
                    loc.byte_range[0],
                    loc.byte_range[1],
                    loc.byte_range[2],
                    loc.byte_range[3],
                    loc.sub_filter.as_deref().unwrap_or("<unknown>"),
                ),
            ));
            all_signatures.push(sr);
        }
    }

    Ok(VerificationReport {
        signatures: all_signatures,
        container: Some(ContainerInfo::Pdf {
            revisions: locations.len(),
        }),
    })
}
