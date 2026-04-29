//! Parse the `qcStatements` X.509 extension (RFC 3739 + ETSI EN 319 412-5).
//!
//! We only decode the OID presence of each statement, not their semantic
//! parameters (`QcType`, `QcLimit`, etc.). That's enough for the TS 119 615
//! qualification decision, which cares about:
//! - whether the cert claims to be qualified (`QcCompliance`),
//! - whether the private key is on a QSCD (`QcSSCD`),
//! - the declared cert type (eSig / eSeal / web auth).

use const_oid::ObjectIdentifier;
use der::{Decode, Reader, SliceReader, Tag};
use eidas_core::{Error, Result};
use x509_cert::Certificate;

/// `qcStatements` extension identifier (RFC 3739 §3.2.6.1).
pub const ID_PE_QC_STATEMENTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");

/// `id-etsi-qcs-QcCompliance` (ETSI EN 319 412-5 §4.2.1).
pub const ID_ETSI_QCS_QC_COMPLIANCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.1");

/// `id-etsi-qcs-QcLimitValue` — monetary limit on use.
pub const ID_ETSI_QCS_QC_LIMIT_VALUE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.2");

/// `id-etsi-qcs-QcRetentionPeriod`.
pub const ID_ETSI_QCS_QC_RETENTION_PERIOD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.3");

/// `id-etsi-qcs-QcSSCD` — private key on QSCD.
pub const ID_ETSI_QCS_QC_SSCD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.4");

/// `id-etsi-qcs-QcPDS` — PKI disclosure statement URIs.
pub const ID_ETSI_QCS_QC_PDS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.5");

/// `id-etsi-qcs-QcType` — cert type (electronic signature / seal / web).
pub const ID_ETSI_QCS_QC_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.6");

/// `id-etsi-qct-esign` — electronic signature certificate.
pub const ID_ETSI_QCT_ESIGN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.1");

/// `id-etsi-qct-eseal` — electronic seal certificate.
pub const ID_ETSI_QCT_ESEAL: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.2");

/// `id-etsi-qct-web` — web authentication certificate.
pub const ID_ETSI_QCT_WEB: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.3");

/// Flags extracted from a cert's qcStatements extension.
#[derive(Debug, Clone, Default)]
pub struct QcStatements {
    pub qc_compliance: bool,
    pub qc_sscd: bool,
    pub qc_type_esign: bool,
    pub qc_type_eseal: bool,
    pub qc_type_web: bool,
    /// All statement OIDs seen (raw, for diagnostics).
    pub statements: Vec<ObjectIdentifier>,
}

impl QcStatements {
    /// True if the cert declares itself qualified (per `QcCompliance`).
    pub fn is_qualified_certificate(&self) -> bool {
        self.qc_compliance
    }
}

/// Convenience: does the certificate assert `QcSSCD`?
pub fn has_qc_sscd(cert: &Certificate) -> bool {
    parse_qc_statements(cert)
        .ok()
        .map(|s| s.qc_sscd)
        .unwrap_or(false)
}

/// Parse the `qcStatements` extension from `cert`. Returns default-empty
/// flags if the extension is absent.
pub fn parse_qc_statements(cert: &Certificate) -> Result<QcStatements> {
    let mut out = QcStatements::default();
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(out);
    };
    let ext = match exts.iter().find(|e| e.extn_id == ID_PE_QC_STATEMENTS) {
        Some(e) => e,
        None => return Ok(out),
    };

    // QCStatements ::= SEQUENCE OF QCStatement
    // QCStatement  ::= SEQUENCE { statementId OBJECT IDENTIFIER, statementInfo ANY DEFINED BY statementId OPTIONAL }
    let ext_bytes = ext.extn_value.as_bytes();
    let mut outer = SliceReader::new(ext_bytes)
        .map_err(|e| Error::Asn1(format!("qcStatements outer: {e}")))?;
    let outer_hdr = der::Header::decode(&mut outer)
        .map_err(|e| Error::Asn1(format!("qcStatements header: {e}")))?;
    if outer_hdr.tag != Tag::Sequence {
        return Err(Error::Asn1("qcStatements is not SEQUENCE".into()));
    }
    let body = outer
        .read_slice(outer_hdr.length)
        .map_err(|e| Error::Asn1(e.to_string()))?;
    let mut r = SliceReader::new(body)
        .map_err(|e| Error::Asn1(format!("qcStatements body: {e}")))?;

    while !r.is_finished() {
        let stmt_hdr = der::Header::decode(&mut r)
            .map_err(|e| Error::Asn1(format!("QCStatement header: {e}")))?;
        if stmt_hdr.tag != Tag::Sequence {
            // Unexpected; bail.
            break;
        }
        let stmt_bytes = r
            .read_slice(stmt_hdr.length)
            .map_err(|e| Error::Asn1(e.to_string()))?;
        let mut s = SliceReader::new(stmt_bytes)
            .map_err(|e| Error::Asn1(format!("QCStatement body: {e}")))?;
        let oid = ObjectIdentifier::decode(&mut s)
            .map_err(|e| Error::Asn1(format!("QCStatement OID: {e}")))?;
        out.statements.push(oid);

        // Set known flags.
        match oid {
            o if o == ID_ETSI_QCS_QC_COMPLIANCE => out.qc_compliance = true,
            o if o == ID_ETSI_QCS_QC_SSCD => out.qc_sscd = true,
            o if o == ID_ETSI_QCS_QC_TYPE => {
                // statementInfo = SEQUENCE OF OBJECT IDENTIFIER
                if !s.is_finished() {
                    let inner_hdr = der::Header::decode(&mut s)
                        .map_err(|e| Error::Asn1(format!("QcType inner: {e}")))?;
                    if inner_hdr.tag == Tag::Sequence {
                        let inner_body = s
                            .read_slice(inner_hdr.length)
                            .map_err(|e| Error::Asn1(e.to_string()))?;
                        let mut ir = SliceReader::new(inner_body)
                            .map_err(|e| Error::Asn1(e.to_string()))?;
                        while !ir.is_finished() {
                            if let Ok(t) = ObjectIdentifier::decode(&mut ir) {
                                match t {
                                    o if o == ID_ETSI_QCT_ESIGN => out.qc_type_esign = true,
                                    o if o == ID_ETSI_QCT_ESEAL => out.qc_type_eseal = true,
                                    o if o == ID_ETSI_QCT_WEB => out.qc_type_web = true,
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let q = QcStatements::default();
        assert!(!q.is_qualified_certificate());
        assert!(q.statements.is_empty());
    }
}
