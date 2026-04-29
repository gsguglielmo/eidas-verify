//! Locate PAdES signature dictionaries in a PDF byte stream.

use eidas_core::{Error, Result};

/// Location of a single PAdES signature within a PDF.
#[derive(Debug, Clone)]
pub struct PdfSignatureLocation {
    /// The four integers from `/ByteRange [offset1 length1 offset2 length2]`.
    pub byte_range: [usize; 4],
    /// DER bytes of the CMS SignedData extracted from `/Contents <...>`.
    pub cms_der: Vec<u8>,
    /// Raw `/SubFilter` name (without the leading `/`), if present.
    pub sub_filter: Option<String>,
    /// Byte offset at which `/ByteRange` appears (for diagnostics).
    pub byte_range_offset: usize,
}

/// Scan `pdf` for signature dictionaries and extract every location.
pub fn find_signatures(pdf: &[u8]) -> Result<Vec<PdfSignatureLocation>> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(br_start) = find_subsequence(&pdf[cursor..], b"/ByteRange") {
        let abs_start = cursor + br_start;
        // Parse the four-integer array that follows.
        let after_key = abs_start + b"/ByteRange".len();
        let array_start = match find_byte(&pdf[after_key..], b'[') {
            Some(i) => after_key + i,
            None => break,
        };
        let array_end = match find_byte(&pdf[array_start..], b']') {
            Some(i) => array_start + i,
            None => break,
        };
        let array_bytes = &pdf[array_start + 1..array_end];
        let byte_range = parse_four_ints(array_bytes)?;

        // Sanity-check that the ranges are inside the document.
        let [a, b, c, d] = byte_range;
        if a.saturating_add(b) > pdf.len() || c.saturating_add(d) > pdf.len() {
            return Err(Error::Pdf(format!(
                "/ByteRange {byte_range:?} extends past file length {}",
                pdf.len()
            )));
        }

        // Find the `/Contents` hex blob. The gap between the two ByteRange
        // chunks — pdf[a+b .. c] — contains the placeholder; the `<hex>` is
        // inside it.
        let gap_start = a + b;
        let gap_end = c;
        if gap_end <= gap_start || gap_end > pdf.len() {
            return Err(Error::Pdf(format!(
                "/ByteRange {byte_range:?} has degenerate gap"
            )));
        }
        let gap = &pdf[gap_start..gap_end];
        let hex_lt = match find_byte(gap, b'<') {
            Some(i) => i,
            None => return Err(Error::Pdf("no '<' inside ByteRange gap".into())),
        };
        let hex_gt = match find_byte(&gap[hex_lt + 1..], b'>') {
            Some(i) => hex_lt + 1 + i,
            None => return Err(Error::Pdf("unterminated '<...>' in ByteRange gap".into())),
        };
        let hex_str = &gap[hex_lt + 1..hex_gt];
        let cms_der = decode_pdf_hex(hex_str)
            .ok_or_else(|| Error::Pdf("invalid hex in /Contents".into()))?;

        // Try to recover /SubFilter name, if we can find it in a small window
        // around the /ByteRange (typically earlier in the same dict).
        let window_start = abs_start.saturating_sub(512);
        let window = &pdf[window_start..abs_start];
        let sub_filter = find_sub_filter(window);

        out.push(PdfSignatureLocation {
            byte_range,
            cms_der,
            sub_filter,
            byte_range_offset: abs_start,
        });

        cursor = gap_end;
    }
    Ok(out)
}

/// Given a PDF and one of its signatures, return the two-slice concatenation
/// that was signed (i.e. the bytes the CMS SignedData's messageDigest
/// attribute commits to).
#[must_use]
pub fn signed_bytes<'a>(pdf: &'a [u8], loc: &PdfSignatureLocation) -> Vec<u8> {
    let [a, b, c, d] = loc.byte_range;
    let mut out = Vec::with_capacity(b + d);
    out.extend_from_slice(&pdf[a..a + b]);
    out.extend_from_slice(&pdf[c..c + d]);
    out
}

// -----------------------------------------------------------------------------
// Helpers

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn find_byte(haystack: &[u8], b: u8) -> Option<usize> {
    haystack.iter().position(|x| *x == b)
}

/// Parse `[ n n n n ]` (or similar) contents into four non-negative ints.
fn parse_four_ints(bytes: &[u8]) -> Result<[usize; 4]> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::Pdf(format!("/ByteRange is not UTF-8: {e}")))?;
    let mut vals = [0usize; 4];
    let mut n = 0;
    for tok in text.split_whitespace() {
        if n >= 4 {
            break;
        }
        let v: usize = tok
            .parse()
            .map_err(|e| Error::Pdf(format!("/ByteRange entry {tok:?} not a usize: {e}")))?;
        vals[n] = v;
        n += 1;
    }
    if n != 4 {
        return Err(Error::Pdf(format!(
            "/ByteRange needs 4 integers, got {n}"
        )));
    }
    Ok(vals)
}

/// Decode PDF hex (angle-bracket notation): pairs of hex chars, whitespace
/// ignored; trailing single digit is padded with '0'.
fn decode_pdf_hex(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut nibble: Option<u8> = None;
    for &b in bytes {
        if b.is_ascii_whitespace() {
            continue;
        }
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        match nibble {
            None => nibble = Some(v),
            Some(hi) => {
                out.push((hi << 4) | v);
                nibble = None;
            }
        }
    }
    if let Some(hi) = nibble {
        out.push(hi << 4);
    }
    // Contents placeholders are commonly padded with trailing zeroes; trim
    // trailing 0x00 bytes introduced by the padding so downstream ASN.1
    // parsers see exactly the DER-encoded CMS.
    while out.last() == Some(&0) {
        out.pop();
    }
    Some(out)
}

fn find_sub_filter(window: &[u8]) -> Option<String> {
    let idx = find_subsequence(window, b"/SubFilter")?;
    let rest = &window[idx + b"/SubFilter".len()..];
    // Skip whitespace, expect '/', take name chars up to whitespace/<</[/(
    let mut it = rest.iter().copied();
    let mut saw_slash = false;
    let mut name = Vec::new();
    for b in it.by_ref() {
        if !saw_slash {
            if b == b'/' {
                saw_slash = true;
                continue;
            }
            if b.is_ascii_whitespace() {
                continue;
            }
            // Something unexpected; bail.
            return None;
        }
        if b.is_ascii_whitespace()
            || b == b'/'
            || b == b'<'
            || b == b'>'
            || b == b'['
            || b == b'('
        {
            break;
        }
        name.push(b);
    }
    if name.is_empty() {
        return None;
    }
    String::from_utf8(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_basic() {
        assert_eq!(decode_pdf_hex(b"deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_pdf_hex(b"DE AD BE EF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn decode_hex_strips_trailing_zero_padding() {
        // A PDF signature placeholder often looks like "<abcd000000...>"; the
        // real DER ends before the padding.
        let d = decode_pdf_hex(b"abcd0000").unwrap();
        assert_eq!(d, vec![0xab, 0xcd]);
    }

    #[test]
    fn parse_four_ints_basic() {
        assert_eq!(parse_four_ints(b"0 100 200 300").unwrap(), [0, 100, 200, 300]);
        assert_eq!(parse_four_ints(b"  0  100  200  300  ").unwrap(), [0, 100, 200, 300]);
    }

    #[test]
    fn parse_four_ints_rejects_too_few() {
        assert!(parse_four_ints(b"1 2 3").is_err());
    }
}
