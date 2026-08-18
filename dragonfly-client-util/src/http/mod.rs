/*
 *     Copyright 2024 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use dragonfly_api::common::v2::Range;
use dragonfly_client_core::{
    error::{BackendError, ErrorType, OrErr},
    Error, Result,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_RANGE};
use reqwest::StatusCode;
use std::collections::HashMap;

pub mod basic_auth;
pub mod query_params;

/// Converts a headermap to a hashmap.
pub fn headermap_to_hashmap(header: &HeaderMap<HeaderValue>) -> HashMap<String, String> {
    let mut hashmap: HashMap<String, String> = HashMap::with_capacity(header.len());
    for (k, v) in header {
        if let Ok(v) = v.to_str() {
            hashmap.insert(k.to_string(), v.to_string());
        }
    }

    hashmap
}

/// Converts a hashmap to a headermap.
pub fn hashmap_to_headermap(header: &HashMap<String, String>) -> Result<HeaderMap<HeaderValue>> {
    let mut headermap = HeaderMap::with_capacity(header.len());
    for (k, v) in header {
        let name = HeaderName::from_bytes(k.as_bytes()).or_err(ErrorType::ParseError)?;
        let value = HeaderValue::from_bytes(v.as_bytes()).or_err(ErrorType::ParseError)?;
        headermap.insert(name, value);
    }

    Ok(headermap)
}

/// Converts a vector of header string to a hashmap.
pub fn header_vec_to_hashmap(raw_header: Vec<String>) -> Result<HashMap<String, String>> {
    let mut header = HashMap::with_capacity(raw_header.len());
    for h in raw_header {
        if let Some((k, v)) = h.split_once(':') {
            header.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    Ok(header)
}

/// Converts a vector of header string to a reqwest headermap.
pub fn header_vec_to_headermap(raw_header: Vec<String>) -> Result<HeaderMap> {
    hashmap_to_headermap(&header_vec_to_hashmap(raw_header)?)
}

/// Gets the range from http header.
pub fn get_range(header: &HeaderMap, content_length: u64) -> Result<Option<Range>> {
    match header.get(reqwest::header::RANGE) {
        Some(range) => {
            let range = range.to_str().or_err(ErrorType::ParseError)?;
            Ok(Some(parse_range_header(range, content_length)?))
        }
        None => Ok(None),
    }
}

/// Parses a Range header string as per RFC 7233,
/// supported Range Header: "Range": "bytes=100-200", "Range": "bytes=-50",
/// "Range": "bytes=150-", "Range": "bytes=0-0,-1".
pub fn parse_range_header(range_header_value: &str, content_length: u64) -> Result<Range> {
    let parsed_ranges =
        http_range_header::parse_range_header(range_header_value).or_err(ErrorType::ParseError)?;
    let valid_ranges = parsed_ranges
        .validate(content_length)
        .or_err(ErrorType::ParseError)?;

    // Not support multiple ranges.
    let valid_range = valid_ranges
        .first()
        .ok_or_else(|| Error::EmptyHTTPRangeError)?;

    let start = valid_range.start().to_owned();
    let length = valid_range.end() - start + 1;
    Ok(Range { start, length })
}

/// Validates that a ranged response satisfies the requested range, since the server may
/// ignore the Range header or transfer a range different from the requested one, which is
/// described by the Content-Range header, refer to RFC 9110 Section 15.3.7.
pub fn validate_ranged_response(
    range: Option<Range>,
    status_code: StatusCode,
    response_header: &HeaderMap,
) -> Result<()> {
    let Some(range) = range else {
        return Ok(());
    };

    if !status_code.is_success() {
        return Ok(());
    }

    let err = |message: String| {
        Error::BackendError(Box::new(BackendError {
            message,
            status_code: Some(status_code),
            header: Some(response_header.clone()),
        }))
    };

    let expected_end = range.start + range.length - 1;
    if status_code != StatusCode::PARTIAL_CONTENT {
        if range.start == 0 {
            return Ok(());
        }

        return Err(err(format!(
            "expected 206 Partial Content for range bytes={}-{}, got {}",
            range.start, expected_end, status_code
        )));
    }

    let content_range = response_header
        .get(CONTENT_RANGE)
        .and_then(|content_range| content_range.to_str().ok())
        .ok_or_else(|| {
            err(format!(
                "missing Content-Range for range bytes={}-{}",
                range.start, expected_end
            ))
        })?;

    // The Content-Range is formatted as "bytes <start>-<end>/<total>".
    let (actual_start, actual_end) = content_range
        .strip_prefix("bytes ")
        .and_then(|content_range| content_range.split_once('/'))
        .and_then(|(bytes_range, _)| bytes_range.split_once('-'))
        .and_then(|(start, end)| Some((start.parse::<u64>().ok()?, end.parse::<u64>().ok()?)))
        .ok_or_else(|| err(format!("invalid Content-Range {content_range}")))?;

    if actual_start != range.start || actual_end != expected_end {
        return Err(err(format!(
            "Content-Range {} mismatches requested range bytes={}-{}",
            content_range, range.start, expected_end
        )));
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// SigV4 signature-bound range detection and grid-alignment helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `alg` is one of the AWS SigV4 algorithm identifiers we
/// recognize: `AWS4-HMAC-SHA256` or `AWS4-ECDSA-P256-SHA256`. Comparison is
/// case-insensitive.
pub fn is_aws_v4_algorithm(alg: &str) -> bool {
    let alg = alg.trim();
    alg.eq_ignore_ascii_case("AWS4-HMAC-SHA256")
        || alg.eq_ignore_ascii_case("AWS4-ECDSA-P256-SHA256")
}

/// Returns `true` if the semicolon-separated signed-headers list contains
/// `"range"`. Comparison is case-insensitive.
pub fn signed_headers_contain_range(signed_headers: &str) -> bool {
    signed_headers
        .split(';')
        .any(|h| h.trim().eq_ignore_ascii_case("range"))
}

/// Case-insensitive `strip_prefix` without allocating.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Returns `true` if the **value** of an `Authorization` header indicates that
/// the `Range` header is covered by an AWS SigV4 signature.
///
/// Expected format:
/// ```text
/// AWS4-HMAC-SHA256 Credential=AKID/date/region/s3/aws4_request,
///                 SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,
///                 Signature=<hex>
/// ```
pub fn is_range_signed_in_authorization_value(auth_value: &str) -> bool {
    let (alg, rest) = match auth_value.split_once(' ') {
        Some(parts) => parts,
        None => return false,
    };
    if !is_aws_v4_algorithm(alg) {
        return false;
    }

    let mut has_credential = false;
    let mut has_signature = false;
    let mut range_signed = false;

    for part in rest.split(',') {
        let part = part.trim();
        if let Some(val) = strip_prefix_ci(part, "Credential=") {
            has_credential = !val.trim().is_empty();
        } else if let Some(val) = strip_prefix_ci(part, "SignedHeaders=") {
            range_signed = signed_headers_contain_range(val.trim());
        } else if let Some(val) = strip_prefix_ci(part, "Signature=") {
            has_signature = !val.trim().is_empty();
        }
    }

    has_credential && has_signature && range_signed
}

/// Returns `true` if the request headers contain an `Authorization` header
/// that SigV4-signs the `Range` header.
pub fn is_range_signed_in_authorization(header: &HeaderMap) -> bool {
    header
        .get(reqwest::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_range_signed_in_authorization_value)
}

/// Minimal percent-decoder used to handle `%3B` → `;` and similar in
/// `X-Amz-SignedHeaders` presigned-URL query values.
fn percent_decode_simple(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                result.push(char::from(h << 4 | l));
                i += 3;
                continue;
            }
        }
        result.push(char::from(bytes[i]));
        i += 1;
    }
    result
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Returns `true` if the query string of a presigned URL indicates that the
/// `Range` header is covered by an AWS SigV4 signature.
///
/// Looks for:
/// - `X-Amz-Algorithm` matching a supported SigV4 algorithm
/// - `X-Amz-Signature` being non-empty
/// - `X-Amz-SignedHeaders` containing `"range"` (after percent-decoding)
pub fn is_range_signed_in_presigned_url(query: &str) -> bool {
    let mut algorithm: Option<String> = None;
    let mut has_signature = false;
    let mut range_in_signed_headers = false;

    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            if key.eq_ignore_ascii_case("X-Amz-Algorithm") {
                algorithm = Some(percent_decode_simple(value));
            } else if key.eq_ignore_ascii_case("X-Amz-Signature") {
                has_signature = !value.is_empty();
            } else if key.eq_ignore_ascii_case("X-Amz-SignedHeaders") {
                let decoded = percent_decode_simple(value);
                range_in_signed_headers = signed_headers_contain_range(&decoded);
            }
        }
    }

    let valid_alg = algorithm.as_deref().is_some_and(is_aws_v4_algorithm);
    valid_alg && has_signature && range_in_signed_headers
}

/// Parses a `bytes=X-Y` Range header value where **both endpoints are
/// explicit**.  Returns `(start, end)` on success.  Returns `None` for:
/// - multi-range (`bytes=0-9,20-29`)
/// - open-ended (`bytes=X-`)
/// - suffix (`bytes=-N`)
/// - start > end
///
/// The range unit comparison is case-insensitive per RFC 7233.
pub fn is_single_byte_range(range: &str) -> Option<(u64, u64)> {
    let trimmed = range.trim();
    // Case-insensitive "bytes=" prefix (RFC 7233 §2.1: range units are case-insensitive).
    let rest = if trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("bytes=") {
        &trimmed[6..]
    } else {
        return None;
    };
    // Reject multi-range.
    if rest.contains(',') {
        return None;
    }
    let (start_str, end_str) = rest.split_once('-')?;
    let start_str = start_str.trim();
    let end_str = end_str.trim();
    // Both must be non-empty (open-ended or suffix forms are rejected).
    if start_str.is_empty() || end_str.is_empty() {
        return None;
    }
    let start = start_str.parse::<u64>().ok()?;
    let end = end_str.parse::<u64>().ok()?;
    if start > end {
        return None;
    }
    Some((start, end))
}

/// Returns `(start, end)` if the request has a SigV4-signed single explicit
/// `bytes=X-Y` `Range` header. Returns `None` otherwise.
///
/// **Does NOT check `If-Range`** — that policy condition belongs to the
/// fast-path gate ([`fast_path_metadata`]), not in the detection helper, so
/// callers such as `need_prefetch` can correctly suppress whole-object
/// prefetch even when `If-Range` is present.
///
/// `url_query` is the raw query string from the request URL; pass `None`
/// when not available.
///
/// Conditions checked (fast-path gate conditions 2, 3):
/// - `Range` is present and a single explicit `bytes=X-Y` (condition 3)
/// - `Authorization` header signed with AWS SigV4 and `range` in
///   `SignedHeaders`, OR presigned URL with `X-Amz-Algorithm`,
///   `X-Amz-Signature`, and `range` in `X-Amz-SignedHeaders` (condition 2)
pub fn signature_bound_range(header: &HeaderMap, url_query: Option<&str>) -> Option<(u64, u64)> {
    // Range must be present.
    let range_value = header
        .get(reqwest::header::RANGE)
        .and_then(|v| v.to_str().ok())?;
    // Condition 3: must be single explicit bytes=X-Y.
    let (start, end) = is_single_byte_range(range_value)?;
    // Condition 2: must be signature-bound.
    let is_signed = is_range_signed_in_authorization(header)
        || url_query.is_some_and(is_range_signed_in_presigned_url);
    if !is_signed {
        return None;
    }
    Some((start, end))
}

/// Same as [`signature_bound_range`] but operates on a
/// `HashMap<String, String>` (as stored in `Download::request_header`).
///
/// **Does NOT check `If-Range`** — see [`signature_bound_range`].
///
/// `url_query` is the raw query string extracted from the download URL.
pub fn signature_bound_range_from_hashmap(
    header: &HashMap<String, String>,
    url_query: Option<&str>,
) -> Option<(u64, u64)> {
    // Range must be present.
    let range_value = header
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("range"))
        .map(|(_, v)| v.as_str())?;
    // Condition 3: must be single explicit bytes=X-Y.
    let (start, end) = is_single_byte_range(range_value)?;
    // Condition 2: signature-bound via Authorization or presigned URL.
    let is_signed_via_auth = header
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .is_some_and(is_range_signed_in_authorization_value);
    let is_signed = is_signed_via_auth || url_query.is_some_and(is_range_signed_in_presigned_url);
    if !is_signed {
        return None;
    }
    Some((start, end))
}

/// Parses a `Content-Range` header value of the form `bytes <start>-<end>/<total>`.
/// Returns `(start, end, total)` on success, or `None` if the value does not
/// match that format (wildcards such as `bytes */<total>` are rejected).
pub fn parse_content_range_header(content_range: &str) -> Option<(u64, u64, u64)> {
    let rest = content_range.trim().strip_prefix("bytes ")?;
    let (range_part, total_str) = rest.split_once('/')?;
    let (start_str, end_str) = range_part.split_once('-')?;
    // Reject wildcard range ("bytes */N").
    let start_str = start_str.trim();
    let end_str = end_str.trim();
    if start_str == "*" || end_str.is_empty() {
        return None;
    }
    let start = start_str.parse::<u64>().ok()?;
    let end = end_str.parse::<u64>().ok()?;
    let total = total_str.trim().parse::<u64>().ok()?;
    Some((start, end, total))
}

/// Gets the `Content-Range` from a `HeaderMap`, parsed as `(start, end, total)`.
pub fn get_content_range(header: &HeaderMap) -> Option<(u64, u64, u64)> {
    header
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range_header)
}

/// Gets the `Content-Range` from a `HashMap<String, String>`, parsed as
/// `(start, end, total)`.
pub fn get_content_range_from_hashmap(header: &HashMap<String, String>) -> Option<(u64, u64, u64)> {
    header
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-range"))
        .and_then(|(_, v)| parse_content_range_header(v))
}

/// Returns `true` if `(start, end)` aligns exactly with one piece in the
/// piece grid defined by `piece_length` and `content_length`.
///
/// All of the following must hold:
/// - `end < content_length`
/// - `start % piece_length == 0`
/// - Either `end == start + piece_length - 1` (full piece), or
///   `end == content_length - 1` with `start` being the start of the last
///   piece (`start == ((content_length - 1) / piece_length) * piece_length`)
///
/// Returns `false` for `piece_length == 0` or `content_length == 0`.
pub fn is_aligned_single_piece(
    start: u64,
    end: u64,
    piece_length: u64,
    content_length: u64,
) -> bool {
    if piece_length == 0 || content_length == 0 {
        return false;
    }
    if end >= content_length {
        return false;
    }
    if start % piece_length != 0 {
        return false;
    }
    // Full piece?
    if end == start.saturating_add(piece_length).saturating_sub(1) {
        return true;
    }
    // Final (possibly short) piece?
    let last_piece_start = ((content_length - 1) / piece_length) * piece_length;
    end == content_length - 1 && start == last_piece_start
}

/// Returns the `Range` to pass to the backend for a piece download.
///
/// When the client's signed range exactly covers this piece's window
/// (`signed_start == piece_offset` and `signed_length == piece_length`),
/// returns `None` so that `make_request_headers` leaves the `Range` header
/// verbatim (preserving the SigV4 signature).
///
/// On any mismatch, falls back to `Some(Range { start: piece_offset, length:
/// piece_length })`.  The alignment gate in the fast-path conditions should
/// make mismatches unreachable; treat one as a bug and log a warning.
pub fn source_request_range(
    signed_start: u64,
    signed_length: u64,
    piece_offset: u64,
    piece_length: u64,
) -> Option<Range> {
    if signed_start == piece_offset && signed_length == piece_length {
        None
    } else {
        Some(Range {
            start: piece_offset,
            length: piece_length,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Signed-range fast-path gate
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum piece count used when computing automatic piece length.
/// Mirrors `piece.rs::MAX_PIECE_COUNT`.
const MAX_PIECE_COUNT: u64 = 500;

/// Minimum piece length (4 MiB). Mirrors `dragonfly_client_config::MIN_PIECE_LENGTH`.
/// Inlined to avoid a dependency on `dragonfly-client-config` from this crate.
const MIN_PIECE_LENGTH_FAST_PATH: u64 = 4 * 1024 * 1024;

/// Maximum piece length (64 MiB), mirroring `piece::MAX_PIECE_LENGTH`.
const MAX_PIECE_LENGTH_FAST_PATH: u64 = 64 * 1024 * 1024;

/// Resolved metadata returned by [`fast_path_metadata`] when all fast-path
/// conditions are satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastPathMetadata {
    /// Start of the signed `Range` (source-object coordinates).
    pub signed_start: u64,
    /// End of the signed `Range` (source-object coordinates, inclusive).
    pub signed_end: u64,
    /// Asserted total object size from `X-Dragonfly-Content-Length`.
    pub content_length: u64,
    /// Resolved piece length.
    pub piece_length: u64,
}

/// Evaluates all signed-range fast-path conditions against a `Download`
/// request header map and returns the resolved metadata when every condition
/// holds.
///
/// The caller is responsible for stripping `X-Dragonfly-Content-Length` from
/// the header map before forwarding it to the origin.
///
/// Conditions checked here:
/// - (2, 3) `Range` is a SigV4-signed single explicit `bytes=X-Y`
/// - (4)    `X-Dragonfly-Content-Length` is present and `> 0`
/// - (5)    Piece length resolves from `piece_length_hint` or from the
///          automatic strategy
/// - (6, 7, 8) `(start, end)` aligns exactly with one piece
/// - (9)   **No `If-Range` header** — checked here rather than in the
///         detection helpers so that `need_prefetch` continues to recognise
///         signed ranges even when `If-Range` is present
pub fn fast_path_metadata(
    request_header: &HashMap<String, String>,
    url: &str,
    piece_length_hint: Option<u64>,
) -> Option<FastPathMetadata> {
    // Condition 9: reject If-Range here (not in the detection helpers).
    if request_header
        .keys()
        .any(|k| k.eq_ignore_ascii_case("if-range"))
    {
        return None;
    }

    // Conditions 2, 3 (without If-Range filter — that is checked above).
    let url_query = url.find('?').map(|i| &url[i + 1..]);
    let (sr_start, sr_end) = signature_bound_range_from_hashmap(request_header, url_query)?;

    // Condition 4.
    let content_length = request_header
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-dragonfly-content-length"))
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .filter(|&n| n > 0)?;

    // Condition 5: resolve piece length.
    let piece_length = match piece_length_hint {
        Some(pl) if pl >= MIN_PIECE_LENGTH_FAST_PATH => pl,
        _ => {
            let raw = (content_length as f64 / MAX_PIECE_COUNT as f64) as u64;
            let actual = raw.next_power_of_two();
            match (
                actual > MIN_PIECE_LENGTH_FAST_PATH,
                actual < MAX_PIECE_LENGTH_FAST_PATH,
            ) {
                (true, true) => actual,
                (_, false) => MAX_PIECE_LENGTH_FAST_PATH,
                (false, _) => MIN_PIECE_LENGTH_FAST_PATH,
            }
        }
    };

    // Conditions 6, 7, 8.
    if !is_aligned_single_piece(sr_start, sr_end, piece_length, content_length) {
        return None;
    }

    Some(FastPathMetadata {
        signed_start: sr_start,
        signed_end: sr_end,
        content_length,
        piece_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_headermap_to_hashmap() {
        let mut header = HeaderMap::new();
        header.insert("Content-Type", HeaderValue::from_static("application/json"));
        header.insert("Authorization", HeaderValue::from_static("Bearer token"));

        let hashmap = headermap_to_hashmap(&header);
        assert_eq!(hashmap.get("content-type").unwrap(), "application/json");
        assert_eq!(hashmap.get("authorization").unwrap(), "Bearer token");
        assert_eq!(hashmap.get("foo"), None);
    }

    #[test]
    fn test_hashmap_to_headermap() {
        let mut hashmap = HashMap::new();
        hashmap.insert("Content-Type".to_string(), "application/json".to_string());
        hashmap.insert("Authorization".to_string(), "Bearer token".to_string());

        let header = hashmap_to_headermap(&hashmap).unwrap();
        assert_eq!(header.get("Content-Type").unwrap(), "application/json");
        assert_eq!(header.get("Authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn test_header_vec_to_hashmap() {
        let raw_header = vec![
            "Content-Type: application/json".to_string(),
            "Authorization: Bearer token".to_string(),
        ];

        let hashmap = header_vec_to_hashmap(raw_header).unwrap();
        assert_eq!(hashmap.get("Content-Type").unwrap(), "application/json");
        assert_eq!(hashmap.get("Authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn test_header_vec_to_headermap() {
        let raw_header = vec![
            "Content-Type: application/json".to_string(),
            "Authorization: Bearer token".to_string(),
        ];

        let header = header_vec_to_headermap(raw_header).unwrap();
        assert_eq!(header.get("Content-Type").unwrap(), "application/json");
        assert_eq!(header.get("Authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn test_get_range() {
        let mut header = HeaderMap::new();
        header.insert(
            reqwest::header::RANGE,
            HeaderValue::from_static("bytes=0-100"),
        );

        let range = get_range(&header, 200).unwrap().unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.length, 101);
    }

    #[test]
    fn test_parse_range_header() {
        let range = parse_range_header("bytes=0-100", 200).unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.length, 101);
    }

    #[test]
    fn test_validate_ranged_response() {
        let range = Some(Range {
            start: 10,
            length: 20,
        });

        assert!(validate_ranged_response(None, StatusCode::OK, &HeaderMap::new()).is_ok());
        assert!(validate_ranged_response(range, StatusCode::NOT_FOUND, &HeaderMap::new()).is_ok());
        assert!(validate_ranged_response(
            Some(Range {
                start: 0,
                length: 20
            }),
            StatusCode::OK,
            &HeaderMap::new()
        )
        .is_ok());
        assert!(validate_ranged_response(range, StatusCode::OK, &HeaderMap::new()).is_err());

        let mut header = HeaderMap::new();
        header.insert(CONTENT_RANGE, HeaderValue::from_static("bytes 10-29/100"));
        assert!(validate_ranged_response(range, StatusCode::PARTIAL_CONTENT, &header).is_ok());
        assert!(
            validate_ranged_response(range, StatusCode::PARTIAL_CONTENT, &HeaderMap::new())
                .is_err()
        );

        for content_range in ["bytes */100", "bytes 10-/100", "10-29/100", "bytes 10-29"] {
            let mut header = HeaderMap::new();
            header.insert(CONTENT_RANGE, HeaderValue::from_str(content_range).unwrap());
            assert!(validate_ranged_response(range, StatusCode::PARTIAL_CONTENT, &header).is_err());
        }

        for content_range in ["bytes 0-29/100", "bytes 10-30/100", "bytes 0-99/100"] {
            let mut header = HeaderMap::new();
            header.insert(CONTENT_RANGE, HeaderValue::from_str(content_range).unwrap());
            assert!(validate_ranged_response(range, StatusCode::PARTIAL_CONTENT, &header).is_err());
        }
    }

    // ── SigV4 detection ──────────────────────────────────────────────────────

    #[test]
    fn test_is_aws_v4_algorithm() {
        assert!(is_aws_v4_algorithm("AWS4-HMAC-SHA256"));
        assert!(is_aws_v4_algorithm("aws4-hmac-sha256"));
        assert!(is_aws_v4_algorithm("AWS4-ECDSA-P256-SHA256"));
        assert!(is_aws_v4_algorithm("  AWS4-HMAC-SHA256  "));
        assert!(!is_aws_v4_algorithm("AWS4-HMAC-SHA512"));
        assert!(!is_aws_v4_algorithm("HMAC-SHA256"));
        assert!(!is_aws_v4_algorithm(""));
    }

    #[test]
    fn test_signed_headers_contain_range() {
        assert!(signed_headers_contain_range("host;range;x-amz-date"));
        assert!(signed_headers_contain_range("range"));
        assert!(signed_headers_contain_range("Range"));
        assert!(signed_headers_contain_range("host;RANGE;content-md5"));
        assert!(!signed_headers_contain_range("host;content-md5"));
        assert!(!signed_headers_contain_range(""));
        assert!(!signed_headers_contain_range("content-range"));
    }

    #[test]
    fn test_is_range_signed_in_authorization_value() {
        // Valid SigV4 with range in SignedHeaders.
        let auth = "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;range;x-amz-date, Signature=abc123";
        assert!(is_range_signed_in_authorization_value(auth));

        // Valid, lowercase algorithm.
        let auth = "aws4-hmac-sha256 Credential=AKID/20240101/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;range;x-amz-date, Signature=abc123";
        assert!(is_range_signed_in_authorization_value(auth));

        // ECDSA variant.
        let auth = "AWS4-ECDSA-P256-SHA256 Credential=AKID/date/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;range, Signature=abc";
        assert!(is_range_signed_in_authorization_value(auth));

        // Range NOT in SignedHeaders.
        let auth = "AWS4-HMAC-SHA256 Credential=AKID/date/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;x-amz-date, Signature=abc123";
        assert!(!is_range_signed_in_authorization_value(auth));

        // Empty Credential.
        let auth = "AWS4-HMAC-SHA256 Credential=, \
                    SignedHeaders=host;range;x-amz-date, Signature=abc123";
        assert!(!is_range_signed_in_authorization_value(auth));

        // Empty Signature.
        let auth = "AWS4-HMAC-SHA256 Credential=AKID/date/us/s3/aws4_request, \
                    SignedHeaders=host;range, Signature=";
        assert!(!is_range_signed_in_authorization_value(auth));

        // Non-AWS algorithm.
        let auth = "Bearer sometoken";
        assert!(!is_range_signed_in_authorization_value(auth));

        // No space → no algorithm.
        assert!(!is_range_signed_in_authorization_value("AWS4-HMAC-SHA256"));
    }

    #[test]
    fn test_is_range_signed_in_authorization_headermap() {
        let mut header = HeaderMap::new();
        let auth = "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;range;x-amz-date, Signature=abc123";
        header.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(auth).unwrap(),
        );
        assert!(is_range_signed_in_authorization(&header));

        // Without Authorization header.
        assert!(!is_range_signed_in_authorization(&HeaderMap::new()));

        // Without range in SignedHeaders.
        let mut header2 = HeaderMap::new();
        let auth2 = "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, \
                     SignedHeaders=host;x-amz-date, Signature=abc123";
        header2.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(auth2).unwrap(),
        );
        assert!(!is_range_signed_in_authorization(&header2));
    }

    #[test]
    fn test_is_range_signed_in_presigned_url() {
        // Valid presigned URL query.
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKID%2F20240101%2Fus-east-1%2Fs3%2Faws4_request\
                 &X-Amz-Date=20240101T000000Z\
                 &X-Amz-Expires=3600\
                 &X-Amz-SignedHeaders=host%3Brange\
                 &X-Amz-Signature=abc123";
        assert!(is_range_signed_in_presigned_url(q));

        // Lowercase algorithm.
        let q2 = "X-Amz-Algorithm=aws4-hmac-sha256\
                  &X-Amz-SignedHeaders=host%3Brange\
                  &X-Amz-Signature=abc";
        assert!(is_range_signed_in_presigned_url(q2));

        // Range not in signed headers.
        let q3 = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                  &X-Amz-SignedHeaders=host\
                  &X-Amz-Signature=abc";
        assert!(!is_range_signed_in_presigned_url(q3));

        // Empty signature.
        let q4 = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                  &X-Amz-SignedHeaders=host%3Brange\
                  &X-Amz-Signature=";
        assert!(!is_range_signed_in_presigned_url(q4));

        // Non-AWS algorithm.
        let q5 = "X-Amz-Algorithm=AWS4-HMAC-SHA512\
                  &X-Amz-SignedHeaders=host%3Brange\
                  &X-Amz-Signature=abc";
        assert!(!is_range_signed_in_presigned_url(q5));

        // Missing algorithm.
        let q6 = "X-Amz-SignedHeaders=host%3Brange&X-Amz-Signature=abc";
        assert!(!is_range_signed_in_presigned_url(q6));
    }

    #[test]
    fn test_is_single_byte_range() {
        assert_eq!(is_single_byte_range("bytes=0-999"), Some((0, 999)));
        assert_eq!(
            is_single_byte_range("bytes=4194304-8388607"),
            Some((4194304, 8388607))
        );
        assert_eq!(is_single_byte_range("bytes=0-0"), Some((0, 0)));
        // Case-insensitive unit (RFC 7233 §2.1).
        assert_eq!(is_single_byte_range("Bytes=0-999"), Some((0, 999)));
        assert_eq!(is_single_byte_range("BYTES=0-999"), Some((0, 999)));

        // Open-ended.
        assert_eq!(is_single_byte_range("bytes=100-"), None);
        // Suffix.
        assert_eq!(is_single_byte_range("bytes=-100"), None);
        // Multi-range.
        assert_eq!(is_single_byte_range("bytes=0-9,20-29"), None);
        // start > end.
        assert_eq!(is_single_byte_range("bytes=100-50"), None);
        // Not bytes.
        assert_eq!(is_single_byte_range("items=0-9"), None);
        // Empty.
        assert_eq!(is_single_byte_range(""), None);
    }

    #[test]
    fn test_signature_bound_range() {
        let auth = "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;range;x-amz-date, Signature=abc123";

        // Happy path: Authorization-based.
        let mut hdr = HeaderMap::new();
        hdr.insert(reqwest::header::AUTHORIZATION, auth.parse().unwrap());
        hdr.insert(reqwest::header::RANGE, "bytes=0-4194303".parse().unwrap());
        assert_eq!(signature_bound_range(&hdr, None), Some((0, 4194303)));

        // If-Range present → signature_bound_range still returns Some
        // (If-Range is NOT checked here; it is a policy gate in fast_path_metadata).
        let mut hdr2 = hdr.clone();
        hdr2.insert("if-range", "\"etag\"".parse().unwrap());
        assert_eq!(signature_bound_range(&hdr2, None), Some((0, 4194303)));

        // Range not signature-bound.
        let mut hdr3 = HeaderMap::new();
        hdr3.insert(reqwest::header::RANGE, "bytes=0-99".parse().unwrap());
        assert_eq!(signature_bound_range(&hdr3, None), None);

        // Open-ended range → None (is_single_byte_range rejects it).
        let mut hdr4 = HeaderMap::new();
        hdr4.insert(reqwest::header::AUTHORIZATION, auth.parse().unwrap());
        hdr4.insert(reqwest::header::RANGE, "bytes=100-".parse().unwrap());
        assert_eq!(signature_bound_range(&hdr4, None), None);

        // No Range header.
        let mut hdr5 = HeaderMap::new();
        hdr5.insert(reqwest::header::AUTHORIZATION, auth.parse().unwrap());
        assert_eq!(signature_bound_range(&hdr5, None), None);

        // Presigned URL path.
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-SignedHeaders=host%3Brange\
                 &X-Amz-Signature=abc";
        let mut hdr6 = HeaderMap::new();
        hdr6.insert(reqwest::header::RANGE, "bytes=0-4194303".parse().unwrap());
        assert_eq!(signature_bound_range(&hdr6, Some(q)), Some((0, 4194303)));
    }

    // ── fast_path_metadata tests ─────────────────────────────────────────────

    fn make_auth() -> &'static str {
        "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, \
         SignedHeaders=host;range;x-amz-date, Signature=abc123"
    }

    fn signed_hashmap(range: &str, content_length: u64) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("authorization".to_string(), make_auth().to_string());
        m.insert("range".to_string(), range.to_string());
        m.insert(
            "x-dragonfly-content-length".to_string(),
            content_length.to_string(),
        );
        m
    }

    #[test]
    fn test_fast_path_metadata_happy_path() {
        const PL: u64 = 4 * 1024 * 1024;
        const CL: u64 = 10 * PL;
        let hdr = signed_hashmap("bytes=0-4194303", CL);
        let fp = fast_path_metadata(&hdr, "https://s3.example.com/bucket/key", Some(PL)).unwrap();
        assert_eq!(fp.signed_start, 0);
        assert_eq!(fp.signed_end, PL - 1);
        assert_eq!(fp.content_length, CL);
        assert_eq!(fp.piece_length, PL);
    }

    #[test]
    fn test_fast_path_metadata_if_range_rejected() {
        const PL: u64 = 4 * 1024 * 1024;
        const CL: u64 = 10 * PL;
        let mut hdr = signed_hashmap("bytes=0-4194303", CL);
        // If-Range must block the fast path (condition 9).
        hdr.insert("If-Range".to_string(), "\"etag\"".to_string());
        assert!(fast_path_metadata(&hdr, "https://s3.example.com/bucket/key", Some(PL)).is_none());
    }

    #[test]
    fn test_fast_path_metadata_missing_content_length() {
        const PL: u64 = 4 * 1024 * 1024;
        let mut hdr = HashMap::new();
        hdr.insert("authorization".to_string(), make_auth().to_string());
        hdr.insert("range".to_string(), "bytes=0-4194303".to_string());
        // No X-Dragonfly-Content-Length → None.
        assert!(fast_path_metadata(&hdr, "https://s3.example.com/key", Some(PL)).is_none());
    }

    #[test]
    fn test_fast_path_metadata_zero_content_length_rejected() {
        const PL: u64 = 4 * 1024 * 1024;
        let mut hdr = HashMap::new();
        hdr.insert("authorization".to_string(), make_auth().to_string());
        hdr.insert("range".to_string(), "bytes=0-4194303".to_string());
        hdr.insert("x-dragonfly-content-length".to_string(), "0".to_string());
        assert!(fast_path_metadata(&hdr, "https://s3.example.com/key", Some(PL)).is_none());
    }

    #[test]
    fn test_fast_path_metadata_case_insensitive_header_keys() {
        // X-Dragonfly-Content-Length in mixed case must be found.
        const PL: u64 = 4 * 1024 * 1024;
        const CL: u64 = 10 * PL;
        let mut hdr = HashMap::new();
        hdr.insert("Authorization".to_string(), make_auth().to_string());
        hdr.insert("Range".to_string(), "bytes=0-4194303".to_string());
        hdr.insert("X-Dragonfly-Content-Length".to_string(), CL.to_string());
        let fp = fast_path_metadata(&hdr, "https://s3.example.com/bucket/key", Some(PL)).unwrap();
        assert_eq!(fp.content_length, CL);
    }

    #[test]
    fn test_fast_path_metadata_misaligned_rejected() {
        const PL: u64 = 4 * 1024 * 1024;
        const CL: u64 = 10 * PL;
        // Start not piece-aligned.
        let hdr = signed_hashmap("bytes=1-4194304", CL);
        assert!(fast_path_metadata(&hdr, "https://s3.example.com/key", Some(PL)).is_none());
    }

    // ── Alignment predicate ──────────────────────────────────────────────────

    #[test]
    fn test_is_aligned_single_piece() {
        const PL: u64 = 4 * 1024 * 1024; // 4 MiB
        const CL: u64 = 10 * PL; // 40 MiB

        // Full first piece.
        assert!(is_aligned_single_piece(0, PL - 1, PL, CL));
        // Full middle piece.
        assert!(is_aligned_single_piece(PL, 2 * PL - 1, PL, CL));
        // Last full piece (CL is multiple of PL).
        assert!(is_aligned_single_piece(9 * PL, 10 * PL - 1, PL, CL));

        // Final short piece.
        let cl2 = 10 * PL + 1234;
        assert!(is_aligned_single_piece(10 * PL, cl2 - 1, PL, cl2));

        // Off by one at end.
        assert!(!is_aligned_single_piece(0, PL, PL, CL)); // end == PL (one too far)
                                                          // Off by one at start.
        assert!(!is_aligned_single_piece(1, PL, PL, CL)); // start not piece-aligned
                                                          // Two-piece span.
        assert!(!is_aligned_single_piece(0, 2 * PL - 1, PL, CL));
        // Start not a multiple of piece_length.
        assert!(!is_aligned_single_piece(PL + 1, 2 * PL, PL, CL));
        // end >= content_length.
        assert!(!is_aligned_single_piece(0, CL, PL, CL));
        // Zero content_length.
        assert!(!is_aligned_single_piece(0, 0, PL, 0));
        // Zero piece_length.
        assert!(!is_aligned_single_piece(0, 0, 0, CL));
    }

    #[test]
    fn test_parse_content_range_header() {
        assert_eq!(
            parse_content_range_header("bytes 0-4194303/10485760"),
            Some((0, 4194303, 10485760))
        );
        assert_eq!(
            parse_content_range_header("bytes 4194304-8388607/10485760"),
            Some((4194304, 8388607, 10485760))
        );
        // Wildcard range → None.
        assert_eq!(parse_content_range_header("bytes */10485760"), None);
        // Missing bytes prefix → None.
        assert_eq!(parse_content_range_header("0-100/200"), None);
        // Missing total → None.
        assert_eq!(parse_content_range_header("bytes 0-100"), None);
    }

    #[test]
    fn test_source_request_range() {
        // Exact match → None (forward verbatim).
        assert_eq!(source_request_range(0, 4194304, 0, 4194304), None);
        assert_eq!(
            source_request_range(4194304, 4194304, 4194304, 4194304),
            None
        );

        // Mismatch → Some (rewrite).
        assert_eq!(
            source_request_range(0, 4194304, 4194304, 4194304),
            Some(Range {
                start: 4194304,
                length: 4194304
            })
        );
        assert_eq!(
            source_request_range(0, 1234, 0, 4194304),
            Some(Range {
                start: 0,
                length: 4194304
            })
        );
    }
}
