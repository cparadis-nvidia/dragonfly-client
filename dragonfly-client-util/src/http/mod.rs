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

/// The X-Dragonfly-Content-Length header declares the total content length of
/// the task up front, so dfdaemon can skip the ranged stat request to the
/// origin. This also keeps requests whose Range header is covered by an
/// upstream request signature (e.g. AWS SigV4 with a signed Range header)
/// intact, because the stat request would rewrite the Range header and
/// invalidate the signature.
pub const DRAGONFLY_CONTENT_LENGTH_HEADER: &str = "X-Dragonfly-Content-Length";

/// The X-Dragonfly-Piece-Offset header declares that the client's ranged
/// requests are aligned to a chunk grid shifted by the given offset, e.g.
/// ranged reads of a SafeTensors payload that starts after the file header.
/// It is only a validation aid for compact range tasks: misaligned ranges are
/// rejected early so all clients produce identical, cache-shareable ranges.
/// It requires the X-Dragonfly-Content-Length header and a declared piece
/// length.
pub const DRAGONFLY_PIECE_OFFSET_HEADER: &str = "X-Dragonfly-Piece-Offset";

/// Gets the content length declared by the X-Dragonfly-Content-Length header.
pub fn get_task_content_length(header: &HeaderMap) -> Option<u64> {
    header
        .get(DRAGONFLY_CONTENT_LENGTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// A compact range task downloads and stores only the requested byte range of
/// the source object, instead of allocating storage for the whole object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactRange {
    /// The requested byte range in source object coordinates.
    pub range: Range,

    /// The total content length of the source object declared by the
    /// X-Dragonfly-Content-Length header.
    pub total_content_length: u64,
}

/// Returns the compact range task parameters when the client declares the
/// total content length with the X-Dragonfly-Content-Length header and sends
/// a Range header. Such a request is served as a compact range task: the task
/// id is derived from the range, the task stores only the requested bytes and
/// the source receives the client's original Range header unchanged, which
/// keeps ranges covered by an upstream request signature (e.g. AWS SigV4)
/// valid.
///
/// When the X-Dragonfly-Piece-Offset header is present, the range is
/// additionally validated to cover exactly one chunk of the grid that starts
/// at the offset with the declared piece length, so all clients chunk the
/// object identically and share the same compact range tasks.
pub fn get_compact_range(
    header: &HashMap<String, String>,
    piece_length: Option<u64>,
) -> Result<Option<CompactRange>> {
    let Some(total_content_length) = find_header(header, DRAGONFLY_CONTENT_LENGTH_HEADER)
        .and_then(|value| value.trim().parse::<u64>().ok())
    else {
        return Ok(None);
    };

    let Some(range_header) = find_header(header, reqwest::header::RANGE.as_str()) else {
        return Ok(None);
    };
    let range = parse_range_header(range_header, total_content_length)?;

    if let Some(piece_offset) = find_header(header, DRAGONFLY_PIECE_OFFSET_HEADER) {
        let piece_offset = piece_offset
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::ValidationError(format!("invalid piece offset {piece_offset}")))?;
        let Some(piece_length) = piece_length else {
            return Err(Error::ValidationError(
                "the X-Dragonfly-Piece-Offset header requires a declared piece length".to_string(),
            ));
        };

        let aligned_start = range.start >= piece_offset
            && piece_length > 0
            && (range.start - piece_offset) % piece_length == 0;
        // The trailing chunk is the only chunk shorter than the piece length.
        let aligned_length = range.length == piece_length
            || (range.start + range.length == total_content_length && range.length < piece_length);
        if !aligned_start || !aligned_length {
            return Err(Error::ValidationError(format!(
                "range [{}, {}) is not aligned to the chunk grid with offset {} and piece length {}",
                range.start,
                range.start + range.length,
                piece_offset,
                piece_length
            )));
        }
    }

    Ok(Some(CompactRange {
        range,
        total_content_length,
    }))
}

/// Finds a header value by case-insensitive name in a string header map.
fn find_header<'a>(header: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    header
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Returns whether a Range header value asks for exactly the bytes
/// [start, start + length), using the absolute single-range form
/// "bytes=<start>-<end>". Other range forms are never an exact match.
pub fn is_exact_range(range_header_value: &str, start: u64, length: u64) -> bool {
    if length == 0 {
        return false;
    }

    let Some((unit, spec)) = range_header_value.split_once('=') else {
        return false;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return false;
    }

    let Some((first, last)) = spec.trim().split_once('-') else {
        return false;
    };

    let Some(end) = start.checked_add(length - 1) else {
        return false;
    };

    first.parse::<u64>().ok() == Some(start) && last.parse::<u64>().ok() == Some(end)
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

    #[test]
    fn test_get_task_content_length() {
        let mut header = HeaderMap::new();
        assert_eq!(get_task_content_length(&header), None);

        header.insert(
            DRAGONFLY_CONTENT_LENGTH_HEADER,
            HeaderValue::from_static("4194304"),
        );
        assert_eq!(get_task_content_length(&header), Some(4194304));

        header.insert(
            DRAGONFLY_CONTENT_LENGTH_HEADER,
            HeaderValue::from_static("not-a-number"),
        );
        assert_eq!(get_task_content_length(&header), None);
    }

    #[test]
    fn test_get_compact_range() {
        // Without the content length header there is no compact range task.
        let header = HashMap::from([("range".to_string(), "bytes=100-199".to_string())]);
        assert_eq!(get_compact_range(&header, None).unwrap(), None);

        // Without a Range header there is no compact range task.
        let header =
            HashMap::from([("x-dragonfly-content-length".to_string(), "1000".to_string())]);
        assert_eq!(get_compact_range(&header, None).unwrap(), None);

        // An invalid content length disables the compact range task.
        let header = HashMap::from([
            ("x-dragonfly-content-length".to_string(), "oops".to_string()),
            ("range".to_string(), "bytes=100-199".to_string()),
        ]);
        assert_eq!(get_compact_range(&header, None).unwrap(), None);

        // The content length and a Range header form a compact range task,
        // matched case-insensitively.
        let header = HashMap::from([
            ("X-Dragonfly-Content-Length".to_string(), "1000".to_string()),
            ("Range".to_string(), "bytes=100-199".to_string()),
        ]);
        assert_eq!(
            get_compact_range(&header, None).unwrap(),
            Some(CompactRange {
                range: Range {
                    start: 100,
                    length: 100,
                },
                total_content_length: 1000,
            })
        );

        // A suffix range is resolved against the declared content length.
        let header = HashMap::from([
            ("x-dragonfly-content-length".to_string(), "1000".to_string()),
            ("range".to_string(), "bytes=-100".to_string()),
        ]);
        assert_eq!(
            get_compact_range(&header, None).unwrap(),
            Some(CompactRange {
                range: Range {
                    start: 900,
                    length: 100,
                },
                total_content_length: 1000,
            })
        );

        // A range whose end exceeds the declared content length is clamped,
        // matching how the origin serves it (RFC 7233).
        let header = HashMap::from([
            ("x-dragonfly-content-length".to_string(), "1000".to_string()),
            ("range".to_string(), "bytes=900-1100".to_string()),
        ]);
        assert_eq!(
            get_compact_range(&header, None).unwrap(),
            Some(CompactRange {
                range: Range {
                    start: 900,
                    length: 100,
                },
                total_content_length: 1000,
            })
        );

        // A range that starts beyond the declared content length is rejected.
        let header = HashMap::from([
            ("x-dragonfly-content-length".to_string(), "1000".to_string()),
            ("range".to_string(), "bytes=1000-1100".to_string()),
        ]);
        assert!(get_compact_range(&header, None).is_err());
    }

    #[test]
    fn test_get_compact_range_validates_chunk_alignment() {
        // A SafeTensors-like layout: the payload is chunked into 100 byte
        // pieces from offset 8.
        let header = |range: &str| {
            HashMap::from([
                ("x-dragonfly-content-length".to_string(), "458".to_string()),
                ("x-dragonfly-piece-offset".to_string(), "8".to_string()),
                ("range".to_string(), range.to_string()),
            ])
        };

        // Aligned chunks, including the shorter trailing chunk.
        for (range, expected_start, expected_length) in [
            ("bytes=8-107", 8, 100),
            ("bytes=208-307", 208, 100),
            ("bytes=408-457", 408, 50),
        ] {
            assert_eq!(
                get_compact_range(&header(range), Some(100)).unwrap(),
                Some(CompactRange {
                    range: Range {
                        start: expected_start,
                        length: expected_length,
                    },
                    total_content_length: 458,
                }),
                "{range} should be aligned"
            );
        }

        // Misaligned ranges are rejected.
        for range in [
            // Starts before the grid offset.
            "bytes=0-7",
            // Not on a chunk boundary.
            "bytes=100-199",
            // Spans two chunks.
            "bytes=8-207",
            // Shorter than the piece length but not trailing.
            "bytes=8-57",
        ] {
            assert!(
                get_compact_range(&header(range), Some(100)).is_err(),
                "{range} should be rejected"
            );
        }

        // The piece offset requires a declared piece length.
        assert!(get_compact_range(&header("bytes=8-107"), None).is_err());

        // An invalid piece offset is rejected.
        let mut invalid = header("bytes=8-107");
        invalid.insert("x-dragonfly-piece-offset".to_string(), "oops".to_string());
        assert!(get_compact_range(&invalid, Some(100)).is_err());
    }

    #[test]
    fn test_is_exact_range() {
        assert!(is_exact_range("bytes=100-199", 100, 100));
        assert!(is_exact_range("bytes=0-0", 0, 1));
        assert!(is_exact_range("BYTES = 100-199", 100, 100));

        assert!(!is_exact_range("bytes=100-199", 100, 99));
        assert!(!is_exact_range("bytes=100-199", 101, 100));
        assert!(!is_exact_range("bytes=-50", 0, 50));
        assert!(!is_exact_range("bytes=100-", 100, 100));
        assert!(!is_exact_range("bytes=0-0,100-199", 0, 200));
        assert!(!is_exact_range("items=100-199", 100, 100));
        assert!(!is_exact_range("100-199", 100, 100));
        assert!(!is_exact_range("bytes=100-199", 100, 0));
        assert!(!is_exact_range("bytes=0-x", 0, u64::MAX));
    }
}
