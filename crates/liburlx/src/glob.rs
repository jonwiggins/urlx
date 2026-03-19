//! URL globbing — pattern expansion for URL templates.
//!
//! Supports curl-compatible glob patterns:
//! - `{a,b,c}` — set expansion
//! - `[0-9]` — numeric range
//! - `[0-100:10]` — numeric range with step
//! - `[a-z]` — alpha range
//! - `[a-z:2]` — alpha range with step
//!
//! Patterns can be nested: `http://{a,b}.example.com/[1-3]/`
//! generates 6 URLs.

#![allow(clippy::module_name_repetitions)]

use crate::Error;

/// A parsed glob segment — either literal text or an expansion pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Literal text (no expansion).
    Literal(String),
    /// Set expansion: `{a,b,c}`.
    Set(Vec<String>),
    /// Numeric range: `[start-end]` or `[start-end:step]`.
    NumericRange {
        start: i64,
        end: i64,
        step: i64,
        /// Zero-pad width (e.g., `[01-10]` → width 2).
        width: usize,
    },
    /// Alpha range: `[a-z]` or `[a-z:step]`.
    AlphaRange { start: char, end: char, step: u32 },
}

impl Segment {
    /// Number of values this segment expands to.
    fn count(&self) -> usize {
        match self {
            Self::Literal(_) => 1,
            Self::Set(items) => items.len(),
            Self::NumericRange { start, end, step, .. } => {
                if *step == 0 {
                    return 0;
                }
                let range = start.abs_diff(*end);
                #[allow(clippy::cast_possible_truncation)]
                let count = (range / step.unsigned_abs()) as usize + 1;
                count
            }
            Self::AlphaRange { start, end, step } => {
                if *step == 0 {
                    return 0;
                }
                let range = (*start as u32).abs_diff(*end as u32);
                (range / step) as usize + 1
            }
        }
    }

    /// Get the value at the given index.
    fn value_at(&self, index: usize) -> String {
        match self {
            Self::Literal(s) => s.clone(),
            Self::Set(items) => items[index].clone(),
            Self::NumericRange { start, step, width, .. } => {
                #[allow(clippy::cast_possible_wrap)]
                let val = start + (index as i64) * step;
                if *width > 0 {
                    format!("{val:0>width$}", width = *width)
                } else {
                    val.to_string()
                }
            }
            Self::AlphaRange { start, step, .. } => {
                #[allow(clippy::cast_possible_truncation)]
                let val = *start as u32 + (index as u32) * step;
                char::from_u32(val).map_or_else(|| "?".to_string(), |c| c.to_string())
            }
        }
    }
}

/// Maximum number of glob patterns (sets + ranges) allowed in a single URL.
/// Matches curl's `CURL_GLOB_PATTERNS_MAX`.
const MAX_GLOB_PATTERNS: usize = 100;

/// Parse a URL glob pattern into segments, tracking character position for errors.
///
/// # Errors
///
/// Returns an error if the glob pattern is malformed or exceeds the pattern limit.
#[allow(clippy::too_many_lines)]
fn parse_glob(pattern: &str) -> Result<Vec<Segment>, Error> {
    let mut segments = Vec::new();
    let mut chars = pattern.chars().peekable();
    let mut literal = String::new();
    let mut pos: usize = 0;
    let mut glob_count: usize = 0;

    while let Some(&ch) = chars.peek() {
        match ch {
            '\\' => {
                // Backslash escaping: \{ \} \[ \] produce literal characters
                let _ = chars.next(); // consume '\'
                pos += 1;
                if let Some(&next_ch) = chars.peek() {
                    if matches!(next_ch, '{' | '}' | '[' | ']') {
                        literal.push(next_ch);
                        let _ = chars.next();
                        pos += next_ch.len_utf8();
                    } else {
                        // Not a glob-special char: keep the backslash
                        literal.push('\\');
                    }
                } else {
                    // Trailing backslash
                    literal.push('\\');
                }
            }
            '{' => {
                glob_count += 1;
                if glob_count > MAX_GLOB_PATTERNS {
                    // Truncate the URL display for the error message
                    // 1-indexed position for display
                    let display_pos = pos + 1;
                    let truncated: String = pattern.chars().take(pos + 2).collect();
                    return Err(Error::UrlGlob {
                        message: format!("too many {{}} sets in URL position {display_pos}:"),
                        url: truncated,
                        position: pos,
                    });
                }
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                let _ = chars.next(); // consume '{'
                pos += 1;
                let (set, consumed) = parse_set_with_len(&mut chars)?;
                pos += consumed;
                segments.push(set);
            }
            '[' => {
                // Peek ahead to decide how to handle the bracket:
                // 1. Empty brackets `[]` → literal (curl compat: test 1290)
                // 2. IPv6 address `[::1]` or `[::1%25scope]` → literal (test 1056)
                // 3. Otherwise → glob range pattern
                //
                // IPv6 detection: scan to closing `]` and check if content looks
                // like an IPv6 address (contains multiple colons, or starts with
                // a colon, or contains `%` for scope IDs). A glob range never has
                // colons before the step separator, so any `:` before a `-` range
                // dash indicates IPv6.
                #[allow(clippy::unused_peekable)]
                let treat_as_literal = {
                    let mut scan = chars.clone();
                    let _ = scan.next(); // skip '['
                    let mut bracket_content = String::new();
                    let mut found_close = false;
                    for c in scan {
                        if c == ']' {
                            found_close = true;
                            break;
                        }
                        bracket_content.push(c);
                    }
                    if !found_close {
                        false // unclosed bracket — let normal parser handle the error
                    } else if bracket_content.is_empty() {
                        true // empty brackets `[]`
                    } else {
                        // IPv6 heuristic: starts with `:` or hex digit followed
                        // by `:`, or contains `%` (scope ID separator).
                        // A valid glob range looks like `N-M` or `N-M:S` — never
                        // starts with `:` and has at most one `:` (the step sep).
                        let colon_count = bracket_content.chars().filter(|&c| c == ':').count();
                        bracket_content.starts_with(':')
                            || colon_count >= 2
                            || bracket_content.contains('%')
                    }
                };

                if treat_as_literal {
                    // Consume everything from '[' to ']' as literal text
                    literal.push('[');
                    let _ = chars.next(); // consume '['
                    pos += 1;
                    // Consume up to and including ']'
                    while let Some(&c) = chars.peek() {
                        literal.push(c);
                        let _ = chars.next();
                        pos += c.len_utf8();
                        if c == ']' {
                            break;
                        }
                    }
                } else {
                    glob_count += 1;
                    if glob_count > MAX_GLOB_PATTERNS {
                        let display_pos = pos + 1;
                        let truncated: String = pattern.chars().take(pos + 2).collect();
                        return Err(Error::UrlGlob {
                            message: format!("too many [] sets in URL position {display_pos}:"),
                            url: truncated,
                            position: pos,
                        });
                    }
                    if !literal.is_empty() {
                        segments.push(Segment::Literal(std::mem::take(&mut literal)));
                    }
                    let open_pos = pos;
                    let _ = chars.next(); // consume '['
                    pos += 1;
                    let (range, consumed) = parse_range_with_len(&mut chars, pattern, open_pos)?;
                    pos += consumed;
                    segments.push(range);
                }
            }
            _ => {
                literal.push(ch);
                let _ = chars.next();
                pos += ch.len_utf8();
            }
        }
    }

    if !literal.is_empty() {
        segments.push(Segment::Literal(literal));
    }

    Ok(segments)
}

/// Parse a set expansion `{a,b,c}`, returning the segment and character count consumed.
fn parse_set_with_len(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<(Segment, usize), Error> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut depth = 1;
    let mut consumed: usize = 0;

    for ch in chars.by_ref() {
        consumed += ch.len_utf8();
        match ch {
            '{' => {
                depth += 1;
                current.push(ch);
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    items.push(current);
                    if items.is_empty() {
                        return Err(Error::Http("empty glob set {}".to_string()));
                    }
                    return Ok((Segment::Set(items), consumed));
                }
                current.push(ch);
            }
            ',' if depth == 1 => {
                items.push(std::mem::take(&mut current));
            }
            _ => {
                current.push(ch);
            }
        }
    }

    Err(Error::Http("unclosed glob set '{'".to_string()))
}

/// Parse a range `[start-end]` or `[start-end:step]`, returning the segment and chars consumed.
/// `url` and `open_pos` are used to generate curl-compatible error messages with position info.
fn parse_range_with_len(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    url: &str,
    open_pos: usize,
) -> Result<(Segment, usize), Error> {
    let mut content = String::new();
    let mut consumed: usize = 0;

    for ch in chars.by_ref() {
        consumed += ch.len_utf8();
        if ch == ']' {
            // Position after the closing ']' (1-indexed for curl compat)
            let end_pos = open_pos + 1 + consumed;
            let seg = parse_range_content_with_pos(&content, url, end_pos)?;
            return Ok((seg, consumed));
        }
        content.push(ch);
    }

    Err(Error::Http("unclosed glob range '['".to_string()))
}

/// Parse the content inside `[...]` with position info for curl-compatible errors.
fn parse_range_content_with_pos(
    content: &str,
    url: &str,
    end_pos: usize,
) -> Result<Segment, Error> {
    // Split on '-' to get start and end (possibly with :step)
    // Careful: negative numbers could have leading '-'
    // Format: start-end or start-end:step
    let (range_part, step_str) = content.rfind(':').map_or((content, None), |colon_pos| {
        (&content[..colon_pos], Some(&content[colon_pos + 1..]))
    });

    // Find the '-' separator (not a leading minus sign)
    let dash_pos = find_range_dash(range_part)
        .ok_or_else(|| Error::Http(format!("invalid glob range: [{content}]")))?;

    let start_str = &range_part[..dash_pos];
    let end_str = &range_part[dash_pos + 1..];

    // Try alpha range first
    if start_str.len() == 1 && end_str.len() == 1 {
        let start_ch = start_str.chars().next().unwrap_or('a');
        let end_ch = end_str.chars().next().unwrap_or('z');
        if start_ch.is_ascii_alphabetic() && end_ch.is_ascii_alphabetic() {
            let step = step_str
                .map(str::parse::<u32>)
                .transpose()
                .map_err(|_| Error::Http(format!("invalid glob range step: [{content}]")))?
                .unwrap_or(1);
            if start_ch > end_ch {
                return Err(bad_range_error(url, end_pos));
            }
            return Ok(Segment::AlphaRange { start: start_ch, end: end_ch, step });
        }
    }

    // Numeric range
    let start: i64 = start_str
        .parse()
        .map_err(|_| Error::Http(format!("invalid glob range start: [{content}]")))?;
    let end: i64 =
        end_str.parse().map_err(|_| Error::Http(format!("invalid glob range end: [{content}]")))?;

    // Detect zero-padding from the start value
    let width = if start_str.len() > 1 && start_str.starts_with('0') {
        start_str.len()
    } else if end_str.len() > 1 && end_str.starts_with('0') {
        end_str.len()
    } else {
        0
    };

    let step = step_str
        .map(str::parse::<i64>)
        .transpose()
        .map_err(|_| Error::Http(format!("invalid glob range step: [{content}]")))?
        .unwrap_or(1);

    if step == 0 {
        return Err(Error::Http("glob range step cannot be zero".to_string()));
    }

    // Validate range direction matches step sign (curl compat: [2-1] is an error)
    if (step > 0 && start > end) || (step < 0 && start < end) {
        return Err(bad_range_error(url, end_pos));
    }

    Ok(Segment::NumericRange { start, end, step, width })
}

/// Build a curl-compatible "bad range" error with URL position and caret indicator.
///
/// `end_pos` is the 0-indexed byte position after the closing `]`.
/// curl uses 1-indexed positions in its error messages.
fn bad_range_error(url: &str, end_pos: usize) -> Error {
    if url.is_empty() {
        return Error::UrlGlob {
            message: "bad range in URL".to_string(),
            url: String::new(),
            position: 0,
        };
    }
    // curl uses 1-indexed positions
    let display_pos = end_pos + 1;
    Error::UrlGlob {
        message: format!("bad range in URL position {display_pos}:"),
        url: url.to_string(),
        position: end_pos,
    }
}

/// Find the dash that separates start from end in a range.
/// Skips a leading '-' (negative number).
fn find_range_dash(s: &str) -> Option<usize> {
    let start = usize::from(s.starts_with('-'));
    s[start..].find('-').map(|pos| pos + start)
}

/// Maximum number of URLs that glob expansion can produce.
const MAX_EXPANSION: usize = 100_000;

/// Expand a URL glob pattern into a list of concrete URLs.
///
/// # Examples
///
/// - `http://example.com/{a,b}` → `["http://example.com/a", "http://example.com/b"]`
/// - `http://example.com/[1-3]` → `["http://example.com/1", "http://example.com/2", "http://example.com/3"]`
///
/// # Errors
///
/// Returns an error if the glob pattern is malformed (unclosed braces, invalid ranges).
pub fn expand_glob(pattern: &str) -> Result<Vec<String>, Error> {
    let segments = parse_glob(pattern)?;

    if segments.iter().all(|s| matches!(s, Segment::Literal(_))) {
        // No expansion needed — but return the processed string (with escape sequences
        // resolved, e.g. \{ -> {) rather than the raw pattern (curl compat: test 214)
        let joined: String = segments.iter().map(|s| s.value_at(0)).collect();
        return Ok(vec![joined]);
    }

    // Compute total combinations
    let total: usize = segments.iter().map(Segment::count).product();

    if total > MAX_EXPANSION {
        return Err(Error::Http(format!(
            "glob expansion too large: {total} URLs (max {MAX_EXPANSION})"
        )));
    }

    let mut results = Vec::with_capacity(total);

    // Use a multi-dimensional index to iterate over all combinations
    let counts: Vec<usize> = segments.iter().map(Segment::count).collect();
    let mut indices = vec![0usize; segments.len()];

    for _ in 0..total {
        // Build current URL from indices
        let mut url = String::new();
        for (seg_idx, segment) in segments.iter().enumerate() {
            url.push_str(&segment.value_at(indices[seg_idx]));
        }
        results.push(url);

        // Increment indices (rightmost first, like an odometer)
        let mut carry = true;
        for i in (0..indices.len()).rev() {
            if carry {
                indices[i] += 1;
                if indices[i] >= counts[i] {
                    indices[i] = 0;
                } else {
                    carry = false;
                }
            }
        }
    }

    Ok(results)
}

/// Expand a URL glob pattern, returning both the expanded URLs and per-URL
/// glob match values (for `#1`, `#2` output template substitution).
///
/// Each element of the returned vector is `(expanded_url, glob_values)` where
/// `glob_values[0]` is the value of the first glob group, etc.
///
/// When there are no glob patterns, returns a single entry with an empty values vec.
///
/// # Errors
///
/// Returns an error if the glob pattern is malformed (unclosed braces, invalid ranges).
pub fn expand_glob_with_values(pattern: &str) -> Result<Vec<(String, Vec<String>)>, Error> {
    let segments = parse_glob(pattern)?;

    // Identify which segments are glob patterns (non-literal)
    let glob_segment_indices: Vec<usize> = segments
        .iter()
        .enumerate()
        .filter(|(_, s)| !matches!(s, Segment::Literal(_)))
        .map(|(i, _)| i)
        .collect();

    if glob_segment_indices.is_empty() {
        // No expansion needed — return processed string with escape sequences resolved
        let joined: String = segments.iter().map(|s| s.value_at(0)).collect();
        return Ok(vec![(joined, Vec::new())]);
    }

    // Compute total combinations
    let total: usize = segments.iter().map(Segment::count).product();

    if total > MAX_EXPANSION {
        return Err(Error::Http(format!(
            "glob expansion too large: {total} URLs (max {MAX_EXPANSION})"
        )));
    }

    let mut results = Vec::with_capacity(total);

    let counts: Vec<usize> = segments.iter().map(Segment::count).collect();
    let mut indices = vec![0usize; segments.len()];

    for _ in 0..total {
        // Build current URL from indices
        let mut url = String::new();
        for (seg_idx, segment) in segments.iter().enumerate() {
            url.push_str(&segment.value_at(indices[seg_idx]));
        }

        // Collect glob match values (only non-literal segments)
        let values: Vec<String> =
            glob_segment_indices.iter().map(|&i| segments[i].value_at(indices[i])).collect();

        results.push((url, values));

        // Increment indices (rightmost first, like an odometer)
        let mut carry = true;
        for i in (0..indices.len()).rev() {
            if carry {
                indices[i] += 1;
                if indices[i] >= counts[i] {
                    indices[i] = 0;
                } else {
                    carry = false;
                }
            }
        }
    }

    Ok(results)
}

/// Returns the number of glob expansion patterns in a URL.
/// Returns 0 if there are no glob patterns.
///
/// # Errors
///
/// Returns an error if the pattern is malformed.
pub fn glob_pattern_count(pattern: &str) -> Result<usize, Error> {
    let segments = parse_glob(pattern)?;
    Ok(segments.iter().filter(|s| !matches!(s, Segment::Literal(_))).count())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    // --- Set expansion ---

    #[test]
    fn set_expansion_basic() {
        let urls = expand_glob("http://example.com/{a,b,c}").unwrap();
        assert_eq!(
            urls,
            vec!["http://example.com/a", "http://example.com/b", "http://example.com/c",]
        );
    }

    #[test]
    fn set_expansion_multiple_sets() {
        let urls = expand_glob("http://{a,b}.example.com/{x,y}").unwrap();
        assert_eq!(
            urls,
            vec![
                "http://a.example.com/x",
                "http://a.example.com/y",
                "http://b.example.com/x",
                "http://b.example.com/y",
            ]
        );
    }

    #[test]
    fn set_expansion_single_item() {
        let urls = expand_glob("http://example.com/{only}").unwrap();
        assert_eq!(urls, vec!["http://example.com/only"]);
    }

    #[test]
    fn set_expansion_empty_items() {
        let urls = expand_glob("http://example.com/{a,,c}").unwrap();
        assert_eq!(
            urls,
            vec!["http://example.com/a", "http://example.com/", "http://example.com/c",]
        );
    }

    // --- Numeric range ---

    #[test]
    fn numeric_range_basic() {
        let urls = expand_glob("http://example.com/[1-5]").unwrap();
        assert_eq!(
            urls,
            vec![
                "http://example.com/1",
                "http://example.com/2",
                "http://example.com/3",
                "http://example.com/4",
                "http://example.com/5",
            ]
        );
    }

    #[test]
    fn numeric_range_with_step() {
        let urls = expand_glob("http://example.com/[0-10:5]").unwrap();
        assert_eq!(
            urls,
            vec!["http://example.com/0", "http://example.com/5", "http://example.com/10",]
        );
    }

    #[test]
    fn numeric_range_zero_padded() {
        let urls = expand_glob("http://example.com/[01-03]").unwrap();
        assert_eq!(
            urls,
            vec!["http://example.com/01", "http://example.com/02", "http://example.com/03",]
        );
    }

    #[test]
    fn numeric_range_single_value() {
        let urls = expand_glob("http://example.com/[5-5]").unwrap();
        assert_eq!(urls, vec!["http://example.com/5"]);
    }

    // --- Alpha range ---

    #[test]
    fn alpha_range_basic() {
        let urls = expand_glob("http://example.com/[a-d]").unwrap();
        assert_eq!(
            urls,
            vec![
                "http://example.com/a",
                "http://example.com/b",
                "http://example.com/c",
                "http://example.com/d",
            ]
        );
    }

    #[test]
    fn alpha_range_with_step() {
        let urls = expand_glob("http://example.com/[a-g:2]").unwrap();
        assert_eq!(
            urls,
            vec![
                "http://example.com/a",
                "http://example.com/c",
                "http://example.com/e",
                "http://example.com/g",
            ]
        );
    }

    #[test]
    fn alpha_range_uppercase() {
        let urls = expand_glob("http://example.com/[A-C]").unwrap();
        assert_eq!(
            urls,
            vec!["http://example.com/A", "http://example.com/B", "http://example.com/C",]
        );
    }

    // --- Combined patterns ---

    #[test]
    fn combined_set_and_range() {
        let urls = expand_glob("http://{foo,bar}.com/[1-2]").unwrap();
        assert_eq!(
            urls,
            vec!["http://foo.com/1", "http://foo.com/2", "http://bar.com/1", "http://bar.com/2",]
        );
    }

    // --- No expansion ---

    #[test]
    fn no_glob_returns_original() {
        let urls = expand_glob("http://example.com/path").unwrap();
        assert_eq!(urls, vec!["http://example.com/path"]);
    }

    // --- Error cases ---

    #[test]
    fn unclosed_brace_error() {
        let err = expand_glob("http://example.com/{a,b").unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }

    #[test]
    fn unclosed_bracket_error() {
        let err = expand_glob("http://example.com/[1-5").unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }

    #[test]
    fn zero_step_error() {
        let err = expand_glob("http://example.com/[1-5:0]").unwrap_err();
        assert!(err.to_string().contains("zero"));
    }

    #[test]
    fn invalid_range_error() {
        let err = expand_glob("http://example.com/[abc]").unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    // --- Glob pattern count ---

    #[test]
    fn pattern_count_none() {
        assert_eq!(glob_pattern_count("http://example.com/").unwrap(), 0);
    }

    #[test]
    fn pattern_count_one() {
        assert_eq!(glob_pattern_count("http://example.com/{a,b}").unwrap(), 1);
    }

    #[test]
    fn pattern_count_two() {
        assert_eq!(glob_pattern_count("http://{a,b}.com/[1-3]").unwrap(), 2);
    }

    // --- Expansion counter ---

    #[test]
    fn large_expansion_capped() {
        // Trying to generate too many URLs should fail
        let err = expand_glob("http://[0-999]/[0-999]").unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    // --- Edge cases ---

    #[test]
    fn literal_braces_in_url() {
        // If there's no closing brace matching, it fails
        let err = expand_glob("http://example.com/{unclosed").unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }

    #[test]
    fn numeric_range_step_2() {
        let urls = expand_glob("http://example.com/[1-9:3]").unwrap();
        assert_eq!(
            urls,
            vec!["http://example.com/1", "http://example.com/4", "http://example.com/7",]
        );
    }
}
