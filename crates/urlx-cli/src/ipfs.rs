//! IPFS/IPNS URL rewriting.
//!
//! Rewrites `ipfs://` and `ipns://` URLs to HTTP(S) gateway URLs,
//! matching curl's behavior in `tool_ipfs.c`.

use std::path::PathBuf;

/// Error returned by IPFS URL rewriting.
#[derive(Debug)]
pub enum IpfsError {
    /// Gateway URL from `--ipfs-gateway` is malformed (`CURLE_BAD_FUNCTION_ARGUMENT` = 43).
    BadGatewayArg(String),
    /// Gateway URL is malformed (`CURLE_URL_MALFORMAT` = 3).
    MalformedGateway(String),
    /// No gateway URL found (`CURLE_FILE_COULDNT_READ_FILE` = 37).
    NoGateway(String),
}

impl IpfsError {
    /// Returns the curl-compatible exit code for this error.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::BadGatewayArg(_) => 43,
            Self::MalformedGateway(_) => 3,
            Self::NoGateway(_) => 37,
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        match self {
            Self::BadGatewayArg(msg) | Self::MalformedGateway(msg) | Self::NoGateway(msg) => msg,
        }
    }
}

/// Check if a URL uses the `ipfs://` or `ipns://` scheme.
pub fn is_ipfs_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("ipfs://") || lower.starts_with("ipns://")
}

/// Rewrite an `ipfs://` or `ipns://` URL to an HTTP gateway URL.
///
/// Gateway resolution order (matching curl):
/// 1. `--ipfs-gateway` CLI argument
/// 2. `IPFS_GATEWAY` environment variable
/// 3. `$IPFS_PATH/gateway` file (if `IPFS_PATH` env set)
/// 4. `$HOME/.ipfs/gateway` file
///
/// # Errors
///
/// Returns [`IpfsError`] with the appropriate curl exit code on failure.
pub fn ipfs_url_rewrite(url: &str, ipfs_gateway: Option<&str>) -> Result<String, IpfsError> {
    let lower = url.to_ascii_lowercase();

    // Extract protocol name and the rest of the URL after "://"
    let (protocol, rest) = if lower.starts_with("ipfs://") {
        ("ipfs", &url[7..])
    } else if lower.starts_with("ipns://") {
        ("ipns", &url[7..])
    } else {
        return Ok(url.to_string());
    };

    // Split CID/host from path+query.
    // ipfs://CID/path?query -> cid="CID", path_and_query="/path?query"
    let (cid, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => match rest.find('?') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        },
    };

    if cid.is_empty() {
        return Err(IpfsError::MalformedGateway("malformed target URL".to_string()));
    }

    // Separate path from query string
    let (ipfs_path, query) = match path_and_query.find('?') {
        Some(i) => (&path_and_query[..i], Some(&path_and_query[i + 1..])),
        None => (path_and_query, None),
    };

    // Normalize: if path is just "/", treat as empty (curl compat)
    let ipfs_path = if ipfs_path == "/" { "" } else { ipfs_path };

    // Resolve gateway URL
    let (gateway_str, from_cli_arg) = resolve_gateway(ipfs_gateway)?;

    // Parse and validate gateway URL using string manipulation (no url crate dependency)
    let (gw_scheme, gw_rest) = if let Some(r) = gateway_str.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = gateway_str.strip_prefix("https://") {
        ("https", r)
    } else {
        return Err(if from_cli_arg {
            IpfsError::BadGatewayArg("--ipfs-gateway was given a malformed URL".to_string())
        } else {
            IpfsError::MalformedGateway("malformed target URL".to_string())
        });
    };

    // Split authority from path
    let (gw_authority, gw_path) = match gw_rest.find('/') {
        Some(i) => (&gw_rest[..i], &gw_rest[i..]),
        None => (gw_rest, "/"),
    };

    // Validate: authority must not be empty and must not contain commas
    // (curl rejects commas in hostnames; test 723)
    if gw_authority.is_empty() || gw_authority.contains(',') {
        return Err(if from_cli_arg {
            IpfsError::BadGatewayArg("--ipfs-gateway was given a malformed URL".to_string())
        } else {
            IpfsError::MalformedGateway("malformed target URL".to_string())
        });
    }

    // Validate: gateway URL must not have a query string (curl compat: test 739)
    if gw_path.contains('?') {
        return Err(IpfsError::MalformedGateway("malformed target URL".to_string()));
    }

    // Build new path: {gw_path}/{protocol}/{cid}{ipfs_path}
    // Strip trailing slash from gateway path to avoid double slashes
    let gw_path_base = gw_path.trim_end_matches('/');
    let new_path = format!("{gw_path_base}/{protocol}/{cid}{ipfs_path}");

    // Build the rewritten URL
    let query_str = match query {
        Some(q) => format!("?{q}"),
        None => String::new(),
    };

    Ok(format!("{gw_scheme}://{gw_authority}{new_path}{query_str}"))
}

/// Resolve the IPFS gateway URL from available sources.
///
/// Returns `(gateway_url, from_cli_arg)` where `from_cli_arg` indicates
/// whether the gateway came from the `--ipfs-gateway` CLI argument
/// (affects error code: 43 vs 3).
fn resolve_gateway(ipfs_gateway: Option<&str>) -> Result<(String, bool), IpfsError> {
    // 1. CLI argument (highest priority)
    if let Some(gw) = ipfs_gateway {
        return Ok((gw.to_string(), true));
    }

    // 2. IPFS_GATEWAY environment variable
    if let Ok(gw) = std::env::var("IPFS_GATEWAY") {
        if !gw.is_empty() {
            return Ok((gw, false));
        }
    }

    // 3. IPFS_PATH env -> {IPFS_PATH}/gateway file
    if let Ok(ipfs_path) = std::env::var("IPFS_PATH") {
        if !ipfs_path.is_empty() {
            let mut path = PathBuf::from(&ipfs_path);
            path.push("gateway");
            return read_gateway_file(&path);
        }
    }

    // 4. HOME/.ipfs/gateway
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            let mut path = PathBuf::from(&home);
            path.push(".ipfs");
            path.push("gateway");
            return read_gateway_file(&path);
        }
    }

    Err(IpfsError::NoGateway("IPFS automatic gateway detection failed".to_string()))
}

/// Read the gateway URL from a file.
///
/// Only the first line is used; subsequent lines are ignored (curl compat: test 740).
fn read_gateway_file(path: &PathBuf) -> Result<(String, bool), IpfsError> {
    let content = std::fs::read_to_string(path)
        .map_err(|_| IpfsError::NoGateway("IPFS automatic gateway detection failed".to_string()))?;

    // Read first line only (up to \n or \r), trimmed
    let first_line = content.lines().next().unwrap_or("").trim();

    if first_line.is_empty() {
        return Err(IpfsError::NoGateway("IPFS automatic gateway detection failed".to_string()));
    }

    Ok((first_line.to_string(), false))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn basic_ipfs_rewrite() {
        let result = ipfs_url_rewrite(
            "ipfs://bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u",
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();
        assert_eq!(
            result,
            "http://127.0.0.1:8080/ipfs/bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u"
        );
    }

    #[test]
    fn basic_ipns_rewrite() {
        let result = ipfs_url_rewrite(
            "ipns://bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u",
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();
        assert_eq!(
            result,
            "http://127.0.0.1:8080/ipns/bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u"
        );
    }

    #[test]
    fn ipfs_with_path() {
        let result = ipfs_url_rewrite(
            "ipfs://bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u/a/b",
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();
        assert_eq!(
            result,
            "http://127.0.0.1:8080/ipfs/bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u/a/b"
        );
    }

    #[test]
    fn ipfs_with_path_and_query() {
        let result = ipfs_url_rewrite(
            "ipfs://bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u/a/b?foo=bar&aaa=bbb",
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();
        assert_eq!(
            result,
            "http://127.0.0.1:8080/ipfs/bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u/a/b?foo=bar&aaa=bbb"
        );
    }

    #[test]
    fn gateway_with_path() {
        let result = ipfs_url_rewrite(
            "ipfs://bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u",
            Some("http://127.0.0.1:8080/foo/bar"),
        )
        .unwrap();
        assert_eq!(
            result,
            "http://127.0.0.1:8080/foo/bar/ipfs/bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u"
        );
    }

    #[test]
    fn gateway_with_path_and_ipfs_path_and_query() {
        let result = ipfs_url_rewrite(
            "ipfs://bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u/a/b?foo=bar&aaa=bbb",
            Some("http://127.0.0.1:8080/some/path"),
        )
        .unwrap();
        assert_eq!(
            result,
            "http://127.0.0.1:8080/some/path/ipfs/bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u/a/b?foo=bar&aaa=bbb"
        );
    }

    #[test]
    fn ipns_with_domain() {
        let result = ipfs_url_rewrite(
            "ipns://fancy.tld/a/b?foo=bar&aaa=bbb",
            Some("http://127.0.0.1:8080/some/path"),
        )
        .unwrap();
        assert_eq!(result, "http://127.0.0.1:8080/some/path/ipns/fancy.tld/a/b?foo=bar&aaa=bbb");
    }

    #[test]
    fn malformed_cli_gateway() {
        let result = ipfs_url_rewrite(
            "ipfs://bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u",
            Some("http://nonexisting,local:8080"),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().exit_code(), 43);
    }

    #[test]
    fn gateway_with_query_string_rejected() {
        let result = ipfs_url_rewrite(
            "ipns://fancy.tld/a/b?foo=bar",
            Some("http://127.0.0.1:8080/some/path?biz=baz"),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().exit_code(), 3);
    }

    #[test]
    fn non_ipfs_url_unchanged() {
        let result = ipfs_url_rewrite("http://example.com", Some("http://gw:8080")).unwrap();
        assert_eq!(result, "http://example.com");
    }

    #[test]
    fn is_ipfs_url_detection() {
        assert!(is_ipfs_url("ipfs://hash"));
        assert!(is_ipfs_url("ipns://name"));
        assert!(is_ipfs_url("IPFS://hash"));
        assert!(is_ipfs_url("IPNS://name"));
        assert!(!is_ipfs_url("http://example.com"));
        assert!(!is_ipfs_url("ftp://files.example.com"));
    }
}
