//! AWS Signature Version 4 request signing.
//!
//! Implements the AWS `SigV4` signing process for authenticating requests
//! to AWS services. Equivalent to curl's `--aws-sigv4` option.
//!
//! References:
//! - <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html>
//! - <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>

use sha2::Digest as _;

/// AWS `SigV4` signing configuration.
#[derive(Debug, Clone)]
pub struct AwsSigV4Config {
    /// The AWS provider prefix (e.g., "aws").
    pub provider: String,
    /// The AWS region (e.g., "us-east-1").
    pub region: String,
    /// The AWS service name (e.g., "s3", "execute-api").
    pub service: String,
}

impl AwsSigV4Config {
    /// Parse a `SigV4` spec string in the format `provider:region:service`.
    ///
    /// This matches curl's `--aws-sigv4` format.
    #[must_use]
    pub fn parse(spec: &str) -> Option<Self> {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        Some(Self {
            provider: parts[0].to_string(),
            region: parts[1].to_string(),
            service: parts[2].to_string(),
        })
    }
}

/// Sign an HTTP request using AWS `SigV4`.
///
/// Returns the headers to add to the request: `Authorization`, `x-amz-date`,
/// and `x-amz-content-sha256`.
///
/// # Arguments
///
/// * `method` - HTTP method (GET, POST, etc.)
/// * `url` - The full request URL
/// * `headers` - Existing request headers
/// * `body` - The request body (empty for GET)
/// * `access_key` - AWS access key ID
/// * `secret_key` - AWS secret access key
/// * `config` - `SigV4` configuration (region, service)
/// * `timestamp` - The signing timestamp (ISO 8601 format)
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    method: &str,
    url: &url::Url,
    headers: &[(String, String)],
    body: &[u8],
    access_key: &str,
    secret_key: &str,
    config: &AwsSigV4Config,
    timestamp: &str,
) -> Vec<(String, String)> {
    let date = &timestamp[..8]; // YYYYMMDD

    // Step 1: Create the canonical request
    let payload_hash = hex_sha256(body);
    let canonical_request =
        create_canonical_request(method, url, headers, &payload_hash, timestamp);

    // Step 2: Create the string to sign
    let credential_scope = format!(
        "{date}/{region}/{service}/{provider}_request",
        region = config.region,
        service = config.service,
        provider = config.provider.to_lowercase(),
    );
    let string_to_sign = format!(
        "{provider}-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{hash}",
        provider = config.provider.to_uppercase(),
        hash = hex_sha256(canonical_request.as_bytes()),
    );

    // Step 3: Calculate the signature
    let signing_key =
        derive_signing_key(secret_key, date, &config.region, &config.service, &config.provider);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    // Step 4: Build the Authorization header
    let signed_headers = get_signed_headers_list(headers, timestamp);
    let authorization = format!(
        "{provider}-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        provider = config.provider.to_uppercase(),
    );

    vec![
        ("Authorization".to_string(), authorization),
        ("x-amz-date".to_string(), timestamp.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash),
    ]
}

/// Generate the current UTC timestamp in AWS `SigV4` format (`YYYYMMDDTHHMMSSZ`).
#[must_use]
pub fn now_timestamp() -> String {
    use std::time::SystemTime;

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();

    let secs = now.as_secs();
    // Simple timestamp calculation (no chrono dependency)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}{month:02}{day:02}T{hours:02}{minutes:02}{seconds:02}Z")
}

/// Convert days since 1970-01-01 to (year, month, day).
const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Adapted from Howard Hinnant's algorithm
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Create the canonical request string.
fn create_canonical_request(
    method: &str,
    url: &url::Url,
    headers: &[(String, String)],
    payload_hash: &str,
    timestamp: &str,
) -> String {
    let canonical_uri = url.path();

    // Sort query parameters
    let canonical_querystring = canonical_query_string(url);

    // Build canonical headers (must include host and x-amz-date)
    let host = url.host_str().unwrap_or("");
    let mut canonical_headers: Vec<(String, String)> = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), timestamp.to_string()),
    ];

    // Add any existing x-amz-* headers
    for (k, v) in headers {
        let lower = k.to_lowercase();
        if lower.starts_with("x-amz-") && lower != "x-amz-date" {
            canonical_headers.push((lower, v.trim().to_string()));
        }
    }

    canonical_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let headers_str: String = canonical_headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let signed_headers: String =
        canonical_headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");

    format!("{method}\n{canonical_uri}\n{canonical_querystring}\n{headers_str}\n{signed_headers}\n{payload_hash}")
}

/// Build the canonical query string (sorted parameters).
fn canonical_query_string(url: &url::Url) -> String {
    let mut pairs: Vec<(String, String)> =
        url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// Get the sorted list of signed header names.
fn get_signed_headers_list(headers: &[(String, String)], _timestamp: &str) -> String {
    let mut names = vec!["host".to_string(), "x-amz-date".to_string()];

    for (k, _) in headers {
        let lower = k.to_lowercase();
        if lower.starts_with("x-amz-") && lower != "x-amz-date" && !names.contains(&lower) {
            names.push(lower);
        }
    }

    names.sort();
    names.join(";")
}

/// Compute SHA-256 hash as hex string.
fn hex_sha256(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}

/// Compute HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use sha2::Sha256;

    // HMAC-SHA256 implementation (inline to avoid adding hmac crate)
    let block_size = 64;

    let key = if key.len() > block_size { Sha256::digest(key).to_vec() } else { key.to_vec() };

    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5Cu8; block_size];

    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }

    ipad.extend_from_slice(data);
    let inner_hash = Sha256::digest(&ipad);

    opad.extend_from_slice(&inner_hash);
    Sha256::digest(&opad).to_vec()
}

/// Derive the `SigV4` signing key.
fn derive_signing_key(
    secret_key: &str,
    date: &str,
    region: &str,
    service: &str,
    provider: &str,
) -> Vec<u8> {
    let k_secret =
        format!("{provider_upper}4{secret_key}", provider_upper = provider.to_uppercase(),);
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, format!("{}_request", provider.to_lowercase()).as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_sigv4_spec() {
        let config = AwsSigV4Config::parse("aws:us-east-1:s3").unwrap();
        assert_eq!(config.provider, "aws");
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.service, "s3");
    }

    #[test]
    fn parse_sigv4_spec_too_few_parts() {
        assert!(AwsSigV4Config::parse("aws:us-east-1").is_none());
    }

    #[test]
    fn hex_sha256_empty_body() {
        let hash = hex_sha256(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha256(key, data);
        assert_eq!(
            hex::encode(&result),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2024-01-15 is day 19737 since epoch
        let (y, m, d) = days_to_ymd(19_737);
        assert_eq!((y, m, d), (2024, 1, 15));
    }

    #[test]
    fn now_timestamp_format() {
        let ts = now_timestamp();
        assert_eq!(ts.len(), 16); // YYYYMMDDTHHMMSSZ
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[8..9], "T");
    }

    #[test]
    fn sign_request_produces_authorization() {
        let config = AwsSigV4Config {
            provider: "aws".to_string(),
            region: "us-east-1".to_string(),
            service: "s3".to_string(),
        };

        let url = url::Url::parse("https://example.s3.amazonaws.com/test.txt").unwrap();
        let headers = vec![];
        let timestamp = "20130524T000000Z";

        let result = sign_request(
            "GET",
            &url,
            &headers,
            b"",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            &config,
            timestamp,
        );

        // Should produce 3 headers
        assert_eq!(result.len(), 3);

        // Check header names
        let names: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Authorization"));
        assert!(names.contains(&"x-amz-date"));
        assert!(names.contains(&"x-amz-content-sha256"));

        // Authorization should contain the expected format
        let auth = &result.iter().find(|(k, _)| k == "Authorization").unwrap().1;
        assert!(auth.starts_with("AWS-HMAC-SHA256"));
        assert!(auth.contains("Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws_request"));
        assert!(auth.contains("SignedHeaders=host;x-amz-date"));
        assert!(auth.contains("Signature="));
    }

    #[test]
    fn canonical_query_string_sorted() {
        let url = url::Url::parse("https://example.com/?z=1&a=2&m=3").unwrap();
        let qs = canonical_query_string(&url);
        assert_eq!(qs, "a=2&m=3&z=1");
    }

    #[test]
    fn canonical_query_string_empty() {
        let url = url::Url::parse("https://example.com/path").unwrap();
        let qs = canonical_query_string(&url);
        assert!(qs.is_empty());
    }

    #[test]
    fn derive_signing_key_not_empty() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20130524",
            "us-east-1",
            "s3",
            "aws",
        );
        assert_eq!(key.len(), 32); // SHA-256 output is 32 bytes
    }
}
