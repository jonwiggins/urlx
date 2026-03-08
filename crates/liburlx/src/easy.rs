//! Single-transfer blocking API.
//!
//! The `Easy` handle is the primary way to perform URL transfers.
//! It provides a blocking API that wraps the async internals.

use crate::error::Error;
use crate::protocol::http::response::Response;
use crate::url::Url;

/// A handle for performing a single URL transfer.
///
/// This is the main entry point for the liburlx API, modeled after
/// curl's `CURL *` easy handle.
#[derive(Debug)]
pub struct Easy {
    url: Option<Url>,
}

impl Easy {
    /// Create a new transfer handle.
    #[must_use]
    pub const fn new() -> Self {
        Self { url: None }
    }

    /// Set the URL to transfer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UrlParse`] if the URL is invalid.
    pub fn url(&mut self, url: &str) -> Result<(), Error> {
        self.url = Some(Url::parse(url)?);
        Ok(())
    }

    /// Perform the transfer and return the response.
    ///
    /// # Errors
    ///
    /// Returns errors for connection failures, TLS errors, HTTP protocol
    /// errors, timeouts, and other transfer problems.
    pub fn perform(&self) -> Result<Response, Error> {
        let url = self.url.as_ref().ok_or_else(|| Error::UrlParse("no URL set".to_string()))?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Http(format!("failed to create runtime: {e}")))?;

        rt.block_on(perform_async(url))
    }
}

impl Default for Easy {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal async transfer implementation.
async fn perform_async(url: &Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let request_target = url.request_target();

    // Connect via TCP
    let addr = format!("{host}:{port}");
    let tcp_stream = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;

    match url.scheme() {
        "https" => {
            #[cfg(feature = "rustls")]
            {
                let tls = crate::tls::TlsConnector::new()?;
                let mut tls_stream = tls.connect(tcp_stream, &host).await?;
                crate::protocol::http::h1::get(
                    &mut tls_stream,
                    &host,
                    &request_target,
                    url.as_str(),
                )
                .await
            }
            #[cfg(not(feature = "rustls"))]
            {
                Err(Error::Http("HTTPS support requires the 'rustls' feature".to_string()))
            }
        }
        "http" => {
            let mut tcp_stream = tcp_stream;
            crate::protocol::http::h1::get(&mut tcp_stream, &host, &request_target, url.as_str())
                .await
        }
        scheme => Err(Error::Http(format!("unsupported scheme: {scheme}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn easy_new_has_no_url() {
        let easy = Easy::new();
        assert!(easy.url.is_none());
    }

    #[test]
    fn easy_set_url() {
        let mut easy = Easy::new();
        easy.url("http://example.com").unwrap();
        assert!(easy.url.is_some());
    }

    #[test]
    fn easy_set_invalid_url() {
        let mut easy = Easy::new();
        assert!(easy.url("").is_err());
    }

    #[test]
    fn easy_perform_without_url() {
        let easy = Easy::new();
        let result = easy.perform();
        assert!(result.is_err());
    }

    #[test]
    fn easy_default() {
        let easy = Easy::default();
        assert!(easy.url.is_none());
    }
}
