//! Content-Encoding decompression for HTTP response bodies.
//!
//! Supports gzip, deflate, brotli, and zstd encodings.

use crate::error::Error;

/// Decompress a response body based on the Content-Encoding header.
///
/// # Errors
///
/// Returns [`Error::Http`] if decompression fails.
pub fn decompress(data: &[u8], encoding: &str) -> Result<Vec<u8>, Error> {
    let enc = encoding.trim();
    if enc.eq_ignore_ascii_case("gzip") || enc.eq_ignore_ascii_case("x-gzip") {
        decompress_gzip(data)
    } else if enc.eq_ignore_ascii_case("deflate") {
        decompress_deflate(data)
    } else if cfg!(feature = "decompression") && enc.eq_ignore_ascii_case("br") {
        #[cfg(feature = "decompression")]
        return decompress_brotli(data);
        #[cfg(not(feature = "decompression"))]
        Err(Error::Http(format!("unsupported Content-Encoding: {enc}")))
    } else if cfg!(feature = "decompression") && enc.eq_ignore_ascii_case("zstd") {
        #[cfg(feature = "decompression")]
        return decompress_zstd(data);
        #[cfg(not(feature = "decompression"))]
        Err(Error::Http(format!("unsupported Content-Encoding: {enc}")))
    } else if enc.eq_ignore_ascii_case("identity") {
        Ok(data.to_vec())
    } else {
        Err(Error::Http(format!("unsupported Content-Encoding: {enc}")))
    }
}

/// Returns the Accept-Encoding header value for what we can decompress.
#[must_use]
pub const fn accepted_encodings() -> &'static str {
    #[cfg(feature = "decompression")]
    {
        "gzip, deflate, br, zstd"
    }
    #[cfg(not(feature = "decompression"))]
    {
        "gzip, deflate"
    }
}

/// Decompress gzip data.
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read;

    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut buf = Vec::new();
    let _n = decoder
        .read_to_end(&mut buf)
        .map_err(|e| Error::Http(format!("gzip decompression failed: {e}")))?;
    Ok(buf)
}

/// Decompress raw deflate data.
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read;

    // Try raw deflate first, then zlib-wrapped deflate (curl does the same)
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut buf = Vec::new();
    if decoder.read_to_end(&mut buf).is_ok() {
        Ok(buf)
    } else {
        // Retry with zlib wrapper
        let mut decoder = flate2::read::ZlibDecoder::new(data);
        let mut buf = Vec::new();
        let _n = decoder
            .read_to_end(&mut buf)
            .map_err(|e| Error::Http(format!("deflate decompression failed: {e}")))?;
        Ok(buf)
    }
}

/// Decompress brotli data.
#[cfg(feature = "decompression")]
fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read;

    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut buf = Vec::new();
    let _n = decoder
        .read_to_end(&mut buf)
        .map_err(|e| Error::Http(format!("brotli decompression failed: {e}")))?;
    Ok(buf)
}

/// Decompress zstd data.
#[cfg(feature = "decompression")]
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read;

    let mut decoder = zstd::Decoder::new(data)
        .map_err(|e| Error::Http(format!("zstd decoder init failed: {e}")))?;
    let mut buf = Vec::new();
    let _n = decoder
        .read_to_end(&mut buf)
        .map_err(|e| Error::Http(format!("zstd decompression failed: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn identity_passthrough() {
        let data = b"hello world";
        let result = decompress(data, "identity").unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"hello gzip world";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress(&compressed, "gzip").unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn deflate_roundtrip() {
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let original = b"hello deflate world";
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress(&compressed, "deflate").unwrap();
        assert_eq!(result, original);
    }

    #[cfg(feature = "decompression")]
    #[test]
    fn brotli_roundtrip() {
        use brotli::enc::BrotliEncoderParams;
        use std::io::Write;

        let original = b"hello brotli world";
        let mut compressed = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::with_params(
                &mut compressed,
                4096,
                &BrotliEncoderParams::default(),
            );
            encoder.write_all(original).unwrap();
        }

        let result = decompress(&compressed, "br").unwrap();
        assert_eq!(result, original);
    }

    #[cfg(feature = "decompression")]
    #[test]
    fn zstd_roundtrip() {
        let original = b"hello zstd world";
        let compressed = zstd::encode_all(&original[..], 3).unwrap();

        let result = decompress(&compressed, "zstd").unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn unsupported_encoding_returns_error() {
        let result = decompress(b"data", "unknown");
        assert!(result.is_err());
    }

    #[test]
    fn x_gzip_alias() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"test x-gzip";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress(&compressed, "x-gzip").unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn accepted_encodings_includes_gzip() {
        let enc = accepted_encodings();
        assert!(enc.contains("gzip"));
        assert!(enc.contains("deflate"));
    }
}
