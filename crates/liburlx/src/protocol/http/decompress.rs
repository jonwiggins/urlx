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
    fn broken_deflate_test223_returns_error() {
        // Full 412-byte payload from curl test 223: deflate stream with three
        // bytes removed from the beginning, then cut short. Both raw deflate
        // and zlib decoding must fail on this data.
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x58, 0xdb, 0x6e, 0xe3, 0x36, 0x10, 0x7d, 0x37, 0x90, 0x7f, 0x60, 0xfd,
            0xd4, 0x02, 0xb6, 0x6e, 0xb6, 0x13, 0x39, 0x70, 0xb4, 0x28, 0x72, 0xd9,
            0x04, 0xcd, 0x36, 0xc1, 0xda, 0x05, 0xba, 0x4f, 0x06, 0x2d, 0xd1, 0x36,
            0x1b, 0x49, 0x14, 0x48, 0xca, 0xb9, 0x3c, 0xf4, 0xdb, 0x3b, 0x94, 0x28,
            0x89, 0xb1, 0x1c, 0xaf, 0x77, 0x83, 0xbe, 0x04, 0x48, 0x62, 0x72, 0xe6,
            0x9c, 0xc3, 0xe1, 0x0c, 0x49, 0x93, 0x99, 0x7c, 0x7a, 0x4a, 0x62, 0xb4,
            0x21, 0x5c, 0x50, 0x96, 0x9e, 0x75, 0x5d, 0xcb, 0xe9, 0x22, 0x92, 0x86,
            0x2c, 0xa2, 0xe9, 0xea, 0xac, 0x7b, 0x33, 0xbd, 0xeb, 0xfb, 0xfe, 0x68,
            0xdc, 0x77, 0xbb, 0x9f, 0x82, 0xce, 0xe4, 0x97, 0x8b, 0xbb, 0xf3, 0xd9,
            0xb7, 0xfb, 0x4b, 0x94, 0x71, 0xf6, 0x0f, 0x09, 0x65, 0x3f, 0xa6, 0x42,
            0x02, 0x10, 0x4d, 0xbf, 0x4d, 0x67, 0x97, 0x5f, 0x50, 0x77, 0x2d, 0x65,
            0x76, 0x6a, 0xdb, 0x4b, 0x4e, 0xc4, 0x3a, 0x21, 0x58, 0x5a, 0x29, 0x91,
            0xf6, 0x02, 0x87, 0x0f, 0x24, 0x8d, 0xec, 0x65, 0xd2, 0xd7, 0x3c, 0xd1,
            0x77, 0xac, 0xa1, 0x15, 0xc9, 0xa8, 0x0b, 0xa2, 0x5b, 0x5a, 0x41, 0x07,
            0xa1, 0xca, 0xa6, 0xda, 0x4d, 0x6f, 0x4e, 0xa3, 0xc0, 0x3d, 0x76, 0xbd,
            0x89, 0x6d, 0x18, 0x4a, 0x44, 0x84, 0x25, 0x99, 0xe3, 0x28, 0x22, 0x80,
            0x18, 0x8f, 0xfd, 0xbe, 0xe3, 0xf7, 0x3d, 0x17, 0x39, 0xc3, 0x53, 0xc7,
            0x3d, 0xf5, 0xc6, 0x13, 0xdb, 0xf0, 0x1b, 0x84, 0x3c, 0x53, 0x1f, 0x51,
            0xe0, 0x39, 0xce, 0xb0, 0xef, 0x3a, 0x7d, 0xd7, 0x47, 0x8e, 0x77, 0xea,
            0xc1, 0xcf, 0x40, 0x53, 0x2a, 0xc4, 0xab, 0x38, 0x52, 0x9c, 0x90, 0xb9,
            0x58, 0x33, 0x2e, 0x83, 0x30, 0xe7, 0x71, 0x1d, 0x8e, 0x61, 0x6f, 0xe3,
            0x97, 0x79, 0x1c, 0x17, 0x70, 0x84, 0xd3, 0x08, 0xc5, 0x74, 0xd1, 0xa6,
            0x16, 0x10, 0x1d, 0x1e, 0x11, 0xa1, 0x96, 0x3a, 0x67, 0x49, 0x52, 0x52,
            0x52, 0x82, 0x24, 0x63, 0xb5, 0x00, 0xc7, 0xfc, 0x19, 0x2d, 0x19, 0x47,
            0x61, 0x4c, 0x49, 0x2a, 0xfb, 0x82, 0x46, 0x04, 0xfd, 0xf5, 0xf5, 0x16,
            0x49, 0x8e, 0x53, 0xb1, 0x84, 0x8a, 0x5a, 0x30, 0x8b, 0x46, 0xc8, 0x50,
            0xde, 0x19, 0x0c, 0xa2, 0x02, 0xe1, 0x72, 0x04, 0xa5, 0x5a, 0xa9, 0x70,
            0x55, 0xdf, 0x25, 0x8d, 0x89, 0x38, 0xea, 0xe4, 0x42, 0x75, 0xd4, 0x18,
            0xe2, 0x39, 0x95, 0xf8, 0xc9, 0x42, 0x37, 0x12, 0x89, 0x3c, 0xcb, 0x40,
            0x5f, 0xa0, 0xeb, 0xd9, 0xec, 0xbe, 0x57, 0xfc, 0x9d, 0xf6, 0xd0, 0x15,
            0xb4, 0x8f, 0x3a, 0x57, 0x45, 0xfb, 0xe2, 0xe6, 0x7c, 0xd6, 0x43, 0xb3,
            0xcb, 0xdb, 0x3f, 0x2f, 0xe1, 0xf3, 0xf6, 0xe2, 0x77, 0x80, 0x5d, 0xdd,
            0xdc, 0x5e, 0xf6, 0x8a, 0xe1, 0x3f, 0xdf, 0xdd, 0x5f, 0x5f, 0x7e, 0x85,
            0x36, 0x0c, 0xf0, 0x48, 0x62, 0x88, 0xa9, 0x94, 0xea, 0x67, 0x4c, 0xc8,
            0x9e, 0x6e, 0xe6, 0xd0,
        ];
        assert_eq!(data.len(), 412);
        assert!(
            decompress(data, "deflate").is_err(),
            "broken deflate from test 223 must fail decompression"
        );
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
