//! DICT protocol handler.
//!
//! Implements the DICT protocol (RFC 2229) for dictionary lookups.
//! Supports DEFINE and MATCH commands.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::Error;
use crate::protocol::http::response::Response;

/// Read a DICT response status line.
///
/// DICT responses start with a 3-digit status code.
///
/// # Errors
///
/// Returns an error if the connection drops.
async fn read_status<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<(u16, String), Error> {
    let mut line = String::new();
    let bytes_read = stream
        .read_line(&mut line)
        .await
        .map_err(|e| Error::Http(format!("DICT read error: {e}")))?;

    if bytes_read == 0 {
        return Err(Error::Http("DICT connection closed unexpectedly".to_string()));
    }

    let trimmed = line.trim();
    if trimmed.len() < 3 {
        return Err(Error::Http(format!("DICT response too short: {trimmed}")));
    }

    let code = trimmed[..3]
        .parse::<u16>()
        .map_err(|_| Error::Http(format!("DICT invalid status code: {trimmed}")))?;
    let message = if trimmed.len() > 4 { trimmed[4..].to_string() } else { String::new() };

    Ok((code, message))
}

/// Read a text block terminated by `.` on its own line.
///
/// # Errors
///
/// Returns an error if the connection drops.
async fn read_text_block<S: AsyncRead + Unpin>(stream: &mut BufReader<S>) -> Result<String, Error> {
    let mut result = String::new();

    loop {
        let mut line = String::new();
        let bytes_read = stream
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Http(format!("DICT read error: {e}")))?;

        if bytes_read == 0 {
            return Err(Error::Http("DICT connection closed during text block".to_string()));
        }

        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed == "." {
            break;
        }

        let content = trimmed.strip_prefix('.').unwrap_or(trimmed);
        result.push_str(content);
        result.push('\n');
    }

    Ok(result)
}

/// Send a DICT command.
///
/// # Errors
///
/// Returns an error if the write fails.
async fn send_command<S: AsyncWrite + Unpin>(stream: &mut S, command: &str) -> Result<(), Error> {
    let cmd = format!("{command}\r\n");
    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| Error::Http(format!("DICT write error: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("DICT flush error: {e}")))?;
    Ok(())
}

/// Look up a word using the DICT protocol.
///
/// URL format: `dict://host:port/d:word:database`
///
/// - `d:word` — define a word (default database: `*`)
/// - `m:word` — match a word
///
/// # Errors
///
/// Returns an error if the lookup fails.
pub async fn lookup(url: &crate::url::Url) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let path = url.path().trim_start_matches('/');

    // Parse the DICT URL path: d:word:database or m:word:database
    let (command, word, database) = parse_dict_path(path)?;

    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    let (reader, mut writer) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader);

    // Read server banner
    let (code, _) = read_status(&mut reader).await?;
    if code != 220 {
        return Err(Error::Http(format!("DICT server rejected connection: {code}")));
    }

    let mut result = String::new();

    match command {
        "d" | "define" => {
            send_command(&mut writer, &format!("DEFINE {database} {word}")).await?;

            // Read definition responses
            loop {
                let (code, _msg) = read_status(&mut reader).await?;
                match code {
                    150 => {
                        // N definitions found
                    }
                    151 => {
                        // Definition follows
                        let text = read_text_block(&mut reader).await?;
                        result.push_str(&text);
                        result.push('\n');
                    }
                    250 => break, // ok
                    552 => {
                        // No match
                        break;
                    }
                    _ => {
                        return Err(Error::Http(format!("DICT error: code {code}")));
                    }
                }
            }
        }
        "m" | "match" => {
            send_command(&mut writer, &format!("MATCH {database} . {word}")).await?;

            loop {
                let (code, _msg) = read_status(&mut reader).await?;
                match code {
                    152 => {
                        let text = read_text_block(&mut reader).await?;
                        result.push_str(&text);
                    }
                    250 | 552 => break,
                    _ => {
                        return Err(Error::Http(format!("DICT error: code {code}")));
                    }
                }
            }
        }
        _ => {
            return Err(Error::Http(format!("DICT unknown command: {command}")));
        }
    }

    // QUIT
    send_command(&mut writer, "QUIT").await?;

    let body = result.into_bytes();
    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), body.len().to_string());

    Ok(Response::new(200, headers, body, url.as_str().to_string()))
}

/// Parse a DICT URL path into (command, word, database).
///
/// Format: `command:word[:database]`
///
/// # Errors
///
/// Returns an error if the path is malformed.
fn parse_dict_path(path: &str) -> Result<(&str, &str, &str), Error> {
    let parts: Vec<&str> = path.splitn(3, ':').collect();

    match parts.len() {
        1 => Ok(("d", parts[0], "*")),
        2 => Ok((parts[0], parts[1], "*")),
        3.. => Ok((parts[0], parts[1], parts[2])),
        _ => Err(Error::Http("DICT URL path is empty".to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_dict_path_full() {
        let (cmd, word, db) = parse_dict_path("d:hello:english").unwrap();
        assert_eq!(cmd, "d");
        assert_eq!(word, "hello");
        assert_eq!(db, "english");
    }

    #[test]
    fn parse_dict_path_no_db() {
        let (cmd, word, db) = parse_dict_path("d:hello").unwrap();
        assert_eq!(cmd, "d");
        assert_eq!(word, "hello");
        assert_eq!(db, "*");
    }

    #[test]
    fn parse_dict_path_word_only() {
        let (cmd, word, db) = parse_dict_path("hello").unwrap();
        assert_eq!(cmd, "d");
        assert_eq!(word, "hello");
        assert_eq!(db, "*");
    }

    #[test]
    fn parse_dict_path_match() {
        let (cmd, word, db) = parse_dict_path("m:test:*").unwrap();
        assert_eq!(cmd, "m");
        assert_eq!(word, "test");
        assert_eq!(db, "*");
    }

    #[tokio::test]
    async fn read_status_ok() {
        let data = b"220 dictd ready\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let (code, msg) = read_status(&mut reader).await.unwrap();
        assert_eq!(code, 220);
        assert_eq!(msg, "dictd ready");
    }

    #[tokio::test]
    async fn read_text_block_basic() {
        let data = b"hello world\r\nfoo bar\r\n.\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let text = read_text_block(&mut reader).await.unwrap();
        assert!(text.contains("hello world"));
        assert!(text.contains("foo bar"));
    }

    #[tokio::test]
    async fn read_text_block_dot_stuffing() {
        let data = b"..starts with dot\r\nnormal\r\n.\r\n";
        let mut reader = BufReader::new(std::io::Cursor::new(data.to_vec()));
        let text = read_text_block(&mut reader).await.unwrap();
        assert!(text.contains(".starts with dot"));
    }
}
