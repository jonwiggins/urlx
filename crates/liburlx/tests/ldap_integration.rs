//! Integration tests for the LDAP/LDAPS protocol handler.
//!
//! These tests stand up a minimal mock LDAP server that speaks the
//! binary BER protocol over TCP, then exercise `liburlx::protocol::ldap::search()`
//! against it covering anonymous bind, authenticated bind, filter types,
//! scopes, attribute selection, LDAPS (TLS), STARTTLS, and error paths.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ─────────────────────── Minimal BER helpers ───────────────────────

mod ber_helpers {
    use tokio::io::AsyncReadExt;

    /// Encode BER length.
    #[allow(clippy::cast_possible_truncation)]
    pub fn encode_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    pub fn encode_integer(value: i32) -> Vec<u8> {
        #[allow(clippy::cast_sign_loss)]
        if (0..=0x7F).contains(&value) {
            vec![0x02, 0x01, value as u8]
        } else {
            let hi = (value >> 8) as u8;
            let lo = (value & 0xFF) as u8;
            vec![0x02, 0x02, hi, lo]
        }
    }

    pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend(encode_length(data.len()));
        out.extend_from_slice(data);
        out
    }

    pub fn encode_enumerated(value: u8) -> Vec<u8> {
        vec![0x0A, 0x01, value]
    }

    pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        out.extend(encode_length(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// Wrap content with an APPLICATION tag (constructed, 0x60 | tag).
    pub fn encode_application(tag_num: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![0x60 | tag_num];
        out.extend(encode_length(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// Read a full BER message from a stream (tag + length + content).
    pub async fn read_message<S: AsyncReadExt + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).await?;
        let mut first = [0u8; 1];
        s.read_exact(&mut first).await?;
        let (content_len, extra) = if first[0] < 0x80 {
            (first[0] as usize, 0usize)
        } else {
            let n = (first[0] & 0x7F) as usize;
            let mut buf = vec![0u8; n];
            s.read_exact(&mut buf).await?;
            let mut len = 0usize;
            for &b in &buf {
                len = (len << 8) | b as usize;
            }
            (len, n)
        };
        let mut msg = Vec::with_capacity(2 + extra + content_len);
        msg.push(tag[0]);
        msg.push(first[0]);
        if extra > 0 {
            let start = msg.len();
            msg.resize(start + extra, 0);
            let mut rem = content_len;
            #[allow(clippy::cast_possible_truncation)]
            for i in (0..extra).rev() {
                msg[start + i] = (rem & 0xFF) as u8;
                rem >>= 8;
            }
        }
        let cs = msg.len();
        msg.resize(cs + content_len, 0);
        s.read_exact(&mut msg[cs..]).await?;
        Ok(msg)
    }

    /// Decode a BER length; returns (length, bytes_consumed).
    pub fn decode_length(data: &[u8]) -> (usize, usize) {
        if data[0] < 0x80 {
            (data[0] as usize, 1)
        } else {
            let n = (data[0] & 0x7F) as usize;
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | data[1 + i] as usize;
            }
            (len, 1 + n)
        }
    }

    /// Decode a TLV element; returns (tag, value_bytes, total_consumed).
    pub fn decode_tlv(data: &[u8]) -> (u8, Vec<u8>, usize) {
        let tag = data[0];
        let (len, lsz) = decode_length(&data[1..]);
        let total = 1 + lsz + len;
        (tag, data[1 + lsz..total].to_vec(), total)
    }

    /// Decode an INTEGER from data; returns (value, consumed).
    pub fn decode_integer(data: &[u8]) -> (i64, usize) {
        assert_eq!(data[0], 0x02, "expected INTEGER tag");
        let (len, lsz) = decode_length(&data[1..]);
        let total = 1 + lsz + len;
        let vb = &data[1 + lsz..total];
        let mut val: i64 = if !vb.is_empty() && vb[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in vb {
            val = (val << 8) | i64::from(b);
        }
        (val, total)
    }

    // ─── Response builders ───

    /// Build a BindResponse (APPLICATION 1, tag 0x61).
    pub fn build_bind_response(message_id: i32, result_code: u8) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(encode_enumerated(result_code));
        content.extend(encode_octet_string(b"")); // matchedDN
        content.extend(encode_octet_string(b"")); // diagnosticMessage
        let bind_resp = encode_application(1, &content);
        let mut msg = Vec::new();
        msg.extend(encode_integer(message_id));
        msg.extend(bind_resp);
        encode_sequence(&msg)
    }

    /// Build a SearchResultEntry (APPLICATION 4, tag 0x64).
    pub fn build_search_result_entry(
        message_id: i32,
        dn: &str,
        attributes: &[(&str, &[&[u8]])],
    ) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(encode_octet_string(dn.as_bytes()));

        let mut attrs_content = Vec::new();
        for &(name, values) in attributes {
            let mut attr_content = Vec::new();
            attr_content.extend(encode_octet_string(name.as_bytes()));
            let mut val_set_content = Vec::new();
            for val in values {
                val_set_content.extend(encode_octet_string(val));
            }
            // SET tag = 0x31
            let mut set = vec![0x31];
            set.extend(encode_length(val_set_content.len()));
            set.extend(val_set_content);
            attr_content.extend(set);
            attrs_content.extend(encode_sequence(&attr_content));
        }
        content.extend(encode_sequence(&attrs_content));

        let entry = encode_application(4, &content);
        let mut msg = Vec::new();
        msg.extend(encode_integer(message_id));
        msg.extend(entry);
        encode_sequence(&msg)
    }

    /// Build a SearchResultDone (APPLICATION 5, tag 0x65).
    pub fn build_search_result_done(message_id: i32, result_code: u8) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(encode_enumerated(result_code));
        content.extend(encode_octet_string(b"")); // matchedDN
        content.extend(encode_octet_string(b"")); // diagnosticMessage
        let done = encode_application(5, &content);
        let mut msg = Vec::new();
        msg.extend(encode_integer(message_id));
        msg.extend(done);
        encode_sequence(&msg)
    }

    /// Build an ExtendedResponse (APPLICATION 24, tag 0x78).
    pub fn build_extended_response(message_id: i32, result_code: u8) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(encode_enumerated(result_code));
        content.extend(encode_octet_string(b"")); // matchedDN
        content.extend(encode_octet_string(b"")); // diagnosticMessage
        let resp = encode_application(24, &content);
        let mut msg = Vec::new();
        msg.extend(encode_integer(message_id));
        msg.extend(resp);
        encode_sequence(&msg)
    }
}

use ber_helpers::*;

// ─────────────────────── Mock LDAP Server ───────────────────────

/// An LDAP attribute: (name, [values]).
type LdapAttr = (String, Vec<Vec<u8>>);

/// An LDAP entry: (dn, [attributes]).
type LdapEntry = (String, Vec<LdapAttr>);

/// Configuration for the mock LDAP server.
#[derive(Clone, Default)]
struct MockLdapConfig {
    /// Entries returned by search.
    entries: Vec<LdapEntry>,
    /// Result code to return for bind (0 = success).
    bind_result_code: u8,
    /// Result code to return for search done (0 = success).
    search_result_code: u8,
    /// Whether to support STARTTLS.
    support_starttls: bool,
    /// TLS config for STARTTLS or LDAPS.
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    /// Whether this is an implicit-TLS (LDAPS) server.
    implicit_tls: bool,
}

/// Start a mock LDAP server, returning the port it's listening on.
async fn start_mock_ldap(config: MockLdapConfig) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(config);

    tokio::spawn(async move {
        // Accept one connection
        let (tcp, _) = listener.accept().await.unwrap();
        handle_ldap_connection(tcp, &config).await;
    });

    port
}

async fn handle_ldap_connection(tcp: tokio::net::TcpStream, config: &MockLdapConfig) {
    if config.implicit_tls {
        if let Some(ref acceptor) = config.tls_acceptor {
            let tls_stream = acceptor.accept(tcp).await.unwrap();
            handle_ldap_protocol(tls_stream, config).await;
        }
    } else {
        handle_ldap_protocol_with_starttls(tcp, config).await;
    }
}

/// Handle LDAP protocol over a stream that might upgrade to TLS via STARTTLS.
async fn handle_ldap_protocol_with_starttls(
    mut stream: tokio::net::TcpStream,
    config: &MockLdapConfig,
) {
    // Read first message
    let msg = read_message(&mut stream).await.unwrap();
    let (_tag, msg_content, _) = decode_tlv(&msg);
    let (msg_id, id_len) = decode_integer(&msg_content);
    let rest = &msg_content[id_len..];
    let (op_tag, _op_value, _) = decode_tlv(rest);

    // Check if first message is ExtendedRequest for STARTTLS (APPLICATION 23, tag 0x77)
    if op_tag == 0x77 && config.support_starttls {
        // Send ExtendedResponse success
        #[allow(clippy::cast_possible_truncation)]
        let resp = build_extended_response(msg_id as i32, 0);
        stream.write_all(&resp).await.unwrap();
        stream.flush().await.unwrap();

        // Upgrade to TLS
        if let Some(ref acceptor) = config.tls_acceptor {
            let tls_stream = acceptor.accept(stream).await.unwrap();
            handle_ldap_protocol(tls_stream, config).await;
        }
    } else if op_tag == 0x77 && !config.support_starttls {
        // STARTTLS not supported — send failure
        #[allow(clippy::cast_possible_truncation)]
        let resp = build_extended_response(msg_id as i32, 2); // protocolError
        stream.write_all(&resp).await.unwrap();
        stream.flush().await.unwrap();
        // Continue as plain LDAP — read next message (bind)
        handle_ldap_bind_and_search(&mut stream, config).await;
    } else if op_tag == 0x60 {
        // It's a BindRequest directly (no STARTTLS attempted)
        #[allow(clippy::cast_possible_truncation)]
        handle_ldap_after_bind(&mut stream, config, msg_id as i32, &_op_value).await;
    }
}

/// Handle the LDAP bind response and search after bind.
async fn handle_ldap_bind_and_search<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    config: &MockLdapConfig,
) {
    let msg = read_message(stream).await.unwrap();
    let (_tag, msg_content, _) = decode_tlv(&msg);
    let (msg_id, id_len) = decode_integer(&msg_content);
    let rest = &msg_content[id_len..];
    let (op_tag, op_value, _) = decode_tlv(rest);

    if op_tag == 0x60 {
        // BindRequest
        #[allow(clippy::cast_possible_truncation)]
        handle_ldap_after_bind(stream, config, msg_id as i32, &op_value).await;
    }
}

/// Handle a BindRequest that was already read (op_value has the bind content).
async fn handle_ldap_after_bind<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    config: &MockLdapConfig,
    msg_id: i32,
    _bind_content: &[u8],
) {
    // Send BindResponse
    let resp = build_bind_response(msg_id, config.bind_result_code);
    stream.write_all(&resp).await.unwrap();
    stream.flush().await.unwrap();

    if config.bind_result_code != 0 {
        return;
    }

    // Read SearchRequest
    let msg = read_message(stream).await.unwrap();
    let (_tag, msg_content, _) = decode_tlv(&msg);
    let (search_msg_id, _id_len) = decode_integer(&msg_content);

    // Send entries
    #[allow(clippy::cast_possible_truncation)]
    let sid = search_msg_id as i32;
    for (dn, attrs) in &config.entries {
        let attr_refs: Vec<(&str, &[&[u8]])> = attrs
            .iter()
            .map(|(name, vals)| {
                let val_refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
                // Leak is fine in tests
                let leaked: &[&[u8]] = Box::leak(val_refs.into_boxed_slice());
                (name.as_str(), leaked)
            })
            .collect();
        let entry = build_search_result_entry(sid, dn, &attr_refs);
        stream.write_all(&entry).await.unwrap();
    }

    // Send SearchResultDone
    let done = build_search_result_done(sid, config.search_result_code);
    stream.write_all(&done).await.unwrap();
    stream.flush().await.unwrap();

    // Client may send unbind — we just close
}

/// Handle LDAP protocol (bind + search) on any async stream.
async fn handle_ldap_protocol<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    config: &MockLdapConfig,
) {
    handle_ldap_bind_and_search(&mut stream, config).await;
}

// ─────────────────────── TLS helpers ───────────────────────

fn generate_test_tls_acceptor() -> Arc<tokio_rustls::TlsAcceptor> {
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = cert_params.self_signed(&key).unwrap();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();

    Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

fn make_insecure_tls_config() -> liburlx::tls::TlsConfig {
    liburlx::tls::TlsConfig { verify_peer: false, verify_host: false, ..Default::default() }
}

// ─────────────────────── Tests ───────────────────────

/// Helper to run an LDAP search against a mock server.
async fn do_ldap_search(
    port: u16,
    url_path: &str,
    use_tls: bool,
    use_ssl: liburlx::protocol::ftp::UseSsl,
) -> Result<liburlx::protocol::http::response::Response, liburlx::Error> {
    let scheme = if use_tls { "ldaps" } else { "ldap" };
    let url_str = format!("{scheme}://localhost:{port}{url_path}");
    let url = liburlx::url::Url::parse(&url_str).unwrap();
    let tls_config = make_insecure_tls_config();
    liburlx::protocol::ldap::search(&url, &tls_config, use_tls, use_ssl).await
}

// ── Anonymous bind + search ──

#[tokio::test]
async fn ldap_anonymous_bind_and_search() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Alice,dc=example,dc=com".to_string(),
            vec![
                ("cn".to_string(), vec![b"Alice".to_vec()]),
                ("mail".to_string(), vec![b"alice@example.com".to_vec()]),
            ],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn,mail?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Alice,dc=example,dc=com"));
    assert!(body.contains("\tcn: Alice"));
    assert!(body.contains("\tmail: alice@example.com"));
}

// ── Authenticated bind ──

#[tokio::test]
async fn ldap_authenticated_bind_and_search() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Bob,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Bob".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let url_str = format!("ldap://admin:secret@localhost:{port}/dc=example,dc=com?cn?sub?(cn=Bob)");
    let url = liburlx::url::Url::parse(&url_str).unwrap();
    let tls_config = make_insecure_tls_config();
    let resp = liburlx::protocol::ldap::search(
        &url,
        &tls_config,
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Bob,dc=example,dc=com"));
    assert!(body.contains("\tcn: Bob"));
}

// ── Multiple entries ──

#[tokio::test]
async fn ldap_multiple_entries() {
    let config = MockLdapConfig {
        entries: vec![
            (
                "cn=Alice,dc=example,dc=com".to_string(),
                vec![("cn".to_string(), vec![b"Alice".to_vec()])],
            ),
            (
                "cn=Bob,dc=example,dc=com".to_string(),
                vec![("cn".to_string(), vec![b"Bob".to_vec()])],
            ),
        ],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Alice,dc=example,dc=com"));
    assert!(body.contains("DN: cn=Bob,dc=example,dc=com"));
}

// ── Multi-valued attributes ──

#[tokio::test]
async fn ldap_multi_valued_attributes() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Group,dc=example,dc=com".to_string(),
            vec![(
                "member".to_string(),
                vec![b"cn=Alice".to_vec(), b"cn=Bob".to_vec(), b"cn=Charlie".to_vec()],
            )],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?member?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("\tmember: cn=Alice"));
    assert!(body.contains("\tmember: cn=Bob"));
    assert!(body.contains("\tmember: cn=Charlie"));
}

// ── Binary attribute values (base64 encoded) ──

#[tokio::test]
async fn ldap_binary_attribute_base64() {
    let binary_data: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Cert,dc=example,dc=com".to_string(),
            vec![("userCertificate".to_string(), vec![binary_data])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?userCertificate?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    // Binary values should be base64-encoded
    assert!(body.contains("\tuserCertificate: AAEC//79"));
}

// ── Empty search results ──

#[tokio::test]
async fn ldap_empty_search_results() {
    let config = MockLdapConfig::default();
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com??sub?(cn=nonexistent)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.is_empty());
}

// ── Scope variations ──

#[tokio::test]
async fn ldap_scope_base() {
    let config = MockLdapConfig {
        entries: vec![(
            "dc=example,dc=com".to_string(),
            vec![("dc".to_string(), vec![b"example".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    // base scope (default when no scope specified)
    let resp =
        do_ldap_search(port, "/dc=example,dc=com?dc", false, liburlx::protocol::ftp::UseSsl::None)
            .await
            .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: dc=example,dc=com"));
}

#[tokio::test]
async fn ldap_scope_one() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?one?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Test,dc=example,dc=com"));
}

#[tokio::test]
async fn ldap_scope_sub() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Deep,ou=Users,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Deep".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Deep,ou=Users,dc=example,dc=com"));
}

// ── Error: bad bind credentials ──

#[tokio::test]
async fn ldap_bind_failure() {
    let config = MockLdapConfig {
        bind_result_code: 49, // invalidCredentials
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let result =
        do_ldap_search(port, "/dc=example,dc=com", false, liburlx::protocol::ftp::UseSsl::None)
            .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    assert!(err_str.contains("bind failed"), "Expected bind error, got: {err_str}");
}

// ── Error: search failure ──

#[tokio::test]
async fn ldap_search_failure() {
    let config = MockLdapConfig {
        search_result_code: 32, // noSuchObject
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let result = do_ldap_search(
        port,
        "/dc=nonexistent?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    assert!(err_str.contains("search failed"), "Expected search error, got: {err_str}");
}

// ── Search result code 4 (sizeLimitExceeded) is not an error ──

#[tokio::test]
async fn ldap_size_limit_exceeded_is_ok() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test".to_vec()])],
        )],
        search_result_code: 4, // sizeLimitExceeded
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Test,dc=example,dc=com"));
}

// ── LDAPS (implicit TLS) ──

#[tokio::test]
async fn ldaps_implicit_tls() {
    let acceptor = generate_test_tls_acceptor();
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Secure,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Secure".to_vec()])],
        )],
        implicit_tls: true,
        tls_acceptor: Some(acceptor),
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        true,
        liburlx::protocol::ftp::UseSsl::All,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Secure,dc=example,dc=com"));
    assert!(body.contains("\tcn: Secure"));
}

// ── STARTTLS ──

#[tokio::test]
async fn ldap_starttls_required() {
    let acceptor = generate_test_tls_acceptor();
    let config = MockLdapConfig {
        entries: vec![(
            "cn=StartTls,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"StartTls".to_vec()])],
        )],
        support_starttls: true,
        tls_acceptor: Some(acceptor),
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    // use_ssl=All means STARTTLS is required
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::All,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=StartTls,dc=example,dc=com"));
    assert!(body.contains("\tcn: StartTls"));
}

#[tokio::test]
async fn ldap_starttls_try_mode() {
    let acceptor = generate_test_tls_acceptor();
    let config = MockLdapConfig {
        entries: vec![(
            "cn=TryTls,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"TryTls".to_vec()])],
        )],
        support_starttls: true,
        tls_acceptor: Some(acceptor),
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    // use_ssl=Try means opportunistic STARTTLS
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::Try,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=TryTls,dc=example,dc=com"));
}

// ── STARTTLS not supported — Try mode falls back to plain ──

#[tokio::test]
async fn ldap_starttls_try_fallback_to_plain() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Plain,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Plain".to_vec()])],
        )],
        support_starttls: false,
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    // use_ssl=Try — server doesn't support STARTTLS, should fall back to plain
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::Try,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();
    assert!(body.contains("DN: cn=Plain,dc=example,dc=com"));
}

// ── STARTTLS not supported — All mode fails ──

#[tokio::test]
async fn ldap_starttls_required_but_not_supported() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Fail,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Fail".to_vec()])],
        )],
        support_starttls: false,
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let result = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::All,
    )
    .await;
    assert!(result.is_err(), "Expected error when STARTTLS required but not supported");
}

// ── Output format verification ──

#[tokio::test]
async fn ldap_output_format_matches_curl() {
    let config = MockLdapConfig {
        entries: vec![
            (
                "cn=John Doe,ou=Users,dc=example,dc=com".to_string(),
                vec![
                    ("cn".to_string(), vec![b"John Doe".to_vec()]),
                    ("mail".to_string(), vec![b"john@example.com".to_vec()]),
                    ("sn".to_string(), vec![b"Doe".to_vec()]),
                ],
            ),
            (
                "cn=Jane Doe,ou=Users,dc=example,dc=com".to_string(),
                vec![
                    ("cn".to_string(), vec![b"Jane Doe".to_vec()]),
                    ("mail".to_string(), vec![b"jane@example.com".to_vec()]),
                ],
            ),
        ],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn,mail,sn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(resp.body().to_vec()).unwrap();

    // curl formats LDAP output as:
    // DN: <dn>\n
    // \t<attr>: <value>\n
    // \n  (blank line between entries)
    assert!(body.contains("DN: cn=John Doe,ou=Users,dc=example,dc=com\n"));
    assert!(body.contains("\tcn: John Doe\n"));
    assert!(body.contains("\tmail: john@example.com\n"));
    assert!(body.contains("\tsn: Doe\n"));
    assert!(body.contains("DN: cn=Jane Doe,ou=Users,dc=example,dc=com\n"));
    assert!(body.contains("\tcn: Jane Doe\n"));
    assert!(body.contains("\tmail: jane@example.com\n"));

    // Entries separated by blank line
    assert!(body.contains("\n\nDN: cn=Jane Doe"));
}

// ── Connection refused ──

#[tokio::test]
async fn ldap_connection_refused() {
    // Use a port where nothing is listening
    let url_str = "ldap://localhost:1/dc=example,dc=com";
    let url = liburlx::url::Url::parse(url_str).unwrap();
    let tls_config = make_insecure_tls_config();
    let result = liburlx::protocol::ldap::search(
        &url,
        &tls_config,
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await;
    assert!(result.is_err());
}

// ── Content-Length header in response ──

#[tokio::test]
async fn ldap_response_has_content_length() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(objectClass=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    let content_length = resp.headers().get("content-length").unwrap();
    let cl: usize = content_length.parse().unwrap();
    assert_eq!(cl, resp.body().len());
}

// ── Filter expression types ──

#[tokio::test]
async fn ldap_filter_equality() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(cn=Test)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    assert!(!resp.body().is_empty());
}

#[tokio::test]
async fn ldap_filter_and() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![
                ("cn".to_string(), vec![b"Test".to_vec()]),
                ("sn".to_string(), vec![b"User".to_vec()]),
            ],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn,sn?sub?(%26(cn=Test)(sn=User))",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    assert!(!resp.body().is_empty());
}

#[tokio::test]
async fn ldap_filter_or() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(|(cn=Test)(cn=Other))",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    assert!(!resp.body().is_empty());
}

#[tokio::test]
async fn ldap_filter_not() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(!(cn=Other))",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    assert!(!resp.body().is_empty());
}

#[tokio::test]
async fn ldap_filter_substring() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test User,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test User".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(cn=*User*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    assert!(!resp.body().is_empty());
}

#[tokio::test]
async fn ldap_filter_presence() {
    let config = MockLdapConfig {
        entries: vec![(
            "cn=Test,dc=example,dc=com".to_string(),
            vec![("cn".to_string(), vec![b"Test".to_vec()])],
        )],
        ..Default::default()
    };
    let port = start_mock_ldap(config).await;
    let resp = do_ldap_search(
        port,
        "/dc=example,dc=com?cn?sub?(cn=*)",
        false,
        liburlx::protocol::ftp::UseSsl::None,
    )
    .await
    .unwrap();
    assert!(!resp.body().is_empty());
}
