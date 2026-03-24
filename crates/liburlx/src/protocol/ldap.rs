//! LDAP/LDAPS protocol handler.
//!
//! Implements the LDAP protocol (RFC 4511) for directory lookups using
//! ASN.1 BER encoding over TCP. Supports both plaintext (`ldap://`) and
//! TLS-encrypted (`ldaps://`) connections.
//!
//! LDAP URL format (RFC 4516):
//! `ldap://host:port/dn?attributes?scope?filter?extensions`

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::protocol::http::response::Response;

// ───────────────────────── ASN.1 BER encoding ─────────────────────────

/// ASN.1 BER tag classes and types used by LDAP.
mod ber {
    /// Encode length in BER format.
    #[allow(clippy::cast_possible_truncation)]
    pub fn encode_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else if len <= 0xFFFF {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        } else if len <= 0xFF_FFFF {
            vec![0x83, (len >> 16) as u8, ((len >> 8) & 0xFF) as u8, (len & 0xFF) as u8]
        } else {
            vec![
                0x84,
                (len >> 24) as u8,
                ((len >> 16) & 0xFF) as u8,
                ((len >> 8) & 0xFF) as u8,
                (len & 0xFF) as u8,
            ]
        }
    }

    /// Encode an INTEGER value.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn encode_integer(value: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        if (0..=0x7F).contains(&value) {
            bytes.push(0x02); // INTEGER tag
            bytes.push(0x01); // length 1
            bytes.push(value as u8);
        } else if (0..=0x7FFF).contains(&value) {
            bytes.push(0x02);
            bytes.push(0x02);
            bytes.push((value >> 8) as u8);
            bytes.push((value & 0xFF) as u8);
        } else {
            let val_bytes = value.to_be_bytes();
            let start =
                val_bytes.iter().position(|&b| b != 0 && b != 0xFF).unwrap_or(val_bytes.len() - 1);
            let need_pad = value >= 0 && val_bytes[start] & 0x80 != 0;
            let payload_len = val_bytes.len() - start + usize::from(need_pad);
            bytes.push(0x02);
            bytes.extend(encode_length(payload_len));
            if need_pad {
                bytes.push(0x00);
            }
            bytes.extend_from_slice(&val_bytes[start..]);
        }
        bytes
    }

    /// Encode an OCTET STRING.
    pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x04];
        bytes.extend(encode_length(data.len()));
        bytes.extend_from_slice(data);
        bytes
    }

    /// Encode a BOOLEAN value.
    pub fn encode_boolean(value: bool) -> Vec<u8> {
        vec![0x01, 0x01, if value { 0xFF } else { 0x00 }]
    }

    /// Encode an ENUMERATED value.
    pub fn encode_enumerated(value: u8) -> Vec<u8> {
        vec![0x0A, 0x01, value]
    }

    /// Wrap content in a SEQUENCE.
    pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x30];
        bytes.extend(encode_length(content.len()));
        bytes.extend_from_slice(content);
        bytes
    }

    /// Wrap content with an APPLICATION tag (constructed).
    pub fn encode_application(tag_num: u8, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x60 | tag_num];
        bytes.extend(encode_length(content.len()));
        bytes.extend_from_slice(content);
        bytes
    }

    /// Encode a context-specific primitive tag.
    pub fn encode_context_primitive(tag_num: u8, data: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80 | tag_num];
        bytes.extend(encode_length(data.len()));
        bytes.extend_from_slice(data);
        bytes
    }

    /// Encode a context-specific constructed tag.
    pub fn encode_context_constructed(tag_num: u8, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xA0 | tag_num];
        bytes.extend(encode_length(content.len()));
        bytes.extend_from_slice(content);
        bytes
    }

    /// Decode a BER length from a byte slice, returning (length, `bytes_consumed`).
    pub fn decode_length(data: &[u8]) -> Result<(usize, usize), String> {
        if data.is_empty() {
            return Err("empty length".to_string());
        }
        if data[0] < 0x80 {
            Ok((data[0] as usize, 1))
        } else {
            let num_bytes = (data[0] & 0x7F) as usize;
            if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
                return Err(format!("invalid BER length: {num_bytes} octets"));
            }
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | data[1 + i] as usize;
            }
            Ok((len, 1 + num_bytes))
        }
    }

    /// Decode an INTEGER from BER-encoded bytes.
    pub fn decode_integer(data: &[u8]) -> Result<(i64, usize), String> {
        if data.is_empty() || data[0] != 0x02 {
            return Err("expected INTEGER tag".to_string());
        }
        let (len, len_size) = decode_length(&data[1..])?;
        let total = 1 + len_size + len;
        if data.len() < total {
            return Err("INTEGER truncated".to_string());
        }
        let value_bytes = &data[1 + len_size..total];
        let mut value: i64 =
            if !value_bytes.is_empty() && value_bytes[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in value_bytes {
            value = (value << 8) | i64::from(b);
        }
        Ok((value, total))
    }

    /// Decode an OCTET STRING from BER-encoded bytes.
    pub fn decode_octet_string(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
        if data.is_empty() || data[0] != 0x04 {
            return Err(format!(
                "expected OCTET STRING tag (0x04), got 0x{:02X}",
                data.first().copied().unwrap_or(0)
            ));
        }
        let (len, len_size) = decode_length(&data[1..])?;
        let total = 1 + len_size + len;
        if data.len() < total {
            return Err("OCTET STRING truncated".to_string());
        }
        Ok((data[1 + len_size..total].to_vec(), total))
    }

    /// Decode a TLV (tag-length-value) element, returning (tag, `value_bytes`, `total_consumed`).
    pub fn decode_tlv(data: &[u8]) -> Result<(u8, Vec<u8>, usize), String> {
        if data.is_empty() {
            return Err("empty TLV".to_string());
        }
        let tag = data[0];
        let (len, len_size) = decode_length(&data[1..])?;
        let total = 1 + len_size + len;
        if data.len() < total {
            return Err(format!("TLV truncated: need {total}, have {}", data.len()));
        }
        Ok((tag, data[1 + len_size..total].to_vec(), total))
    }

    /// Decode an ENUMERATED from BER-encoded bytes.
    pub fn decode_enumerated(data: &[u8]) -> Result<(u8, usize), String> {
        if data.is_empty() || data[0] != 0x0A {
            return Err("expected ENUMERATED tag".to_string());
        }
        let (len, len_size) = decode_length(&data[1..])?;
        let total = 1 + len_size + len;
        if data.len() < total || len == 0 {
            return Err("ENUMERATED truncated".to_string());
        }
        Ok((data[1 + len_size], total))
    }
}

struct LdapUrlComponents {
    base_dn: String,
    attributes: Vec<String>,
    scope: u8,
    filter: String,
}

fn parse_ldap_url(url: &crate::url::Url) -> LdapUrlComponents {
    let path = url.path();
    let base_dn = percent_decode(path.trim_start_matches('/'));
    let query = url.query().unwrap_or_default();
    let parts: Vec<&str> = query.splitn(4, '?').collect();

    let attributes: Vec<String> = if let Some(&attrs_str) = parts.first() {
        if attrs_str.is_empty() {
            Vec::new()
        } else {
            attrs_str.split(',').map(|s| percent_decode(s.trim())).collect()
        }
    } else {
        Vec::new()
    };

    let scope = match parts.get(1).copied().unwrap_or("") {
        "one" => 1,
        "sub" => 2,
        _ => 0,
    };

    let filter = if let Some(&f) = parts.get(2) {
        if f.is_empty() {
            "(objectClass=*)".to_string()
        } else {
            percent_decode(f)
        }
    } else {
        "(objectClass=*)".to_string()
    };

    LdapUrlComponents { base_dn, attributes, scope, filter }
}

fn encode_filter(filter: &str) -> Result<Vec<u8>, Error> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Err(Error::Http("LDAP: empty filter".to_string()));
    }
    let inner = if filter.starts_with('(') && filter.ends_with(')') {
        &filter[1..filter.len() - 1]
    } else {
        filter
    };
    if inner.is_empty() {
        return Err(Error::Http("LDAP: empty filter expression".to_string()));
    }
    match inner.as_bytes()[0] {
        b'&' => {
            let sub_filters = split_filter_list(&inner[1..])?;
            let mut content = Vec::new();
            for sf in &sub_filters {
                content.extend(encode_filter(sf)?);
            }
            Ok(ber::encode_context_constructed(0, &content))
        }
        b'|' => {
            let sub_filters = split_filter_list(&inner[1..])?;
            let mut content = Vec::new();
            for sf in &sub_filters {
                content.extend(encode_filter(sf)?);
            }
            Ok(ber::encode_context_constructed(1, &content))
        }
        b'!' => {
            let sub = inner[1..].trim();
            let encoded = encode_filter(sub)?;
            Ok(ber::encode_context_constructed(2, &encoded))
        }
        _ => encode_simple_filter(inner),
    }
}

fn split_filter_list(s: &str) -> Result<Vec<String>, Error> {
    let s = s.trim();
    let mut filters = Vec::new();
    let mut depth = 0i32;
    let mut start = None;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s_idx) = start {
                        filters.push(s[s_idx..=i].to_string());
                        start = None;
                    }
                }
            }
            _ => {}
        }
    }
    if filters.is_empty() {
        return Err(Error::Http("LDAP: invalid compound filter".to_string()));
    }
    Ok(filters)
}

fn encode_simple_filter(expr: &str) -> Result<Vec<u8>, Error> {
    if let Some(pos) = expr.find(">=") {
        let attr = &expr.as_bytes()[..pos];
        let val = &expr.as_bytes()[pos + 2..];
        let mut content = ber::encode_octet_string(attr);
        content.extend(ber::encode_octet_string(val));
        return Ok(ber::encode_context_constructed(5, &content));
    }
    if let Some(pos) = expr.find("<=") {
        let attr = &expr.as_bytes()[..pos];
        let val = &expr.as_bytes()[pos + 2..];
        let mut content = ber::encode_octet_string(attr);
        content.extend(ber::encode_octet_string(val));
        return Ok(ber::encode_context_constructed(6, &content));
    }
    if let Some(pos) = expr.find("~=") {
        let attr = &expr.as_bytes()[..pos];
        let val = &expr.as_bytes()[pos + 2..];
        let mut content = ber::encode_octet_string(attr);
        content.extend(ber::encode_octet_string(val));
        return Ok(ber::encode_context_constructed(8, &content));
    }
    if let Some(pos) = expr.find('=') {
        let attr = &expr[..pos];
        let val = &expr[pos + 1..];
        if val == "*" {
            return Ok(ber::encode_context_primitive(7, attr.as_bytes()));
        }
        if val.contains('*') {
            return Ok(encode_substring_filter(attr, val));
        }
        let mut content = ber::encode_octet_string(attr.as_bytes());
        content.extend(ber::encode_octet_string(val.as_bytes()));
        return Ok(ber::encode_context_constructed(3, &content));
    }
    Err(Error::Http(format!("LDAP: invalid filter expression: {expr}")))
}

fn encode_substring_filter(attr: &str, val: &str) -> Vec<u8> {
    let parts: Vec<&str> = val.split('*').collect();
    let mut substrings = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let tag = if i == 0 {
            0
        } else if i == parts.len() - 1 {
            2
        } else {
            1
        };
        substrings.extend(ber::encode_context_primitive(tag, part.as_bytes()));
    }
    let substr_seq = ber::encode_sequence(&substrings);
    let mut content = ber::encode_octet_string(attr.as_bytes());
    content.extend(substr_seq);
    ber::encode_context_constructed(4, &content)
}

fn build_bind_request(message_id: i32) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(ber::encode_integer(3));
    content.extend(ber::encode_octet_string(b""));
    content.extend(ber::encode_context_primitive(0, b""));
    let bind_req = ber::encode_application(0, &content);
    let mut msg = Vec::new();
    msg.extend(ber::encode_integer(message_id));
    msg.extend(bind_req);
    ber::encode_sequence(&msg)
}

fn build_bind_request_auth(message_id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(ber::encode_integer(3));
    content.extend(ber::encode_octet_string(dn.as_bytes()));
    content.extend(ber::encode_context_primitive(0, password.as_bytes()));
    let bind_req = ber::encode_application(0, &content);
    let mut msg = Vec::new();
    msg.extend(ber::encode_integer(message_id));
    msg.extend(bind_req);
    ber::encode_sequence(&msg)
}

fn build_search_request(message_id: i32, components: &LdapUrlComponents) -> Result<Vec<u8>, Error> {
    let mut content = Vec::new();
    content.extend(ber::encode_octet_string(components.base_dn.as_bytes()));
    content.extend(ber::encode_enumerated(components.scope));
    content.extend(ber::encode_enumerated(0));
    content.extend(ber::encode_integer(0));
    content.extend(ber::encode_integer(0));
    content.extend(ber::encode_boolean(false));
    content.extend(encode_filter(&components.filter)?);
    let mut attrs_content = Vec::new();
    for attr in &components.attributes {
        attrs_content.extend(ber::encode_octet_string(attr.as_bytes()));
    }
    content.extend(ber::encode_sequence(&attrs_content));
    let search_req = ber::encode_application(3, &content);
    let mut msg = Vec::new();
    msg.extend(ber::encode_integer(message_id));
    msg.extend(search_req);
    Ok(ber::encode_sequence(&msg))
}

fn build_unbind_request(message_id: i32) -> Vec<u8> {
    let unbind_req = vec![0x42, 0x00];
    let mut msg = Vec::new();
    msg.extend(ber::encode_integer(message_id));
    msg.extend(unbind_req);
    ber::encode_sequence(&msg)
}

struct LdapAttribute {
    attr_type: String,
    values: Vec<Vec<u8>>,
}
struct LdapEntry {
    dn: String,
    attributes: Vec<LdapAttribute>,
}

fn parse_ldap_message(data: &[u8]) -> Result<(i64, u8, Vec<u8>, usize), Error> {
    let (tag, msg_content, total) = ber::decode_tlv(data)
        .map_err(|e| Error::Http(format!("LDAP: failed to parse message envelope: {e}")))?;
    if tag != 0x30 {
        return Err(Error::Http(format!("LDAP: expected SEQUENCE, got 0x{tag:02X}")));
    }
    let (message_id, id_len) = ber::decode_integer(&msg_content)
        .map_err(|e| Error::Http(format!("LDAP: failed to parse message ID: {e}")))?;
    let rest = &msg_content[id_len..];
    let (op_tag, op_value, _op_total) = ber::decode_tlv(rest)
        .map_err(|e| Error::Http(format!("LDAP: failed to parse protocol op: {e}")))?;
    Ok((message_id, op_tag, op_value, total))
}

fn parse_bind_response(op_value: &[u8]) -> Result<u8, Error> {
    let (result_code, _) = ber::decode_enumerated(op_value)
        .map_err(|e| Error::Http(format!("LDAP: failed to parse BindResponse result code: {e}")))?;
    Ok(result_code)
}

fn parse_search_result_entry(op_value: &[u8]) -> Result<LdapEntry, Error> {
    let mut pos = 0;
    let (dn_bytes, dn_len) = ber::decode_octet_string(&op_value[pos..])
        .map_err(|e| Error::Http(format!("LDAP: failed to parse entry DN: {e}")))?;
    pos += dn_len;
    let dn = String::from_utf8_lossy(&dn_bytes).into_owned();
    let mut attributes = Vec::new();
    if pos < op_value.len() {
        let (attr_list_tag, attr_list_value, _) = ber::decode_tlv(&op_value[pos..])
            .map_err(|e| Error::Http(format!("LDAP: failed to parse attribute list: {e}")))?;
        if attr_list_tag != 0x30 {
            return Err(Error::Http(format!(
                "LDAP: expected SEQUENCE for attribute list, got 0x{attr_list_tag:02X}"
            )));
        }
        let mut attr_pos = 0;
        while attr_pos < attr_list_value.len() {
            let (pa_tag, pa_value, pa_total) = ber::decode_tlv(&attr_list_value[attr_pos..])
                .map_err(|e| Error::Http(format!("LDAP: failed to parse attribute: {e}")))?;
            attr_pos += pa_total;
            if pa_tag != 0x30 {
                continue;
            }
            let mut pa_pos = 0;
            let (type_bytes, type_len) = ber::decode_octet_string(&pa_value[pa_pos..])
                .map_err(|e| Error::Http(format!("LDAP: failed to parse attribute type: {e}")))?;
            pa_pos += type_len;
            let attr_type = String::from_utf8_lossy(&type_bytes).into_owned();
            let mut values = Vec::new();
            if pa_pos < pa_value.len() {
                let (set_tag, set_value, _) = ber::decode_tlv(&pa_value[pa_pos..])
                    .map_err(|e| Error::Http(format!("LDAP: failed to parse value set: {e}")))?;
                if set_tag == 0x31 {
                    let mut set_pos = 0;
                    while set_pos < set_value.len() {
                        let (val_bytes, val_len) = ber::decode_octet_string(&set_value[set_pos..])
                            .map_err(|e| {
                                Error::Http(format!("LDAP: failed to parse attribute value: {e}"))
                            })?;
                        set_pos += val_len;
                        values.push(val_bytes);
                    }
                }
            }
            attributes.push(LdapAttribute { attr_type, values });
        }
    }
    Ok(LdapEntry { dn, attributes })
}

fn parse_search_result_done(op_value: &[u8]) -> Result<u8, Error> {
    let (result_code, _) = ber::decode_enumerated(op_value).map_err(|e| {
        Error::Http(format!("LDAP: failed to parse SearchResultDone result code: {e}"))
    })?;
    Ok(result_code)
}

fn format_ldap_results(entries: &[LdapEntry]) -> String {
    let mut output = String::new();
    for entry in entries {
        output.push_str("DN: ");
        output.push_str(&entry.dn);
        output.push('\n');
        for attr in &entry.attributes {
            for val in &attr.values {
                output.push('\t');
                output.push_str(&attr.attr_type);
                output.push_str(": ");
                if let Ok(s) = std::str::from_utf8(val) {
                    output.push_str(s);
                } else {
                    output.push_str(&base64_encode(val));
                }
                output.push('\n');
            }
        }
        output.push('\n');
    }
    output
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn percent_decode(input: &str) -> String {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn read_ldap_message<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>, Error> {
    let mut tag_buf = [0u8; 1];
    let _ = stream
        .read_exact(&mut tag_buf)
        .await
        .map_err(|e| Error::Http(format!("LDAP: failed to read message tag: {e}")))?;
    let mut first_len = [0u8; 1];
    let _ = stream
        .read_exact(&mut first_len)
        .await
        .map_err(|e| Error::Http(format!("LDAP: failed to read message length: {e}")))?;
    let (content_len, extra_len_bytes) = if first_len[0] < 0x80 {
        (first_len[0] as usize, 0)
    } else {
        let num_bytes = (first_len[0] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(Error::Http(format!("LDAP: invalid length encoding: {num_bytes} octets")));
        }
        let mut len_buf = vec![0u8; num_bytes];
        let _ = stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| Error::Http(format!("LDAP: failed to read extended length: {e}")))?;
        let mut len = 0usize;
        for &b in &len_buf {
            len = (len << 8) | b as usize;
        }
        (len, num_bytes)
    };
    let mut message = Vec::with_capacity(2 + extra_len_bytes + content_len);
    message.push(tag_buf[0]);
    message.push(first_len[0]);
    if extra_len_bytes > 0 {
        let len_start = message.len();
        message.resize(len_start + extra_len_bytes, 0);
        let mut remaining = content_len;
        #[allow(clippy::cast_possible_truncation)]
        for i in (0..extra_len_bytes).rev() {
            message[len_start + i] = (remaining & 0xFF) as u8;
            remaining >>= 8;
        }
    }
    let content_start = message.len();
    message.resize(content_start + content_len, 0);
    let _ = stream.read_exact(&mut message[content_start..]).await.map_err(|e| {
        Error::Http(format!("LDAP: failed to read message content ({content_len} bytes): {e}"))
    })?;
    Ok(message)
}

/// Perform an LDAP search query.
///
/// Connects to the LDAP server, performs an anonymous bind (or authenticated
/// bind if credentials are provided in the URL), executes the search
/// specified by the URL components, and returns the results.
///
/// # Errors
///
/// Returns an error if the connection, bind, or search fails.
pub async fn search(
    url: &crate::url::Url,
    tls_config: &crate::tls::TlsConfig,
    use_tls: bool,
) -> Result<Response, Error> {
    let (host, port) = url.host_and_port()?;
    let components = parse_ldap_url(url);
    let username = url.username();
    let username_opt = if username.is_empty() { None } else { Some(username) };
    let password = url.password();
    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr).await.map_err(Error::Connect)?;
    if use_tls {
        let connector = crate::tls::TlsConnector::new_no_alpn(tls_config)?;
        let (tls_stream, _alpn) = connector.connect(tcp, &host).await?;
        perform_ldap(tls_stream, url, &components, username_opt, password).await
    } else {
        perform_ldap(tcp, url, &components, username_opt, password).await
    }
}

async fn perform_ldap<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    url: &crate::url::Url,
    components: &LdapUrlComponents,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Response, Error> {
    let mut msg_id = 1;
    let bind_msg = match (username, password) {
        (Some(user), Some(pass)) if !user.is_empty() => build_bind_request_auth(msg_id, user, pass),
        _ => build_bind_request(msg_id),
    };
    stream
        .write_all(&bind_msg)
        .await
        .map_err(|e| Error::Http(format!("LDAP: failed to send BindRequest: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("LDAP: flush error: {e}")))?;
    let resp_data = read_ldap_message(&mut stream).await?;
    let (_id, op_tag, op_value, _) = parse_ldap_message(&resp_data)?;
    if op_tag != 0x61 {
        return Err(Error::Http(format!("LDAP: expected BindResponse (0x61), got 0x{op_tag:02X}")));
    }
    let result_code = parse_bind_response(&op_value)?;
    if result_code != 0 {
        return Err(Error::Transfer {
            code: 39,
            message: format!("LDAP bind failed with result code {result_code}"),
        });
    }
    msg_id += 1;
    let search_msg = build_search_request(msg_id, components)?;
    stream
        .write_all(&search_msg)
        .await
        .map_err(|e| Error::Http(format!("LDAP: failed to send SearchRequest: {e}")))?;
    stream.flush().await.map_err(|e| Error::Http(format!("LDAP: flush error: {e}")))?;
    let mut entries = Vec::new();
    loop {
        let msg_data = read_ldap_message(&mut stream).await?;
        let (_id, op_tag, op_value, _) = parse_ldap_message(&msg_data)?;
        match op_tag {
            0x64 => {
                entries.push(parse_search_result_entry(&op_value)?);
            }
            0x73 => { /* SearchResultReference — skip */ }
            0x65 => {
                let result_code = parse_search_result_done(&op_value)?;
                if result_code != 0 && result_code != 4 {
                    return Err(Error::Transfer {
                        code: 39,
                        message: format!("LDAP search failed with result code {result_code}"),
                    });
                }
                break;
            }
            _ => {
                return Err(Error::Http(format!("LDAP: unexpected response tag 0x{op_tag:02X}")));
            }
        }
    }
    msg_id += 1;
    let unbind_msg = build_unbind_request(msg_id);
    let _ignore = stream.write_all(&unbind_msg).await;
    let output = format_ldap_results(&entries);
    let body = output.into_bytes();
    let mut headers = std::collections::HashMap::new();
    let _old = headers.insert("content-length".to_string(), body.len().to_string());
    Ok(Response::new(200, headers, body, url.as_str().to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ber_encode_length_short() {
        assert_eq!(ber::encode_length(0), vec![0x00]);
        assert_eq!(ber::encode_length(127), vec![0x7F]);
    }
    #[test]
    fn ber_encode_length_long() {
        assert_eq!(ber::encode_length(128), vec![0x81, 0x80]);
        assert_eq!(ber::encode_length(256), vec![0x82, 0x01, 0x00]);
    }
    #[test]
    fn ber_encode_integer_small() {
        assert_eq!(ber::encode_integer(3), vec![0x02, 0x01, 0x03]);
    }
    #[test]
    fn ber_encode_integer_zero() {
        assert_eq!(ber::encode_integer(0), vec![0x02, 0x01, 0x00]);
    }
    #[test]
    fn ber_encode_octet_string_basic() {
        assert_eq!(
            ber::encode_octet_string(b"hello"),
            vec![0x04, 0x05, b'h', b'e', b'l', b'l', b'o']
        );
    }
    #[test]
    fn ber_encode_octet_string_empty() {
        assert_eq!(ber::encode_octet_string(b""), vec![0x04, 0x00]);
    }
    #[test]
    fn ber_encode_boolean() {
        assert_eq!(ber::encode_boolean(false), vec![0x01, 0x01, 0x00]);
        assert_eq!(ber::encode_boolean(true), vec![0x01, 0x01, 0xFF]);
    }
    #[test]
    fn ber_encode_enumerated() {
        assert_eq!(ber::encode_enumerated(2), vec![0x0A, 0x01, 0x02]);
    }
    #[test]
    fn ber_encode_sequence() {
        let seq = ber::encode_sequence(&ber::encode_integer(1));
        assert_eq!(seq[0], 0x30);
    }
    #[test]
    fn ber_decode_length_short() {
        let (len, consumed) = ber::decode_length(&[0x05]).unwrap();
        assert_eq!((len, consumed), (5, 1));
    }
    #[test]
    fn ber_decode_length_long() {
        let (len, consumed) = ber::decode_length(&[0x81, 0x80]).unwrap();
        assert_eq!((len, consumed), (128, 2));
    }
    #[test]
    fn ber_decode_integer() {
        let (val, consumed) = ber::decode_integer(&[0x02, 0x01, 0x03]).unwrap();
        assert_eq!((val, consumed), (3, 3));
    }
    #[test]
    fn ber_decode_octet_string() {
        let (val, consumed) =
            ber::decode_octet_string(&[0x04, 0x05, b'h', b'e', b'l', b'l', b'o']).unwrap();
        assert_eq!(val, b"hello");
        assert_eq!(consumed, 7);
    }
    #[test]
    fn ber_decode_tlv() {
        let (tag, value, consumed) = ber::decode_tlv(&[0x30, 0x03, 0x02, 0x01, 0x05]).unwrap();
        assert_eq!((tag, consumed), (0x30, 5));
        assert_eq!(value, vec![0x02, 0x01, 0x05]);
    }
    #[test]
    fn ber_decode_enumerated() {
        let (val, consumed) = ber::decode_enumerated(&[0x0A, 0x01, 0x00]).unwrap();
        assert_eq!((val, consumed), (0, 3));
    }
    #[test]
    fn parse_ldap_url_basic() {
        let url = crate::url::Url::parse("ldap://localhost/dc=example,dc=com").unwrap();
        let c = parse_ldap_url(&url);
        assert_eq!(c.base_dn, "dc=example,dc=com");
        assert_eq!(c.scope, 0);
        assert_eq!(c.filter, "(objectClass=*)");
        assert!(c.attributes.is_empty());
    }
    #[test]
    fn parse_ldap_url_with_query() {
        let url = crate::url::Url::parse(
            "ldap://localhost/dc=example,dc=com?cn,mail?sub?(objectClass=person)",
        )
        .unwrap();
        let c = parse_ldap_url(&url);
        assert_eq!(c.attributes, vec!["cn", "mail"]);
        assert_eq!(c.scope, 2);
        assert_eq!(c.filter, "(objectClass=person)");
    }
    #[test]
    fn parse_ldap_url_empty_path() {
        let url = crate::url::Url::parse("ldap://localhost/").unwrap();
        assert_eq!(parse_ldap_url(&url).base_dn, "");
    }
    #[test]
    fn parse_ldap_url_scope_one() {
        let url = crate::url::Url::parse("ldap://localhost/dc=test??one").unwrap();
        assert_eq!(parse_ldap_url(&url).scope, 1);
    }
    #[test]
    fn encode_filter_presence() {
        let encoded = encode_filter("(objectClass=*)").unwrap();
        assert_eq!(encoded[0], 0x87);
        assert_eq!(&encoded[2..], b"objectClass");
    }
    #[test]
    fn encode_filter_equality() {
        assert_eq!(encode_filter("(cn=John)").unwrap()[0], 0xA3);
    }
    #[test]
    fn encode_filter_and() {
        assert_eq!(encode_filter("(&(cn=John)(sn=Doe))").unwrap()[0], 0xA0);
    }
    #[test]
    fn encode_filter_or() {
        assert_eq!(encode_filter("(|(cn=John)(cn=Jane))").unwrap()[0], 0xA1);
    }
    #[test]
    fn encode_filter_not() {
        assert_eq!(encode_filter("(!(cn=John))").unwrap()[0], 0xA2);
    }
    #[test]
    fn encode_filter_substring() {
        assert_eq!(encode_filter("(cn=*John*)").unwrap()[0], 0xA4);
    }
    #[test]
    fn encode_filter_gte() {
        assert_eq!(encode_filter("(age>=18)").unwrap()[0], 0xA5);
    }
    #[test]
    fn encode_filter_lte() {
        assert_eq!(encode_filter("(age<=65)").unwrap()[0], 0xA6);
    }
    #[test]
    fn build_bind_request_produces_valid_ber() {
        let msg = build_bind_request(1);
        assert_eq!(msg[0], 0x30);
        assert_eq!(ber::decode_tlv(&msg).unwrap().0, 0x30);
    }
    #[test]
    fn build_bind_request_auth_includes_credentials() {
        let msg = build_bind_request_auth(1, "cn=admin", "secret");
        assert!(String::from_utf8_lossy(&msg).contains("cn=admin"));
    }
    #[test]
    fn build_search_request_produces_valid_ber() {
        let c = LdapUrlComponents {
            base_dn: "dc=example".to_string(),
            attributes: vec!["cn".to_string()],
            scope: 2,
            filter: "(objectClass=*)".to_string(),
        };
        assert_eq!(build_search_request(2, &c).unwrap()[0], 0x30);
    }
    #[test]
    fn build_unbind_request_produces_valid_ber() {
        assert_eq!(build_unbind_request(3)[0], 0x30);
    }
    #[test]
    fn format_ldap_results_basic() {
        let entries = vec![LdapEntry {
            dn: "cn=John Doe,dc=example,dc=com".to_string(),
            attributes: vec![
                LdapAttribute { attr_type: "cn".to_string(), values: vec![b"John Doe".to_vec()] },
                LdapAttribute {
                    attr_type: "mail".to_string(),
                    values: vec![b"john@example.com".to_vec()],
                },
            ],
        }];
        let output = format_ldap_results(&entries);
        assert!(output.contains("DN: cn=John Doe,dc=example,dc=com"));
        assert!(output.contains("\tcn: John Doe"));
        assert!(output.contains("\tmail: john@example.com"));
    }
    #[test]
    fn format_ldap_results_empty() {
        assert!(format_ldap_results(&[]).is_empty());
    }
    #[test]
    fn format_ldap_results_multi_valued() {
        let entries = vec![LdapEntry {
            dn: "cn=Test".to_string(),
            attributes: vec![LdapAttribute {
                attr_type: "member".to_string(),
                values: vec![b"cn=Alice".to_vec(), b"cn=Bob".to_vec()],
            }],
        }];
        let output = format_ldap_results(&entries);
        assert!(output.contains("\tmember: cn=Alice"));
        assert!(output.contains("\tmember: cn=Bob"));
    }
    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("dc%3Dexample"), "dc=example");
    }
    #[test]
    fn percent_decode_empty() {
        assert_eq!(percent_decode(""), "");
    }
    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b"Hi"), "SGk=");
        assert_eq!(base64_encode(b"Hey"), "SGV5");
    }
    #[test]
    fn parse_bind_response_success() {
        let mut v = Vec::new();
        v.extend(ber::encode_enumerated(0));
        v.extend(ber::encode_octet_string(b""));
        v.extend(ber::encode_octet_string(b""));
        assert_eq!(parse_bind_response(&v).unwrap(), 0);
    }
    #[test]
    fn parse_search_result_done_success() {
        let mut v = Vec::new();
        v.extend(ber::encode_enumerated(0));
        v.extend(ber::encode_octet_string(b""));
        v.extend(ber::encode_octet_string(b""));
        assert_eq!(parse_search_result_done(&v).unwrap(), 0);
    }
    #[test]
    fn parse_search_result_entry_basic() {
        let mut value = Vec::new();
        value.extend(ber::encode_octet_string(b"cn=Test,dc=example"));
        let mut attr_content = Vec::new();
        attr_content.extend(ber::encode_octet_string(b"cn"));
        let val = ber::encode_octet_string(b"Test");
        let mut set = vec![0x31];
        set.extend(ber::encode_length(val.len()));
        set.extend(val);
        attr_content.extend(set);
        let attr_seq = ber::encode_sequence(&attr_content);
        value.extend(ber::encode_sequence(&attr_seq));
        let entry = parse_search_result_entry(&value).unwrap();
        assert_eq!(entry.dn, "cn=Test,dc=example");
        assert_eq!(entry.attributes.len(), 1);
        assert_eq!(entry.attributes[0].attr_type, "cn");
        assert_eq!(entry.attributes[0].values, vec![b"Test".to_vec()]);
    }
    #[test]
    fn split_filter_list_basic() {
        assert_eq!(split_filter_list("(cn=John)(sn=Doe)").unwrap(), vec!["(cn=John)", "(sn=Doe)"]);
    }
    #[test]
    fn split_filter_list_nested() {
        let filters = split_filter_list("(&(a=1)(b=2))(c=3)").unwrap();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0], "(&(a=1)(b=2))");
    }
}
