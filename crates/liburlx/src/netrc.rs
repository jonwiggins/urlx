//! `.netrc` file parsing for credential lookup.
//!
//! Supports the standard `.netrc` format used by curl, ftp, and other tools:
//! ```text
//! machine example.com
//! login myuser
//! password mypassword
//!
//! default
//! login anonymous
//! password user@example.com
//! ```

/// A single credential entry from a `.netrc` file.
#[derive(Debug, Clone)]
pub struct NetrcEntry {
    /// The machine name, or `None` for the `default` entry.
    pub machine: Option<String>,
    /// Login/username.
    pub login: Option<String>,
    /// Password.
    pub password: Option<String>,
}

/// Error type for netrc parsing failures.
#[derive(Debug, Clone)]
pub struct NetrcSyntaxError;

/// Parse a `.netrc` file and look up credentials for a host.
///
/// Returns the matching entry for the given hostname, or the `default`
/// entry if no host-specific entry matches.
/// # Errors
///
/// Returns [`NetrcSyntaxError`] for syntax errors (e.g., unterminated quotes).
pub fn lookup(contents: &str, hostname: &str) -> Result<Option<NetrcEntry>, NetrcSyntaxError> {
    let entries = parse(contents)?;
    // First try exact machine match
    let exact = entries
        .iter()
        .find(|e| e.machine.as_ref().is_some_and(|m| m.eq_ignore_ascii_case(hostname)));
    if let Some(entry) = exact {
        return Ok(Some(entry.clone()));
    }
    // Fall back to default entry
    Ok(entries.into_iter().find(|e| e.machine.is_none()))
}

/// Parse a `.netrc` file and look up credentials for a host and specific user.
///
/// Returns the matching entry for the given hostname and login name, or `None`
/// if no entry matches both host and user.
/// # Errors
///
/// Returns [`NetrcSyntaxError`] for syntax errors (e.g., unterminated quotes).
pub fn lookup_user(
    contents: &str,
    hostname: &str,
    username: &str,
) -> Result<Option<NetrcEntry>, NetrcSyntaxError> {
    let entries = parse(contents)?;
    Ok(entries.into_iter().find(|e| {
        e.machine.as_ref().is_some_and(|m| m.eq_ignore_ascii_case(hostname))
            && e.login.as_ref().is_some_and(|l| l == username)
    }))
}

/// Parse all entries from a `.netrc` file.
///
/// Returns `Ok(entries)` on success, or `Err(NetrcSyntaxError)` if the file has a syntax
/// error (e.g., unterminated quoted string).
fn parse(contents: &str) -> Result<Vec<NetrcEntry>, NetrcSyntaxError> {
    let mut entries = Vec::new();
    let mut current: Option<NetrcEntry> = None;

    // Tokenize: split on whitespace, supporting quoted strings with escapes.
    // Comments start with # and run to end of line.
    let tokens = tokenize(contents)?;

    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "machine" => {
                if let Some(entry) = current.take() {
                    entries.push(entry);
                }
                i += 1;
                let machine = tokens.get(i).cloned();
                current = Some(NetrcEntry { machine, login: None, password: None });
            }
            "default" => {
                if let Some(entry) = current.take() {
                    entries.push(entry);
                }
                current = Some(NetrcEntry { machine: None, login: None, password: None });
            }
            "login" => {
                i += 1;
                if let Some(ref mut entry) = current {
                    entry.login = tokens.get(i).cloned();
                }
            }
            "password" => {
                i += 1;
                if let Some(ref mut entry) = current {
                    entry.password = tokens.get(i).cloned();
                }
            }
            "account" | "macdef" => {
                // Skip account and macdef tokens (and their values)
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(entry) = current {
        entries.push(entry);
    }

    Ok(entries)
}

/// Tokenize a `.netrc` file, handling comments and quoted strings with escape sequences.
///
/// Returns `Err(NetrcSyntaxError)` if a quoted string is unterminated.
fn tokenize(contents: &str) -> Result<Vec<String>, NetrcSyntaxError> {
    let mut tokens = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let mut chars = line.chars().peekable();
        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() {
                let _ = chars.next();
                continue;
            }
            if ch == '#' {
                break; // rest of line is comment
            }
            if ch == '"' {
                // Quoted string with escape sequences
                let _ = chars.next(); // consume opening quote
                let mut value = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        // Escape sequence
                        match chars.next() {
                            Some('n') => value.push('\n'),
                            Some('r') => value.push('\r'),
                            Some('t') => value.push('\t'),
                            Some('"') => value.push('"'),
                            Some('\\') => value.push('\\'),
                            Some(other) => value.push(other),
                            None => return Err(NetrcSyntaxError), // escape at end of line
                        }
                    } else if c == '"' {
                        closed = true;
                        break;
                    } else {
                        value.push(c);
                    }
                }
                if !closed {
                    return Err(NetrcSyntaxError); // unterminated quote
                }
                tokens.push(value);
            } else {
                // Unquoted word
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '#' {
                        break;
                    }
                    word.push(c);
                    let _ = chars.next();
                }
                tokens.push(word);
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_netrc() {
        let contents = "machine example.com\nlogin myuser\npassword mypass\n";
        let entry = lookup(contents, "example.com").unwrap().unwrap();
        assert_eq!(entry.machine.as_deref(), Some("example.com"));
        assert_eq!(entry.login.as_deref(), Some("myuser"));
        assert_eq!(entry.password.as_deref(), Some("mypass"));
    }

    #[test]
    fn parse_no_match() {
        let contents = "machine example.com\nlogin myuser\npassword mypass\n";
        let entry = lookup(contents, "other.com").unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn parse_default_fallback() {
        let contents = "machine example.com\nlogin user1\npassword pass1\n\ndefault\nlogin anonymous\npassword anon@\n";
        let entry = lookup(contents, "other.com").unwrap().unwrap();
        assert!(entry.machine.is_none());
        assert_eq!(entry.login.as_deref(), Some("anonymous"));
        assert_eq!(entry.password.as_deref(), Some("anon@"));
    }

    #[test]
    fn parse_case_insensitive_host() {
        let contents = "machine Example.COM\nlogin user\npassword pass\n";
        let entry = lookup(contents, "example.com").unwrap().unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
    }

    #[test]
    fn parse_multiple_machines() {
        let contents = "machine a.com\nlogin a\npassword pa\nmachine b.com\nlogin b\npassword pb\n";
        let a = lookup(contents, "a.com").unwrap().unwrap();
        assert_eq!(a.login.as_deref(), Some("a"));
        let b = lookup(contents, "b.com").unwrap().unwrap();
        assert_eq!(b.login.as_deref(), Some("b"));
    }

    #[test]
    fn parse_inline_format() {
        let contents = "machine example.com login user password pass\n";
        let entry = lookup(contents, "example.com").unwrap().unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
        assert_eq!(entry.password.as_deref(), Some("pass"));
    }

    #[test]
    fn parse_comments() {
        let contents = "# this is a comment\nmachine example.com\n# another comment\nlogin user\npassword pass\n";
        let entry = lookup(contents, "example.com").unwrap().unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
    }

    #[test]
    fn parse_empty() {
        let entries = parse("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_login_only() {
        let contents = "machine example.com\nlogin user\n";
        let entry = lookup(contents, "example.com").unwrap().unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
        assert!(entry.password.is_none());
    }

    #[test]
    fn parse_account_skipped() {
        let contents = "machine example.com\nlogin user\naccount acct\npassword pass\n";
        let entry = lookup(contents, "example.com").unwrap().unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
        assert_eq!(entry.password.as_deref(), Some("pass"));
    }

    #[test]
    fn parse_quoted_password() {
        let contents =
            "machine example.com\nlogin user1\npassword \"with spaces and \\\"\\n\\r\\t\\a\"\n";
        let entry = lookup(contents, "example.com").unwrap().unwrap();
        assert_eq!(entry.login.as_deref(), Some("user1"));
        assert_eq!(entry.password.as_deref(), Some("with spaces and \"\n\r\ta"));
    }

    #[test]
    fn parse_unterminated_quote() {
        let contents = "machine example.com\nlogin user1\npassword \"unterminated\n";
        assert!(lookup(contents, "example.com").is_err());
    }
}
