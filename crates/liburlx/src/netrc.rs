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

/// Parse a `.netrc` file and look up credentials for a host.
///
/// Returns the matching entry for the given hostname, or the `default`
/// entry if no host-specific entry matches.
#[must_use]
pub fn lookup(contents: &str, hostname: &str) -> Option<NetrcEntry> {
    let entries = parse(contents);
    // First try exact machine match
    let exact = entries
        .iter()
        .find(|e| e.machine.as_ref().is_some_and(|m| m.eq_ignore_ascii_case(hostname)));
    if let Some(entry) = exact {
        return Some(entry.clone());
    }
    // Fall back to default entry
    entries.into_iter().find(|e| e.machine.is_none())
}

/// Parse all entries from a `.netrc` file.
fn parse(contents: &str) -> Vec<NetrcEntry> {
    let mut entries = Vec::new();
    let mut current: Option<NetrcEntry> = None;

    // Tokenize: split on whitespace, treating each word as a token.
    // Comments start with # and run to end of line.
    let mut tokens = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        for word in line.split_whitespace() {
            if word.starts_with('#') {
                break;
            }
            tokens.push(word.to_string());
        }
    }

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

    entries
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_netrc() {
        let contents = "machine example.com\nlogin myuser\npassword mypass\n";
        let entry = lookup(contents, "example.com").unwrap();
        assert_eq!(entry.machine.as_deref(), Some("example.com"));
        assert_eq!(entry.login.as_deref(), Some("myuser"));
        assert_eq!(entry.password.as_deref(), Some("mypass"));
    }

    #[test]
    fn parse_no_match() {
        let contents = "machine example.com\nlogin myuser\npassword mypass\n";
        let entry = lookup(contents, "other.com");
        assert!(entry.is_none());
    }

    #[test]
    fn parse_default_fallback() {
        let contents = "machine example.com\nlogin user1\npassword pass1\n\ndefault\nlogin anonymous\npassword anon@\n";
        let entry = lookup(contents, "other.com").unwrap();
        assert!(entry.machine.is_none());
        assert_eq!(entry.login.as_deref(), Some("anonymous"));
        assert_eq!(entry.password.as_deref(), Some("anon@"));
    }

    #[test]
    fn parse_case_insensitive_host() {
        let contents = "machine Example.COM\nlogin user\npassword pass\n";
        let entry = lookup(contents, "example.com").unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
    }

    #[test]
    fn parse_multiple_machines() {
        let contents = "machine a.com\nlogin a\npassword pa\nmachine b.com\nlogin b\npassword pb\n";
        let a = lookup(contents, "a.com").unwrap();
        assert_eq!(a.login.as_deref(), Some("a"));
        let b = lookup(contents, "b.com").unwrap();
        assert_eq!(b.login.as_deref(), Some("b"));
    }

    #[test]
    fn parse_inline_format() {
        let contents = "machine example.com login user password pass\n";
        let entry = lookup(contents, "example.com").unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
        assert_eq!(entry.password.as_deref(), Some("pass"));
    }

    #[test]
    fn parse_comments() {
        let contents = "# this is a comment\nmachine example.com\n# another comment\nlogin user\npassword pass\n";
        let entry = lookup(contents, "example.com").unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
    }

    #[test]
    fn parse_empty() {
        let entries = parse("");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_login_only() {
        let contents = "machine example.com\nlogin user\n";
        let entry = lookup(contents, "example.com").unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
        assert!(entry.password.is_none());
    }

    #[test]
    fn parse_account_skipped() {
        let contents = "machine example.com\nlogin user\naccount acct\npassword pass\n";
        let entry = lookup(contents, "example.com").unwrap();
        assert_eq!(entry.login.as_deref(), Some("user"));
        assert_eq!(entry.password.as_deref(), Some("pass"));
    }
}
