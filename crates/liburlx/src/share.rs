//! Shared state for cross-handle data sharing.
//!
//! The [`Share`] handle allows multiple [`Easy`](crate::easy::Easy) handles
//! to share DNS cache and cookie jar state. This is useful when performing
//! multiple transfers that should benefit from shared caching.
//!
//! Equivalent to libcurl's `curl_share_init` / `curl_share_setopt`.

use std::sync::{Arc, Mutex};

use crate::cookie::CookieJar;
use crate::dns::DnsCache;

/// Specifies which data types should be shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareType {
    /// Share DNS cache between handles.
    Dns,
    /// Share cookie jar between handles.
    Cookies,
}

/// Shared state container for cross-handle data sharing.
///
/// Create a `Share` handle, configure which data to share, then
/// attach it to multiple `Easy` handles. All attached handles will
/// read from and write to the same shared state.
///
/// # Example
///
/// ```no_run
/// use liburlx::{Easy, Share, ShareType};
///
/// let mut share = Share::new();
/// share.add(ShareType::Dns);
/// share.add(ShareType::Cookies);
///
/// let mut easy1 = Easy::new();
/// easy1.set_share(share.clone());
///
/// let mut easy2 = Easy::new();
/// easy2.set_share(share);
/// ```
#[derive(Debug, Clone)]
pub struct Share {
    /// Shared DNS cache (behind `Arc<Mutex>` for thread-safe access).
    dns_cache: Option<Arc<Mutex<DnsCache>>>,
    /// Shared cookie jar (behind `Arc<Mutex>` for thread-safe access).
    cookie_jar: Option<Arc<Mutex<CookieJar>>>,
}

impl Default for Share {
    fn default() -> Self {
        Self::new()
    }
}

impl Share {
    /// Create a new Share handle with no shared data.
    #[must_use]
    pub const fn new() -> Self {
        Self { dns_cache: None, cookie_jar: None }
    }

    /// Enable sharing for the given data type.
    ///
    /// When a data type is added, a shared instance is created that
    /// all attached `Easy` handles will use instead of their own.
    pub fn add(&mut self, share_type: ShareType) {
        match share_type {
            ShareType::Dns => {
                if self.dns_cache.is_none() {
                    self.dns_cache = Some(Arc::new(Mutex::new(DnsCache::new())));
                }
            }
            ShareType::Cookies => {
                if self.cookie_jar.is_none() {
                    self.cookie_jar = Some(Arc::new(Mutex::new(CookieJar::new())));
                }
            }
        }
    }

    /// Disable sharing for the given data type.
    pub fn remove(&mut self, share_type: ShareType) {
        match share_type {
            ShareType::Dns => self.dns_cache = None,
            ShareType::Cookies => self.cookie_jar = None,
        }
    }

    /// Returns the shared DNS cache, if DNS sharing is enabled.
    #[must_use]
    pub const fn dns_cache(&self) -> Option<&Arc<Mutex<DnsCache>>> {
        self.dns_cache.as_ref()
    }

    /// Returns the shared cookie jar, if cookie sharing is enabled.
    #[must_use]
    pub const fn cookie_jar(&self) -> Option<&Arc<Mutex<CookieJar>>> {
        self.cookie_jar.as_ref()
    }

    /// Returns true if DNS sharing is enabled.
    #[must_use]
    pub const fn shares_dns(&self) -> bool {
        self.dns_cache.is_some()
    }

    /// Returns true if cookie sharing is enabled.
    #[must_use]
    pub const fn shares_cookies(&self) -> bool {
        self.cookie_jar.is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn share_new_is_empty() {
        let share = Share::new();
        assert!(!share.shares_dns());
        assert!(!share.shares_cookies());
    }

    #[test]
    fn share_default_is_empty() {
        let share = Share::default();
        assert!(!share.shares_dns());
        assert!(!share.shares_cookies());
    }

    #[test]
    fn share_add_dns() {
        let mut share = Share::new();
        share.add(ShareType::Dns);
        assert!(share.shares_dns());
        assert!(!share.shares_cookies());
        assert!(share.dns_cache().is_some());
    }

    #[test]
    fn share_add_cookies() {
        let mut share = Share::new();
        share.add(ShareType::Cookies);
        assert!(!share.shares_dns());
        assert!(share.shares_cookies());
        assert!(share.cookie_jar().is_some());
    }

    #[test]
    fn share_add_both() {
        let mut share = Share::new();
        share.add(ShareType::Dns);
        share.add(ShareType::Cookies);
        assert!(share.shares_dns());
        assert!(share.shares_cookies());
    }

    #[test]
    fn share_remove() {
        let mut share = Share::new();
        share.add(ShareType::Dns);
        share.add(ShareType::Cookies);
        share.remove(ShareType::Dns);
        assert!(!share.shares_dns());
        assert!(share.shares_cookies());
    }

    #[test]
    fn share_add_idempotent() {
        let mut share = Share::new();
        share.add(ShareType::Dns);
        let ptr1 = Arc::as_ptr(share.dns_cache().unwrap());
        share.add(ShareType::Dns);
        let ptr2 = Arc::as_ptr(share.dns_cache().unwrap());
        // Adding again should not create a new instance
        assert_eq!(ptr1, ptr2);
    }

    #[test]
    fn share_clone_shares_same_state() {
        let mut share = Share::new();
        share.add(ShareType::Dns);
        share.add(ShareType::Cookies);

        let share2 = share.clone();

        // Cloned share should point to the same Arc
        assert!(Arc::ptr_eq(share.dns_cache().unwrap(), share2.dns_cache().unwrap()));
        assert!(Arc::ptr_eq(share.cookie_jar().unwrap(), share2.cookie_jar().unwrap()));
    }

    #[test]
    fn share_dns_cache_is_functional() {
        let mut share = Share::new();
        share.add(ShareType::Dns);

        // Store an entry through the shared cache
        {
            let mut cache = share.dns_cache().unwrap().lock().unwrap();
            cache.put(
                "example.com",
                80,
                vec![std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                    80,
                )],
            );
        }

        // Read it back through a clone — clone shares same Arc
        let share2 = share.clone();
        assert!(share2.dns_cache().unwrap().lock().unwrap().get("example.com", 80).is_some());
    }

    #[test]
    fn share_cookie_jar_is_functional() {
        let mut share = Share::new();
        share.add(ShareType::Cookies);

        // Store a cookie through the shared jar
        {
            let mut jar = share.cookie_jar().unwrap().lock().unwrap();
            jar.store_cookies(&["session=abc123"], "example.com", "/", true);
        }

        // Read it back through a clone — clone shares same Arc
        let share2 = share.clone();
        let header =
            share2.cookie_jar().unwrap().lock().unwrap().cookie_header("example.com", "/", false);
        assert!(header.is_some());
        assert!(header.unwrap().contains("session=abc123"));
    }
}
