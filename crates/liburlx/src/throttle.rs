//! Transfer speed throttling and enforcement.
//!
//! Provides rate limiting for download and upload speeds, and minimum
//! speed enforcement that aborts transfers if throughput is too low.

use std::time::{Duration, Instant};

use crate::error::Error;

/// Configuration for transfer speed limits.
///
/// Bundles the four speed-related options into a single struct
/// to avoid passing them as individual parameters.
#[derive(Debug, Clone, Default)]
pub struct SpeedLimits {
    /// Maximum download speed in bytes/sec. `None` means unlimited.
    pub max_recv_speed: Option<u64>,
    /// Maximum upload speed in bytes/sec. `None` means unlimited.
    pub max_send_speed: Option<u64>,
    /// Minimum transfer speed in bytes/sec. If the speed drops below
    /// this threshold for `low_speed_time`, the transfer is aborted.
    pub low_speed_limit: Option<u32>,
    /// Time window for minimum speed enforcement. The transfer is
    /// aborted if speed stays below `low_speed_limit` for this duration.
    pub low_speed_time: Option<Duration>,
}

impl SpeedLimits {
    /// Returns `true` if any speed limit is configured.
    #[must_use]
    pub const fn has_limits(&self) -> bool {
        self.max_recv_speed.is_some()
            || self.max_send_speed.is_some()
            || (self.low_speed_limit.is_some() && self.low_speed_time.is_some())
    }
}

/// Tracks bytes transferred and enforces rate limits.
///
/// Used during body read/write to throttle transfer speed and detect
/// low-speed conditions.
pub(crate) struct RateLimiter {
    max_speed: Option<u64>,
    low_speed_limit: Option<u32>,
    low_speed_time: Option<Duration>,
    bytes_transferred: u64,
    start_time: Instant,
    /// When we first detected speed below `low_speed_limit`.
    low_speed_start: Option<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter for downloads (uses `max_recv_speed`).
    pub(crate) fn for_recv(limits: &SpeedLimits) -> Self {
        Self {
            max_speed: limits.max_recv_speed,
            low_speed_limit: limits.low_speed_limit,
            low_speed_time: limits.low_speed_time,
            bytes_transferred: 0,
            start_time: Instant::now(),
            low_speed_start: None,
        }
    }

    /// Create a new rate limiter for uploads (uses `max_send_speed`).
    pub(crate) fn for_send(limits: &SpeedLimits) -> Self {
        Self {
            max_speed: limits.max_send_speed,
            low_speed_limit: limits.low_speed_limit,
            low_speed_time: limits.low_speed_time,
            bytes_transferred: 0,
            start_time: Instant::now(),
            low_speed_start: None,
        }
    }

    /// Returns `true` if any limit is active.
    pub(crate) const fn is_active(&self) -> bool {
        self.max_speed.is_some()
            || (self.low_speed_limit.is_some() && self.low_speed_time.is_some())
    }

    /// Record bytes transferred, enforce rate limit (sleep if needed),
    /// and check minimum speed.
    ///
    /// # Errors
    ///
    /// Returns `Error::SpeedLimit` if speed stays below `low_speed_limit`
    /// for longer than `low_speed_time`.
    pub(crate) async fn record(&mut self, bytes: usize) -> Result<(), Error> {
        self.bytes_transferred += bytes as u64;

        // Check low speed enforcement
        self.check_low_speed()?;

        // Enforce max speed by sleeping
        self.throttle().await;

        Ok(())
    }

    /// Check if the transfer speed is below the minimum threshold.
    fn check_low_speed(&mut self) -> Result<(), Error> {
        let (Some(limit), Some(time)) = (self.low_speed_limit, self.low_speed_time) else {
            return Ok(());
        };

        let elapsed = self.start_time.elapsed();
        // Don't check speed in the first 100ms — not enough data
        if elapsed < Duration::from_millis(100) {
            return Ok(());
        }

        #[allow(clippy::cast_precision_loss)]
        let current_speed = self.bytes_transferred as f64 / elapsed.as_secs_f64();

        #[allow(clippy::cast_precision_loss)]
        if current_speed < f64::from(limit) {
            match self.low_speed_start {
                None => {
                    self.low_speed_start = Some(Instant::now());
                }
                Some(start) => {
                    if start.elapsed() >= time {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        return Err(Error::SpeedLimit {
                            speed: current_speed.max(0.0) as u64,
                            limit: u64::from(limit),
                            duration: start.elapsed(),
                        });
                    }
                }
            }
        } else {
            // Speed is OK — reset low speed timer
            self.low_speed_start = None;
        }

        Ok(())
    }

    /// Sleep if needed to enforce max speed.
    async fn throttle(&self) {
        let Some(max_speed) = self.max_speed else {
            return;
        };
        if max_speed == 0 {
            return;
        }

        let elapsed = self.start_time.elapsed();
        #[allow(clippy::cast_precision_loss)]
        let expected_time =
            Duration::from_secs_f64(self.bytes_transferred as f64 / max_speed as f64);

        if let Some(delay) = expected_time.checked_sub(elapsed) {
            tokio::time::sleep(delay).await;
        }
    }
}

/// Size of chunks used for throttled reads and writes.
/// 16 KB provides good granularity for rate limiting while keeping
/// system call overhead reasonable.
pub(crate) const THROTTLE_CHUNK_SIZE: usize = 16 * 1024;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn speed_limits_default_has_no_limits() {
        let limits = SpeedLimits::default();
        assert!(!limits.has_limits());
    }

    #[test]
    fn speed_limits_has_limits_with_recv() {
        let limits = SpeedLimits { max_recv_speed: Some(1024), ..Default::default() };
        assert!(limits.has_limits());
    }

    #[test]
    fn speed_limits_has_limits_with_send() {
        let limits = SpeedLimits { max_send_speed: Some(1024), ..Default::default() };
        assert!(limits.has_limits());
    }

    #[test]
    fn speed_limits_has_limits_with_low_speed() {
        let limits = SpeedLimits {
            low_speed_limit: Some(100),
            low_speed_time: Some(Duration::from_secs(10)),
            ..Default::default()
        };
        assert!(limits.has_limits());
    }

    #[test]
    fn speed_limits_no_limits_with_only_low_speed_limit() {
        // Both low_speed_limit AND low_speed_time are needed
        let limits = SpeedLimits { low_speed_limit: Some(100), ..Default::default() };
        assert!(!limits.has_limits());
    }

    #[test]
    fn rate_limiter_inactive_by_default() {
        let limits = SpeedLimits::default();
        let limiter = RateLimiter::for_recv(&limits);
        assert!(!limiter.is_active());
    }

    #[test]
    fn rate_limiter_active_with_max_speed() {
        let limits = SpeedLimits { max_recv_speed: Some(1024), ..Default::default() };
        let limiter = RateLimiter::for_recv(&limits);
        assert!(limiter.is_active());
    }

    #[test]
    fn rate_limiter_for_send_uses_send_speed() {
        let limits = SpeedLimits {
            max_recv_speed: Some(1024),
            max_send_speed: Some(2048),
            ..Default::default()
        };
        let limiter = RateLimiter::for_send(&limits);
        assert!(limiter.is_active());
        assert_eq!(limiter.max_speed, Some(2048));
    }

    #[tokio::test]
    async fn rate_limiter_record_no_limits() {
        let limits = SpeedLimits::default();
        let mut limiter = RateLimiter::for_recv(&limits);
        // Should not error or block
        limiter.record(1000).await.unwrap();
        assert_eq!(limiter.bytes_transferred, 1000);
    }

    #[tokio::test]
    async fn rate_limiter_throttle_slows_transfer() {
        let limits = SpeedLimits {
            max_recv_speed: Some(1000), // 1000 bytes/sec
            ..Default::default()
        };
        let mut limiter = RateLimiter::for_recv(&limits);

        let start = Instant::now();
        // Record 1000 bytes — should need ~1 second at 1000 B/s
        limiter.record(1000).await.unwrap();
        let elapsed = start.elapsed();

        // Should have slept for approximately 1 second (minus startup time)
        // Allow generous tolerance since this is time-dependent
        assert!(elapsed >= Duration::from_millis(800), "expected >= 800ms, got {elapsed:?}");
    }

    #[tokio::test]
    async fn rate_limiter_low_speed_triggers() {
        let limits = SpeedLimits {
            low_speed_limit: Some(1_000_000), // 1 MB/s minimum
            low_speed_time: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        let mut limiter = RateLimiter::for_recv(&limits);

        // Wait past the initial 100ms guard
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Transfer very few bytes — this sets low_speed_start
        limiter.record(1).await.unwrap();

        // Sleep past the low speed window
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Next record should detect low speed exceeded the time window
        let result = limiter.record(1).await;
        assert!(result.is_err(), "expected SpeedLimit error");
        let err = result.unwrap_err();
        assert!(matches!(err, Error::SpeedLimit { .. }), "expected SpeedLimit, got {err:?}");
    }

    #[tokio::test]
    async fn rate_limiter_low_speed_resets_on_fast() {
        let limits = SpeedLimits {
            low_speed_limit: Some(100), // 100 B/s minimum
            low_speed_time: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        let mut limiter = RateLimiter::for_recv(&limits);

        // Transfer enough to be above the limit
        limiter.record(10_000).await.unwrap();

        // Low speed start should not be set
        assert!(limiter.low_speed_start.is_none());
    }
}
