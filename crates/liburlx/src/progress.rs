//! Progress reporting for transfers.
//!
//! Provides a callback mechanism for monitoring transfer progress,
//! including bytes downloaded/uploaded, total sizes, and transfer speed.

use std::sync::{Arc, Mutex};

/// Information about the current transfer progress.
#[derive(Debug, Clone)]
pub struct ProgressInfo {
    /// Total bytes expected to download (from Content-Length), 0 if unknown.
    pub dl_total: u64,
    /// Bytes downloaded so far.
    pub dl_now: u64,
    /// Total bytes to upload (request body size), 0 if none.
    pub ul_total: u64,
    /// Bytes uploaded so far.
    pub ul_now: u64,
}

/// A thread-safe progress callback.
///
/// Return `false` from the callback to abort the transfer.
pub type ProgressCallback = Arc<Mutex<dyn FnMut(&ProgressInfo) -> bool + Send>>;

/// Create a new progress callback from a closure.
pub fn make_progress_callback<F>(f: F) -> ProgressCallback
where
    F: FnMut(&ProgressInfo) -> bool + Send + 'static,
{
    Arc::new(Mutex::new(f))
}

/// Call a progress callback, returning true to continue or false to abort.
///
/// If the mutex is poisoned, returns true (continue) to avoid aborting
/// on a non-transfer error.
pub fn call_progress(callback: &ProgressCallback, info: &ProgressInfo) -> bool {
    callback.lock().map_or(true, |mut f| f(info))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn progress_info_default_values() {
        let info = ProgressInfo { dl_total: 1000, dl_now: 500, ul_total: 0, ul_now: 0 };
        assert_eq!(info.dl_total, 1000);
        assert_eq!(info.dl_now, 500);
    }

    #[test]
    fn progress_callback_invoked() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        let cb = make_progress_callback(move |info: &ProgressInfo| {
            *called_clone.lock().unwrap() = true;
            assert_eq!(info.dl_now, 100);
            true
        });

        let info = ProgressInfo { dl_total: 200, dl_now: 100, ul_total: 0, ul_now: 0 };
        let result = call_progress(&cb, &info);
        assert!(result);
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn progress_callback_abort() {
        let cb = make_progress_callback(|_| false);
        let info = ProgressInfo { dl_total: 100, dl_now: 50, ul_total: 0, ul_now: 0 };
        let result = call_progress(&cb, &info);
        assert!(!result);
    }

    #[test]
    fn progress_callback_tracks_incremental() {
        let values = Arc::new(Mutex::new(Vec::new()));
        let values_clone = values.clone();

        let cb = make_progress_callback(move |info: &ProgressInfo| {
            values_clone.lock().unwrap().push(info.dl_now);
            true
        });

        for i in &[0, 25, 50, 75, 100] {
            let info = ProgressInfo { dl_total: 100, dl_now: *i, ul_total: 0, ul_now: 0 };
            let _ = call_progress(&cb, &info);
        }

        assert_eq!(*values.lock().unwrap(), vec![0, 25, 50, 75, 100]);
    }

    #[test]
    fn progress_info_clone() {
        let info = ProgressInfo { dl_total: 1000, dl_now: 500, ul_total: 200, ul_now: 100 };
        let cloned = info.clone();
        assert_eq!(cloned.dl_total, info.dl_total);
        assert_eq!(cloned.ul_now, info.ul_now);
    }
}
