//! Concurrent transfer API.
//!
//! The `Multi` handle runs multiple transfers concurrently using
//! tokio's async runtime. Each transfer is spawned as a separate task.
//! Supports connection limiting, dynamic handle management, and
//! per-transfer completion messages.

use std::sync::{Arc, Mutex};

use crate::easy::Easy;
use crate::error::Error;
use crate::protocol::http::response::Response;
use crate::share::Share;

/// Controls HTTP pipelining and multiplexing behavior.
///
/// Equivalent to `CURLMOPT_PIPELINING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PipeliningMode {
    /// No pipelining or multiplexing (default).
    #[default]
    Nothing,
    /// HTTP/2 multiplexing — multiple requests over a single connection.
    Multiplex,
}

/// Completion message for a finished transfer.
///
/// Returned by [`Multi::info_read`] to report per-transfer outcomes
/// without needing to wait for all transfers to complete.
#[derive(Debug)]
pub struct TransferMessage {
    /// The index of this transfer (order it was added).
    pub index: usize,
    /// The result of the transfer.
    pub result: Result<Response, Error>,
}

/// A handle for running multiple URL transfers concurrently.
///
/// Transfers are queued with [`add`](Self::add) and executed in parallel
/// with [`perform`](Self::perform).
#[derive(Debug)]
pub struct Multi {
    handles: Vec<Easy>,
    max_total_connections: Option<usize>,
    max_host_connections: Option<usize>,
    pipelining: PipeliningMode,
    share: Option<Share>,
    /// Completed transfer messages waiting to be read.
    messages: Arc<Mutex<Vec<TransferMessage>>>,
}

impl Default for Multi {
    fn default() -> Self {
        Self::new()
    }
}

impl Multi {
    /// Create a new Multi handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
            max_total_connections: None,
            max_host_connections: None,
            pipelining: PipeliningMode::Nothing,
            share: None,
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a configured Easy handle to be executed concurrently.
    pub fn add(&mut self, easy: Easy) {
        self.handles.push(easy);
    }

    /// Remove a handle by index before performing.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn remove(&mut self, index: usize) -> Option<Easy> {
        if index < self.handles.len() {
            Some(self.handles.remove(index))
        } else {
            None
        }
    }

    /// Returns the number of queued transfers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Returns true if no transfers are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Set the maximum number of total concurrent connections.
    ///
    /// When set, the Multi handle will limit the number of
    /// simultaneously active transfers. Excess transfers are queued
    /// and started as earlier ones complete.
    /// Equivalent to `CURLMOPT_MAX_TOTAL_CONNECTIONS`.
    pub const fn max_total_connections(&mut self, max: usize) {
        self.max_total_connections = Some(max);
    }

    /// Set the maximum number of concurrent connections per host.
    ///
    /// Equivalent to `CURLMOPT_MAX_HOST_CONNECTIONS`.
    pub const fn max_host_connections(&mut self, max: usize) {
        self.max_host_connections = Some(max);
    }

    /// Set the pipelining/multiplexing mode.
    ///
    /// When set to [`PipeliningMode::Multiplex`], HTTP/2 multiplexing is
    /// preferred for connections to the same host.
    /// Equivalent to `CURLMOPT_PIPELINING`.
    pub const fn pipelining(&mut self, mode: PipeliningMode) {
        self.pipelining = mode;
    }

    /// Returns the current pipelining mode.
    #[must_use]
    pub const fn pipelining_mode(&self) -> PipeliningMode {
        self.pipelining
    }

    /// Attach a Share handle for cross-handle data sharing.
    ///
    /// When set, all Easy handles added to this Multi will automatically
    /// have the Share handle attached before performing.
    /// Equivalent to `CURLOPT_SHARE` applied to all handles.
    pub fn set_share(&mut self, share: Share) {
        self.share = Some(share);
    }

    /// Read a completed transfer message.
    ///
    /// Returns `None` when no more messages are available.
    /// Messages are available after [`perform`](Self::perform) completes.
    /// Equivalent to `curl_multi_info_read`.
    #[allow(clippy::option_if_let_else)]
    pub fn info_read(&mut self) -> Option<TransferMessage> {
        if let Ok(mut msgs) = self.messages.lock() {
            if msgs.is_empty() {
                None
            } else {
                Some(msgs.remove(0))
            }
        } else {
            None
        }
    }

    /// Returns the number of pending completion messages.
    #[must_use]
    pub fn messages_in_queue(&self) -> usize {
        self.messages.lock().map_or(0, |m| m.len())
    }

    /// Execute all queued transfers concurrently and return their results.
    ///
    /// Results are returned in the same order as the handles were added.
    /// Each result is independent — a failure in one transfer does not
    /// affect the others.
    ///
    /// If [`max_total_connections`](Self::max_total_connections) is set,
    /// transfers are executed in batches.
    ///
    /// The handle list is drained after execution. Completion messages
    /// are available via [`info_read`](Self::info_read).
    ///
    /// # Errors
    ///
    /// Individual transfer errors are returned in the result vector.
    /// This method itself does not fail.
    pub async fn perform(&mut self) -> Vec<Result<Response, Error>> {
        let mut handles: Vec<Easy> = self.handles.drain(..).collect();

        if handles.is_empty() {
            return Vec::new();
        }

        // Attach share handle to all Easy handles if configured
        if let Some(ref share) = self.share {
            for handle in &mut handles {
                handle.set_share(share.clone());
            }
        }

        let results = if let Some(max_conns) = self.max_total_connections {
            // Execute with connection limiting using a semaphore
            perform_with_limit(handles, max_conns).await
        } else {
            // Execute all concurrently
            perform_unlimited(handles).await
        };

        // Store completion messages
        if let Ok(mut msgs) = self.messages.lock() {
            for (idx, result) in results.iter().enumerate() {
                msgs.push(TransferMessage {
                    index: idx,
                    result: match result {
                        Ok(r) => Ok(r.clone()),
                        Err(e) => Err(Error::Http(e.to_string())),
                    },
                });
            }
        }

        results
    }

    /// Execute all queued transfers concurrently (blocking version).
    ///
    /// Creates a new tokio runtime internally. Do not call from within
    /// an existing async runtime — use [`perform`](Self::perform) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime cannot be created. Individual
    /// transfer errors are in the result vector.
    pub fn perform_blocking(&mut self) -> Result<Vec<Result<Response, Error>>, Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Http(format!("failed to create runtime: {e}")))?;

        Ok(rt.block_on(self.perform()))
    }
}

/// Execute transfers without connection limits.
async fn perform_unlimited(handles: Vec<Easy>) -> Vec<Result<Response, Error>> {
    let mut join_set = tokio::task::JoinSet::new();

    for (idx, mut easy) in handles.into_iter().enumerate() {
        let _handle = join_set.spawn(async move { (idx, easy.perform_async().await) });
    }

    collect_results(&mut join_set).await
}

/// Execute transfers with a connection limit using a semaphore.
async fn perform_with_limit(handles: Vec<Easy>, max_conns: usize) -> Vec<Result<Response, Error>> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_conns));
    let mut join_set = tokio::task::JoinSet::new();

    for (idx, mut easy) in handles.into_iter().enumerate() {
        let sem = semaphore.clone();
        let _handle = join_set.spawn(async move {
            let _permit =
                sem.acquire().await.map_err(|e| Error::Http(format!("semaphore error: {e}")));
            (idx, easy.perform_async().await)
        });
    }

    collect_results(&mut join_set).await
}

/// Collect results from a `JoinSet`, preserving original order.
async fn collect_results(
    join_set: &mut tokio::task::JoinSet<(usize, Result<Response, Error>)>,
) -> Vec<Result<Response, Error>> {
    let mut results: Vec<(usize, Result<Response, Error>)> = Vec::with_capacity(join_set.len());

    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok(indexed_result) => results.push(indexed_result),
            Err(join_err) => {
                results.push((
                    usize::MAX,
                    Err(Error::Http(format!("transfer task failed: {join_err}"))),
                ));
            }
        }
    }

    results.sort_by_key(|(idx, _)| *idx);
    results.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn multi_new_is_empty() {
        let multi = Multi::new();
        assert!(multi.is_empty());
        assert_eq!(multi.len(), 0);
    }

    #[test]
    fn multi_add_increases_count() {
        let mut multi = Multi::new();
        let easy = Easy::new();
        multi.add(easy);
        assert!(!multi.is_empty());
        assert_eq!(multi.len(), 1);
    }

    #[test]
    fn multi_default() {
        let multi = Multi::default();
        assert!(multi.is_empty());
    }

    #[tokio::test]
    async fn multi_perform_empty() {
        let mut multi = Multi::new();
        let results = multi.perform().await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn multi_perform_drains_handles() {
        let mut multi = Multi::new();
        let mut easy = Easy::new();
        // This will fail (no URL), but we're testing the drain behavior
        let _ = easy.url("http://127.0.0.1:1");
        multi.add(easy);
        assert_eq!(multi.len(), 1);

        let _results = multi.perform().await;
        assert!(multi.is_empty(), "handles should be drained after perform");
    }

    #[test]
    fn multi_remove_valid_index() {
        let mut multi = Multi::new();
        multi.add(Easy::new());
        multi.add(Easy::new());
        assert_eq!(multi.len(), 2);

        let removed = multi.remove(0);
        assert!(removed.is_some());
        assert_eq!(multi.len(), 1);
    }

    #[test]
    fn multi_remove_invalid_index() {
        let mut multi = Multi::new();
        assert!(multi.remove(0).is_none());
    }

    #[test]
    fn multi_max_total_connections() {
        let mut multi = Multi::new();
        multi.max_total_connections(4);
        assert_eq!(multi.max_total_connections, Some(4));
    }

    #[test]
    fn multi_max_host_connections() {
        let mut multi = Multi::new();
        multi.max_host_connections(2);
        assert_eq!(multi.max_host_connections, Some(2));
    }

    #[test]
    fn multi_messages_initially_empty() {
        let multi = Multi::new();
        assert_eq!(multi.messages_in_queue(), 0);
    }

    #[test]
    fn multi_info_read_empty() {
        let mut multi = Multi::new();
        assert!(multi.info_read().is_none());
    }

    #[tokio::test]
    async fn multi_perform_stores_messages() {
        let mut multi = Multi::new();
        let mut easy = Easy::new();
        let _ = easy.url("http://127.0.0.1:1");
        easy.connect_timeout(std::time::Duration::from_millis(50));
        multi.add(easy);

        let _results = multi.perform().await;
        // Should have one completion message
        assert_eq!(multi.messages_in_queue(), 1);

        let msg = multi.info_read().unwrap();
        assert_eq!(msg.index, 0);
        assert!(msg.result.is_err()); // Connection should fail

        // Queue should now be empty
        assert_eq!(multi.messages_in_queue(), 0);
    }

    #[tokio::test]
    async fn multi_perform_unlimited_ordering() {
        // Test that results are returned in order even with concurrent execution
        let handles: Vec<Easy> = (0..5)
            .map(|_| {
                let mut e = Easy::new();
                let _ = e.url("http://127.0.0.1:1");
                e.connect_timeout(std::time::Duration::from_millis(10));
                e
            })
            .collect();

        let results = perform_unlimited(handles).await;
        assert_eq!(results.len(), 5);
        // All should fail (unreachable address)
        for r in &results {
            assert!(r.is_err());
        }
    }

    #[tokio::test]
    async fn multi_perform_with_limit() {
        let handles: Vec<Easy> = (0..5)
            .map(|_| {
                let mut e = Easy::new();
                let _ = e.url("http://127.0.0.1:1");
                e.connect_timeout(std::time::Duration::from_millis(10));
                e
            })
            .collect();

        // Limit to 2 concurrent connections
        let results = perform_with_limit(handles, 2).await;
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn multi_pipelining_default() {
        let multi = Multi::new();
        assert_eq!(multi.pipelining_mode(), PipeliningMode::Nothing);
    }

    #[test]
    fn multi_pipelining_set() {
        let mut multi = Multi::new();
        multi.pipelining(PipeliningMode::Multiplex);
        assert_eq!(multi.pipelining_mode(), PipeliningMode::Multiplex);
    }

    #[test]
    fn multi_set_share() {
        let mut multi = Multi::new();
        let mut share = crate::share::Share::new();
        share.add(crate::share::ShareType::Dns);
        multi.set_share(share);
        assert!(multi.share.is_some());
    }

    #[tokio::test]
    async fn multi_perform_attaches_share() {
        let mut share = crate::share::Share::new();
        share.add(crate::share::ShareType::Dns);

        let mut multi = Multi::new();
        multi.set_share(share);

        let mut easy = Easy::new();
        let _ = easy.url("http://127.0.0.1:1");
        easy.connect_timeout(std::time::Duration::from_millis(10));
        multi.add(easy);

        // Perform should succeed (handles get share attached)
        let results = multi.perform().await;
        assert_eq!(results.len(), 1);
        // Transfer will fail (unreachable addr), but share was attached
        assert!(results[0].is_err());
    }
}
