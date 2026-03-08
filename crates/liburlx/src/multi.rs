//! Concurrent transfer API.
//!
//! The `Multi` handle runs multiple transfers concurrently using
//! tokio's async runtime. Each transfer is spawned as a separate task.

use crate::easy::Easy;
use crate::error::Error;
use crate::protocol::http::response::Response;

/// A handle for running multiple URL transfers concurrently.
///
/// Transfers are queued with [`add`](Self::add) and executed in parallel
/// with [`perform`](Self::perform).
#[derive(Debug, Default)]
pub struct Multi {
    handles: Vec<Easy>,
}

impl Multi {
    /// Create a new Multi handle.
    #[must_use]
    pub const fn new() -> Self {
        Self { handles: Vec::new() }
    }

    /// Add a configured Easy handle to be executed concurrently.
    pub fn add(&mut self, easy: Easy) {
        self.handles.push(easy);
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

    /// Execute all queued transfers concurrently and return their results.
    ///
    /// Results are returned in the same order as the handles were added.
    /// Each result is independent — a failure in one transfer does not
    /// affect the others.
    ///
    /// The handle list is drained after execution.
    ///
    /// # Errors
    ///
    /// Individual transfer errors are returned in the result vector.
    /// This method itself does not fail.
    pub async fn perform(&mut self) -> Vec<Result<Response, Error>> {
        let handles: Vec<Easy> = self.handles.drain(..).collect();

        if handles.is_empty() {
            return Vec::new();
        }

        let mut join_set = tokio::task::JoinSet::new();

        // Spawn all transfers, tracking their index for ordering
        for (idx, easy) in handles.into_iter().enumerate() {
            let _handle = join_set.spawn(async move { (idx, easy.perform_async().await) });
        }

        // Collect results, preserving original order
        let mut results: Vec<(usize, Result<Response, Error>)> = Vec::with_capacity(join_set.len());

        while let Some(join_result) = join_set.join_next().await {
            match join_result {
                Ok(indexed_result) => results.push(indexed_result),
                Err(join_err) => {
                    // JoinError means the task panicked — shouldn't happen
                    // but we need to handle it gracefully
                    results.push((
                        usize::MAX,
                        Err(Error::Http(format!("transfer task failed: {join_err}"))),
                    ));
                }
            }
        }

        // Sort by original index to maintain order
        results.sort_by_key(|(idx, _)| *idx);
        results.into_iter().map(|(_, result)| result).collect()
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
}
