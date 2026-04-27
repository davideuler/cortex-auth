//! Simple in-memory rate limiter: sliding-window counter keyed by arbitrary
//! string (IP address, device_code, etc.).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    data: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            data: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` (allowed) or `false` (rate-limited).
    ///
    /// Allows at most `max_count` requests per `window_secs`-second sliding
    /// window for the given `key`. The request is counted even when allowed,
    /// so subsequent calls reflect the new count.
    pub fn check(&self, key: &str, max_count: usize, window_secs: u64) -> bool {
        let window = Duration::from_secs(window_secs);
        let now = Instant::now();
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let queue = data.entry(key.to_string()).or_default();

        // Drop timestamps outside the sliding window.
        while queue
            .front()
            .map(|t| now.duration_since(*t) > window)
            .unwrap_or(false)
        {
            queue.pop_front();
        }

        if queue.len() >= max_count {
            return false;
        }
        queue.push_back(now);
        true
    }

    /// Prune all keys whose last request is older than `max_window_secs`.
    /// Call this from a background task to prevent unbounded memory growth.
    pub fn cleanup(&self, max_window_secs: u64) {
        let window = Duration::from_secs(max_window_secs);
        let now = Instant::now();
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        data.retain(|_, queue| {
            while queue
                .front()
                .map(|t| now.duration_since(*t) > window)
                .unwrap_or(false)
            {
                queue.pop_front();
            }
            !queue.is_empty()
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
