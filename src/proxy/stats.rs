//! Proxy statistics tracking.
//!
//! Tracks compression savings, request counts, latencies, and bandwidth.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Thread-safe proxy statistics
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Total requests processed
    requests: AtomicU64,
    /// Total streaming requests
    streaming_requests: AtomicU64,
    /// Total bytes received (uncompressed)
    bytes_in: AtomicU64,
    /// Total bytes sent (compressed)
    bytes_out: AtomicU64,
    /// Total bytes saved
    bytes_saved: AtomicU64,
    /// Total errors
    errors: AtomicU64,
    /// Request latencies (for percentile calculation)
    latencies: RwLock<Vec<Duration>>,
    /// Start time
    started_at: RwLock<Option<Instant>>,
}

impl ProxyStats {
    /// Create new stats tracker
    pub fn new() -> Self {
        Self {
            started_at: RwLock::new(Some(Instant::now())),
            ..Default::default()
        }
    }

    /// Record a completed request
    pub fn record_request(&self, bytes_in: usize, bytes_out: usize, latency: Duration) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in as u64, Ordering::Relaxed);
        self.bytes_out
            .fetch_add(bytes_out as u64, Ordering::Relaxed);

        if bytes_in > bytes_out {
            self.bytes_saved
                .fetch_add((bytes_in - bytes_out) as u64, Ordering::Relaxed);
        }

        if let Ok(mut latencies) = self.latencies.write() {
            latencies.push(latency);
            // Keep last 1000 latencies for percentile calculation
            if latencies.len() > 1000 {
                latencies.remove(0);
            }
        }
    }

    /// Record a streaming request
    pub fn record_streaming_request(&self) {
        self.streaming_requests.fetch_add(1, Ordering::Relaxed);
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record streaming chunk
    pub fn record_streaming_chunk(&self, bytes_in: usize, bytes_out: usize) {
        self.bytes_in.fetch_add(bytes_in as u64, Ordering::Relaxed);
        self.bytes_out
            .fetch_add(bytes_out as u64, Ordering::Relaxed);

        if bytes_in > bytes_out {
            self.bytes_saved
                .fetch_add((bytes_in - bytes_out) as u64, Ordering::Relaxed);
        }
    }

    /// Record an error
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total requests
    pub fn total_requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Get streaming requests count
    pub fn streaming_requests(&self) -> u64 {
        self.streaming_requests.load(Ordering::Relaxed)
    }

    /// Get total bytes in
    pub fn total_bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    /// Get total bytes out
    pub fn total_bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    /// Get total bytes saved
    pub fn total_bytes_saved(&self) -> u64 {
        self.bytes_saved.load(Ordering::Relaxed)
    }

    /// Get total errors
    pub fn total_errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Get compression ratio (0.0-1.0, lower is better)
    pub fn compression_ratio(&self) -> f64 {
        let bytes_in = self.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.bytes_out.load(Ordering::Relaxed);

        if bytes_in == 0 {
            1.0
        } else {
            bytes_out as f64 / bytes_in as f64
        }
    }

    /// Get savings percentage
    pub fn savings_percent(&self) -> f64 {
        (1.0 - self.compression_ratio()) * 100.0
    }

    /// Get p50 latency
    pub fn p50_latency(&self) -> Option<Duration> {
        self.percentile_latency(50)
    }

    /// Get p95 latency
    pub fn p95_latency(&self) -> Option<Duration> {
        self.percentile_latency(95)
    }

    /// Get p99 latency
    pub fn p99_latency(&self) -> Option<Duration> {
        self.percentile_latency(99)
    }

    /// Calculate percentile latency
    fn percentile_latency(&self, percentile: usize) -> Option<Duration> {
        let latencies = self.latencies.read().ok()?;
        if latencies.is_empty() {
            return None;
        }

        let mut sorted: Vec<_> = latencies.iter().copied().collect();
        sorted.sort();

        let idx = (sorted.len() * percentile / 100).min(sorted.len() - 1);
        Some(sorted[idx])
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.started_at
            .read()
            .ok()
            .and_then(|s| s.map(|start| start.elapsed()))
            .unwrap_or_default()
    }

    /// Get requests per second
    pub fn requests_per_second(&self) -> f64 {
        let uptime = self.uptime().as_secs_f64();
        if uptime > 0.0 {
            self.total_requests() as f64 / uptime
        } else {
            0.0
        }
    }

    /// Get summary as JSON-compatible struct
    pub fn summary(&self) -> StatsSummary {
        StatsSummary {
            total_requests: self.total_requests(),
            streaming_requests: self.streaming_requests(),
            total_errors: self.total_errors(),
            bytes_in: self.total_bytes_in(),
            bytes_out: self.total_bytes_out(),
            bytes_saved: self.total_bytes_saved(),
            compression_ratio: self.compression_ratio(),
            savings_percent: self.savings_percent(),
            p50_latency_ms: self.p50_latency().map(|d| d.as_secs_f64() * 1000.0),
            p95_latency_ms: self.p95_latency().map(|d| d.as_secs_f64() * 1000.0),
            p99_latency_ms: self.p99_latency().map(|d| d.as_secs_f64() * 1000.0),
            uptime_secs: self.uptime().as_secs(),
            requests_per_second: self.requests_per_second(),
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.requests.store(0, Ordering::Relaxed);
        self.streaming_requests.store(0, Ordering::Relaxed);
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.bytes_saved.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);

        if let Ok(mut latencies) = self.latencies.write() {
            latencies.clear();
        }

        if let Ok(mut started) = self.started_at.write() {
            *started = Some(Instant::now());
        }
    }
}

/// Statistics summary for serialization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatsSummary {
    /// Total number of requests processed.
    pub total_requests: u64,
    /// Number of streaming requests.
    pub streaming_requests: u64,
    /// Total number of errors encountered.
    pub total_errors: u64,
    /// Total bytes received.
    pub bytes_in: u64,
    /// Total bytes sent (after compression).
    pub bytes_out: u64,
    /// Total bytes saved by compression.
    pub bytes_saved: u64,
    /// Overall compression ratio.
    pub compression_ratio: f64,
    /// Percentage of bytes saved.
    pub savings_percent: f64,
    /// 50th percentile latency in milliseconds.
    pub p50_latency_ms: Option<f64>,
    /// 95th percentile latency in milliseconds.
    pub p95_latency_ms: Option<f64>,
    /// 99th percentile latency in milliseconds.
    pub p99_latency_ms: Option<f64>,
    /// Server uptime in seconds.
    pub uptime_secs: u64,
    /// Average requests per second.
    pub requests_per_second: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_recording() {
        let stats = ProxyStats::new();

        stats.record_request(1000, 700, Duration::from_millis(50));
        stats.record_request(2000, 1400, Duration::from_millis(100));

        assert_eq!(stats.total_requests(), 2);
        assert_eq!(stats.total_bytes_in(), 3000);
        assert_eq!(stats.total_bytes_out(), 2100);
        assert_eq!(stats.total_bytes_saved(), 900);
    }

    #[test]
    fn test_compression_ratio() {
        let stats = ProxyStats::new();

        stats.record_request(1000, 700, Duration::from_millis(50));

        assert!((stats.compression_ratio() - 0.7).abs() < 0.01);
        assert!((stats.savings_percent() - 30.0).abs() < 0.1);
    }

    #[test]
    fn test_latency_percentiles() {
        let stats = ProxyStats::new();

        // Add 100 latencies
        for i in 1..=100 {
            stats.record_request(100, 70, Duration::from_millis(i));
        }

        let p50 = stats.p50_latency().unwrap();
        let p95 = stats.p95_latency().unwrap();
        let p99 = stats.p99_latency().unwrap();

        assert!(p50.as_millis() >= 49 && p50.as_millis() <= 51);
        assert!(p95.as_millis() >= 94 && p95.as_millis() <= 96);
        assert!(p99.as_millis() >= 98 && p99.as_millis() <= 100);
    }

    #[test]
    fn test_streaming_stats() {
        let stats = ProxyStats::new();

        stats.record_streaming_request();
        stats.record_streaming_chunk(100, 70);
        stats.record_streaming_chunk(100, 70);

        assert_eq!(stats.streaming_requests(), 1);
        assert_eq!(stats.total_requests(), 1);
        assert_eq!(stats.total_bytes_in(), 200);
        assert_eq!(stats.total_bytes_out(), 140);
    }
}
