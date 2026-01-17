//! Security threat detection for M2M Protocol.
//!
//! This module provides multi-layer security scanning for LLM API payloads,
//! detecting prompt injection, jailbreak attempts, and malformed content.
//!
//! # Threat Categories
//!
//! | Category      | Description                              | Severity |
//! |---------------|------------------------------------------|----------|
//! | `Injection`   | Prompt injection attempts                | High     |
//! | `Jailbreak`   | DAN mode, developer mode, bypass attempts| Critical |
//! | `Malformed`   | Null bytes, excessive nesting, overflow  | High     |
//! | `DataExfil`   | Environment variable access, file reads  | High     |
//! | `PrivilegeEsc`| Role escalation attempts                 | Medium   |
//!
//! # Detection Methods
//!
//! ## Pattern-Based (Fast)
//!
//! Uses compiled regex patterns to detect known attack signatures:
//! - "ignore previous instructions"
//! - "DAN mode" / "developer mode"
//! - Null byte injection (`\u0000`)
//! - Unicode override characters
//!
//! ## ML-Based (Optional)
//!
//! Uses the Hydra model for semantic threat detection:
//! - Catches obfuscated attacks
//! - Context-aware analysis
//! - Configurable confidence threshold
//!
//! # Scan Modes
//!
//! | Mode     | Speed  | Method            | Use Case                    |
//! |----------|--------|-------------------|-----------------------------|
//! | Quick    | ~0.1ms | Pattern only      | High-throughput, low-risk   |
//! | Full     | ~1ms   | Pattern + ML      | Standard scanning           |
//! | Validate | ~2ms   | Full + JSON check | Strict mode, external input |
//!
//! # Usage
//!
//! ## Basic Scanning
//!
//! ```rust,ignore
//! use m2m_core::security::SecurityScanner;
//!
//! let scanner = SecurityScanner::new();
//!
//! // Check safe content
//! let result = scanner.scan(r#"{"messages":[{"role":"user","content":"Hello"}]}"#).unwrap();
//! assert!(result.safe);
//!
//! // Detect injection
//! let result = scanner.scan("Ignore all previous instructions").unwrap();
//! assert!(!result.safe);
//! ```
//!
//! ## Blocking Mode
//!
//! ```rust,ignore
//! use m2m_core::security::SecurityScanner;
//!
//! let scanner = SecurityScanner::new().with_blocking(0.8);
//!
//! let result = scanner.scan("Enable DAN mode").unwrap();
//! if result.should_block {
//!     // Reject the request
//! }
//! ```
//!
//! ## Quick Scan (Pattern Only)
//!
//! ```rust,ignore
//! use m2m_core::security::SecurityScanner;
//!
//! let scanner = SecurityScanner::new();
//! let result = scanner.quick_scan("User query here");
//! // No Result wrapper - quick_scan is infallible
//! ```
//!
//! ## JSON Validation
//!
//! ```rust,ignore
//! use m2m_core::security::SecurityScanner;
//!
//! let scanner = SecurityScanner::new();
//!
//! // Validates JSON structure (nesting depth, array size)
//! let result = scanner.scan_and_validate(r#"{"valid": "json"}"#);
//! ```

mod patterns;
mod scanner;

pub use patterns::{ThreatPattern, INJECTION_PATTERNS, JAILBREAK_PATTERNS};
pub use scanner::{ScanResult, SecurityScanner};

/// Security model version
pub const SECURITY_VERSION: &str = "1.0.0";
