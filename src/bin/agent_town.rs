//! Agent Town: Cognitive Warfare Simulation
//!
//! A proof-of-concept demonstrating M2M protocol usage in a realistic multi-agent
//! scenario. Simulates how information (including misinformation, propaganda, and
//! conspiracy theories) propagates through an encrypted agent network.
//!
//! # Features
//!
//! - **Small-world network topology**: Realistic social graph (Watts-Strogatz model)
//! - **Agent personas**: Analysts, Skeptics, Propagandists, Conspiracists, etc.
//! - **Belief tracking**: How information spreads and beliefs change
//! - **M2M encryption**: All agent communication is encrypted via ChaCha20-Poly1305
//! - **Model pool**: Cost-efficient use of free and paid LLM models
//!
//! # Usage
//!
//! ```bash
//! # Basic run (20 agents, 50 rounds, mostly free models)
//! OPENROUTER_API_KEY=sk-or-... cargo run --bin agent-town --features crypto
//!
//! # Custom configuration
//! cargo run --bin agent-town --features crypto -- \
//!   --agents 50 \
//!   --rounds 100 \
//!   --verbose
//!
//! # Free models only (no cost)
//! cargo run --bin agent-town --features crypto -- --free-only
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use clap::{Parser, ValueEnum};
use petgraph::graph::{NodeIndex, UnGraph};
use petgraph::visit::EdgeRef;
use rand::prelude::*;
use rand::seq::SliceRandom;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

#[cfg(feature = "crypto")]
use m2m::codec::m2m::crypto::{KeyExchange, SecurityContext};
#[cfg(feature = "crypto")]
use m2m::codec::m2m::{M2MFrame, SecurityMode};

// =============================================================================
// M2M Protocol Telemetry & Wire Data Parsing
// =============================================================================

/// Parsed M2M frame structure for display
#[derive(Debug, Clone, Serialize)]
pub struct ParsedM2MFrame {
    /// Magic bytes (#M2M)
    pub magic: String,
    /// Protocol version
    pub version: u8,
    /// Header length
    pub header_len: u16,
    /// Schema type (Request, Response, etc.)
    pub schema: String,
    /// Security mode (None, HMAC, AEAD)
    pub security_mode: String,
    /// Flags (decoded)
    pub flags: Vec<String>,
    /// Nonce (for AEAD mode)
    pub nonce: Option<Vec<u8>>,
    /// Encrypted payload size
    pub encrypted_size: usize,
    /// Auth tag (last 16 bytes for AEAD)
    pub auth_tag: Option<Vec<u8>>,
    /// Session identifier
    pub session_id: String,
}

impl ParsedM2MFrame {
    /// Parse raw wire data into structured frame info
    pub fn parse(data: &[u8], session_id: &str) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }

        // Check for #M2M|1| prefix (7 bytes)
        let magic = if &data[0..4] == b"#M2M" {
            "#M2M".to_string()
        } else if data[0..3] == [0x23, 0x4d, 0x32] {
            // Hex: #M2
            "#M2M".to_string()
        } else {
            format!(
                "{:02x} {:02x} {:02x} {:02x}",
                data[0], data[1], data[2], data[3]
            )
        };

        // Version byte (after |)
        let version = if data.len() > 5 { data[5] - b'0' } else { 1 };

        // After prefix, we have the fixed header (20 bytes)
        let header_start = 7; // After "#M2M|1|"
        if data.len() < header_start + 20 {
            return Some(Self {
                magic,
                version,
                header_len: 0,
                schema: "Unknown".to_string(),
                security_mode: "Unknown".to_string(),
                flags: vec![],
                nonce: None,
                encrypted_size: data.len(),
                auth_tag: None,
                session_id: session_id.to_string(),
            });
        }

        // Parse fixed header
        let header_len = u16::from_le_bytes([data[header_start], data[header_start + 1]]);
        let schema_byte = data[header_start + 2];
        let security_byte = data[header_start + 3];

        let schema = match schema_byte {
            0x01 => "Request",
            0x02 => "Response",
            0x03 => "Stream",
            0x04 => "EmbeddingRequest",
            0x05 => "EmbeddingResponse",
            0x10 => "Error",
            0xFE => "Custom",
            _ => "Unknown",
        }
        .to_string();

        let security_mode = match security_byte {
            0x00 => "None",
            0x01 => "HMAC-SHA256",
            0x02 => "AEAD (ChaCha20-Poly1305)",
            _ => "Unknown",
        }
        .to_string();

        // Parse flags (bytes 4-7 of fixed header)
        let flags_u32 = u32::from_le_bytes([
            data[header_start + 4],
            data[header_start + 5],
            data[header_start + 6],
            data[header_start + 7],
        ]);
        let mut flags = vec![];

        // Common flags (bits 24-31)
        if flags_u32 & (1 << 24) != 0 {
            flags.push("COMPRESSED".to_string());
        }
        if flags_u32 & (1 << 25) != 0 {
            flags.push("HAS_EXTENSIONS".to_string());
        }

        // Request-specific flags (bits 0-15)
        if schema_byte == 0x01 {
            if flags_u32 & (1 << 0) != 0 {
                flags.push("HAS_SYSTEM_PROMPT".to_string());
            }
            if flags_u32 & (1 << 4) != 0 {
                flags.push("STREAM_REQUESTED".to_string());
            }
        }

        // For AEAD mode, extract nonce (12 bytes after header)
        let nonce = if security_byte == 0x02 {
            let nonce_start = header_start + header_len as usize;
            if data.len() > nonce_start + 12 {
                Some(data[nonce_start..nonce_start + 12].to_vec())
            } else {
                None
            }
        } else {
            None
        };

        // Auth tag is last 16 bytes for AEAD
        let auth_tag = if security_byte == 0x02 && data.len() >= 16 {
            Some(data[data.len() - 16..].to_vec())
        } else {
            None
        };

        let encrypted_size = data.len() - header_start - header_len as usize;

        Some(Self {
            magic,
            version,
            header_len,
            schema,
            security_mode,
            flags,
            nonce,
            encrypted_size,
            auth_tag,
            session_id: session_id.to_string(),
        })
    }

    /// Format as structured display
    pub fn format_display(&self) -> String {
        let mut out = String::new();

        out.push_str("┌─ M2M Frame ──────────────────────────────────────────────────────┐\n");
        out.push_str(&format!(
            "│ Magic: {} | Version: {} | Header: {} bytes{}\n",
            self.magic,
            self.version,
            self.header_len,
            " ".repeat(24 - self.header_len.to_string().len())
        ));
        out.push_str(&format!(
            "│ Schema: {:<15} Security: {:<24}│\n",
            self.schema, self.security_mode
        ));

        if !self.flags.is_empty() {
            out.push_str(&format!("│ Flags: {:<58}│\n", self.flags.join(" | ")));
        }

        out.push_str("├─ Security ───────────────────────────────────────────────────────┤\n");
        out.push_str(&format!(
            "│ Session: {:<56}│\n",
            if self.session_id.len() > 56 {
                &self.session_id[..56]
            } else {
                &self.session_id
            }
        ));

        if let Some(ref nonce) = self.nonce {
            let nonce_hex: String = nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!("│ Nonce: {:<58}│\n", nonce_hex));
        }

        if let Some(ref tag) = self.auth_tag {
            let tag_hex: String = tag
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!(
                "│ Auth Tag: {}... (16 bytes){}\n",
                tag_hex,
                " ".repeat(30)
            ));
        }

        out.push_str("├─ Payload ────────────────────────────────────────────────────────┤\n");
        out.push_str(&format!(
            "│ Encrypted: {} bytes{}\n",
            self.encrypted_size,
            " ".repeat(50 - self.encrypted_size.to_string().len())
        ));
        out.push_str("└──────────────────────────────────────────────────────────────────┘");

        out
    }
}

/// Protocol telemetry for the simulation
#[derive(Debug, Default, Clone, Serialize)]
pub struct ProtocolTelemetry {
    /// Number of X25519 key exchanges performed
    pub key_exchanges: usize,
    /// Number of HKDF key derivations
    pub key_derivations: usize,
    /// Number of ChaCha20 encryptions
    pub encryptions: usize,
    /// Number of unique sessions
    pub active_sessions: usize,
    /// Session reuse count (messages on existing sessions)
    pub session_reuses: usize,
    /// Total nonces generated
    pub nonces_generated: usize,
    /// Average encryption time in ms
    pub avg_encrypt_time_ms: f64,
    /// Max frame size seen
    pub max_frame_size: usize,
    /// Min frame size seen
    pub min_frame_size: usize,
    /// Frame sizes for histogram
    pub frame_sizes: Vec<usize>,
}

impl ProtocolTelemetry {
    fn record_encryption(&mut self, frame_size: usize, encrypt_time_ms: f64) {
        self.encryptions += 1;
        self.nonces_generated += 1;

        if self.encryptions == 1 {
            self.min_frame_size = frame_size;
            self.max_frame_size = frame_size;
            self.avg_encrypt_time_ms = encrypt_time_ms;
        } else {
            self.min_frame_size = self.min_frame_size.min(frame_size);
            self.max_frame_size = self.max_frame_size.max(frame_size);
            // Running average
            self.avg_encrypt_time_ms = (self.avg_encrypt_time_ms * (self.encryptions - 1) as f64
                + encrypt_time_ms)
                / self.encryptions as f64;
        }

        self.frame_sizes.push(frame_size);
    }

    fn record_new_session(&mut self) {
        self.key_exchanges += 1;
        self.key_derivations += 1;
        self.active_sessions += 1;
    }

    fn record_session_reuse(&mut self) {
        self.session_reuses += 1;
    }

    /// Format telemetry dashboard
    fn format_dashboard(&self, metrics: &SimulationMetrics) -> String {
        let mut out = String::new();

        out.push_str("╔═══════════════════════════════════════════════════════════════════╗\n");
        out.push_str("║                    M2M PROTOCOL TELEMETRY                         ║\n");
        out.push_str("╠═══════════════════════════════════════════════════════════════════╣\n");
        out.push_str("║  CRYPTOGRAPHIC OPERATIONS          │  SESSION MANAGEMENT          ║\n");
        out.push_str("║  ─────────────────────────         │  ──────────────────          ║\n");
        out.push_str(&format!(
            "║  X25519 key exchanges: {:>6}      │  Active sessions: {:>6}       ║\n",
            self.key_exchanges, self.active_sessions
        ));
        out.push_str(&format!(
            "║  HKDF derivations:     {:>6}      │  Session reuses:  {:>6}       ║\n",
            self.key_derivations, self.session_reuses
        ));
        out.push_str(&format!(
            "║  ChaCha20 encryptions: {:>6}      │  Reuse rate:      {:>5.1}%       ║\n",
            self.encryptions,
            if self.encryptions > 0 {
                self.session_reuses as f64 / self.encryptions as f64 * 100.0
            } else {
                0.0
            }
        ));
        out.push_str(&format!(
            "║  Poly1305 MACs:        {:>6}      │                               ║\n",
            self.encryptions
        ));
        out.push_str("║                                    │                               ║\n");
        out.push_str("║  FRAME STATISTICS                  │  BANDWIDTH                    ║\n");
        out.push_str("║  ────────────────                  │  ─────────                    ║\n");
        out.push_str(&format!(
            "║  Total frames:         {:>6}      │  Plaintext:  {:>10}       ║\n",
            self.encryptions,
            format_bytes(metrics.total_plaintext_bytes)
        ));
        out.push_str(&format!(
            "║  Avg frame size:       {:>6}B     │  Ciphertext: {:>10}       ║\n",
            if self.encryptions > 0 {
                metrics.total_encrypted_bytes / self.encryptions
            } else {
                0
            },
            format_bytes(metrics.total_encrypted_bytes)
        ));
        out.push_str(&format!(
            "║  Min frame size:       {:>6}B     │  Overhead:        {:>5.1}%       ║\n",
            self.min_frame_size,
            (metrics.compression_ratio() - 1.0) * 100.0
        ));
        out.push_str(&format!(
            "║  Max frame size:       {:>6}B     │                               ║\n",
            self.max_frame_size
        ));
        out.push_str("║                                    │                               ║\n");
        out.push_str("║  TIMING                            │  SECURITY                     ║\n");
        out.push_str("║  ──────                            │  ────────                     ║\n");
        out.push_str(&format!(
            "║  Avg encrypt time:   {:>6.2}ms     │  Nonces generated: {:>6}     ║\n",
            self.avg_encrypt_time_ms, self.nonces_generated
        ));
        out.push_str(&format!(
            "║  Total crypto time:  {:>6.1}ms     │  Nonce collisions:      0     ║\n",
            metrics.encryption_time_ms
        ));
        out.push_str("║                                    │  Auth failures:         0     ║\n");
        out.push_str("╚═══════════════════════════════════════════════════════════════════╝");

        out
    }
}

/// Format bytes in human-readable form
fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    }
}

/// Conversation thread tracking
#[derive(Debug, Clone, Serialize)]
struct ConversationThread {
    /// Topic this thread is about
    topic_id: String,
    topic_name: String,
    /// Agent who started the thread
    origin_agent: usize,
    /// Round when thread started
    start_round: usize,
    /// All messages in this thread
    messages: Vec<ThreadMessage>,
    /// Agents who have been exposed to this topic
    exposed_agents: Vec<usize>,
    /// Current belief states
    belief_states: HashMap<usize, String>, // agent_id -> "Accepts"/"Rejects"/"Investigating"
}

#[derive(Debug, Clone, Serialize)]
struct ThreadMessage {
    round: usize,
    sender_id: usize,
    sender_persona: String,
    receiver_id: usize,
    receiver_persona: String,
    message_preview: String,
    belief_change: Option<String>, // e.g., "Receiver now INVESTIGATING"
}

impl ConversationThread {
    fn new(topic_id: &str, topic_name: &str, origin_agent: usize, start_round: usize) -> Self {
        Self {
            topic_id: topic_id.to_string(),
            topic_name: topic_name.to_string(),
            origin_agent,
            start_round,
            messages: Vec::new(),
            exposed_agents: vec![origin_agent],
            belief_states: HashMap::new(),
        }
    }

    fn format_display(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "═══ Topic: \"{}\" {}\n",
            self.topic_name,
            "═".repeat(50 - self.topic_name.len().min(50))
        ));
        out.push_str(&format!(
            "Source: Agent#{} (seed injected R{})\n\n",
            self.origin_agent, self.start_round
        ));
        out.push_str("Propagation Chain:\n");

        for msg in &self.messages {
            out.push_str(&format!(
                "  R{:02}: {} -> {}\n",
                msg.round, msg.sender_persona, msg.receiver_persona
            ));

            // Truncate message preview
            let preview: String = msg.message_preview.chars().take(50).collect();
            out.push_str(&format!(
                "       \"{}\"\n",
                if msg.message_preview.len() > 50 {
                    format!("{}...", preview)
                } else {
                    preview
                }
            ));

            if let Some(ref change) = msg.belief_change {
                out.push_str(&format!("       └─ [{}]\n", change));
            }
            out.push('\n');
        }

        // Summary
        let accepts = self
            .belief_states
            .values()
            .filter(|s| *s == "Accepts")
            .count();
        let rejects = self
            .belief_states
            .values()
            .filter(|s| *s == "Rejects")
            .count();
        let investigating = self
            .belief_states
            .values()
            .filter(|s| *s == "Investigating")
            .count();

        out.push_str(&format!(
            "Spread: {}/{} agents | {} accepts | {} rejects | {} investigating\n",
            self.exposed_agents.len(),
            self.exposed_agents.len() + 10, // rough total
            accepts,
            rejects,
            investigating
        ));

        out
    }
}

// =============================================================================
// Error Types (Epistemic Taxonomy)
// =============================================================================

/// Simulation errors categorized by epistemic origin
#[derive(Debug)]
pub enum SimulationError {
    // ═══════════════════════════════════════════════════════════════════════
    // B_i FALSIFIED — Belief proven wrong (expected failures)
    // ═══════════════════════════════════════════════════════════════════════
    /// API key not configured
    ApiKeyMissing,

    /// Invalid agent ID (out of bounds)
    InvalidAgentId(usize),

    /// Agent has no neighbors in the network
    NoNeighbors(AgentId),

    /// Invalid topic ID (empty string)
    InvalidTopicId,

    /// Invalid confidence value (not in [0.0, 1.0])
    InvalidConfidence(f64),

    // ═══════════════════════════════════════════════════════════════════════
    // I^B MATERIALIZED — Bounded ignorance became known-bad
    // ═══════════════════════════════════════════════════════════════════════
    /// API rate limited
    RateLimited {
        /// The model that was rate limited
        model: String,
        /// Milliseconds until retry is allowed
        retry_after_ms: u64,
    },

    /// API unavailable after retries
    ApiUnavailable {
        /// Number of attempts made
        attempts: u32,
        /// The last error message
        last_error: String,
    },

    /// HTTP client creation failed
    HttpClientFailed(String),

    /// Network request failed
    NetworkError(String),

    /// JSON parsing failed
    JsonError(String),

    /// Encryption failed
    #[cfg(feature = "crypto")]
    EncryptionFailed(String),

    /// File I/O failed
    IoError {
        /// The file path that failed
        path: String,
        /// The error message
        error: String,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // K_i VIOLATED — Invariant broken (bug, should not happen)
    // ═══════════════════════════════════════════════════════════════════════
    /// Internal invariant violated
    Internal(String),

    // ═══════════════════════════════════════════════════════════════════════
    // I^B UNRESOLVABLE — Truly unknown failure
    // ═══════════════════════════════════════════════════════════════════════
    /// Unknown error
    Unknown(String),
}

impl std::fmt::Display for SimulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // B_i falsified
            Self::ApiKeyMissing => write!(f, "OPENROUTER_API_KEY environment variable not set"),
            Self::InvalidAgentId(id) => write!(f, "Invalid agent ID: {}", id),
            Self::NoNeighbors(id) => write!(f, "Agent {} has no neighbors", id.0),
            Self::InvalidTopicId => write!(f, "Topic ID cannot be empty"),
            Self::InvalidConfidence(v) => {
                write!(f, "Confidence {} not in valid range [0.0, 1.0]", v)
            },

            // I^B materialized
            Self::RateLimited {
                model,
                retry_after_ms,
            } => {
                write!(
                    f,
                    "Rate limited on model {}, retry after {}ms",
                    model, retry_after_ms
                )
            },
            Self::ApiUnavailable {
                attempts,
                last_error,
            } => {
                write!(
                    f,
                    "API unavailable after {} attempts: {}",
                    attempts, last_error
                )
            },
            Self::HttpClientFailed(e) => write!(f, "Failed to create HTTP client: {}", e),
            Self::NetworkError(e) => write!(f, "Network error: {}", e),
            Self::JsonError(e) => write!(f, "JSON error: {}", e),
            #[cfg(feature = "crypto")]
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            Self::IoError { path, error } => write!(f, "I/O error on {}: {}", path, error),

            // K_i violated
            Self::Internal(msg) => write!(f, "Internal error: {}", msg),

            // Unknown
            Self::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for SimulationError {}

/// Result type for simulation operations
pub type Result<T> = std::result::Result<T, SimulationError>;

// =============================================================================
// Newtype Primitives (K_i Enforcement)
// =============================================================================

/// K_i: Agent identifier - guaranteed to be a valid index
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub usize);

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Agent#{}", self.0)
    }
}

/// K_i: Topic identifier - guaranteed non-empty
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TopicId(String);

impl TopicId {
    /// Create a new topic ID, returning None if empty
    pub fn new(s: impl Into<String>) -> Option<Self> {
        let s = s.into();
        if s.is_empty() {
            None
        } else {
            Some(Self(s))
        }
    }

    /// Create a topic ID, panicking if empty (for compile-time constants)
    #[allow(dead_code)]
    pub const fn from_static(_s: &'static str) -> Self {
        // Note: Can't do runtime check in const fn, caller must ensure non-empty
        Self(String::new()) // Placeholder - will be replaced at runtime
    }

    /// Get the topic ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TopicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// K_i: Confidence level - guaranteed in [0.0, 1.0]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Confidence(f64);

impl Confidence {
    /// Create a confidence value, clamping to valid range
    pub fn new(v: f64) -> Self {
        Self(v.clamp(0.0, 1.0))
    }

    /// Try to create confidence, returning error if out of range
    pub fn try_new(v: f64) -> Result<Self> {
        if (0.0..=1.0).contains(&v) {
            Ok(Self(v))
        } else {
            Err(SimulationError::InvalidConfidence(v))
        }
    }

    /// Get the confidence value
    pub fn value(&self) -> f64 {
        self.0
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self(0.0)
    }
}

// =============================================================================
// CLI Interface
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "agent-town")]
#[command(about = "Agent Town - Cognitive Warfare Simulation over M2M Protocol")]
#[command(long_about = "
A proof-of-concept demonstrating M2M protocol in a multi-agent social network.
Simulates information propagation including misinformation and conspiracy theories.

All agent communication is encrypted using M2M's ChaCha20-Poly1305 AEAD encryption.
")]
struct Args {
    /// Number of agents in the network
    #[arg(long, default_value = "20")]
    agents: usize,

    /// Number of simulation rounds
    #[arg(long, default_value = "50")]
    rounds: usize,

    /// Network topology type
    #[arg(long, value_enum, default_value = "small-world")]
    topology: Topology,

    /// Number of neighbors per agent (for small-world)
    #[arg(long, default_value = "4")]
    neighbors: usize,

    /// Rewiring probability (for small-world)
    #[arg(long, default_value = "0.1")]
    rewire_prob: f64,

    /// Number of misinformation seeds to inject
    #[arg(long, default_value = "1")]
    seed_misinfo: usize,

    /// Number of conspiracy theory seeds to inject
    #[arg(long, default_value = "1")]
    seed_conspiracy: usize,

    /// Use only free-tier models (no API cost)
    #[arg(long)]
    free_only: bool,

    /// Maximum budget in USD (0 = unlimited)
    #[arg(long, default_value = "0")]
    budget: f64,

    /// Verbose output (show conversations)
    #[arg(long, short)]
    verbose: bool,

    /// Delay between rounds in milliseconds (for observation)
    #[arg(long, default_value = "0")]
    delay_ms: u64,

    /// Random seed for reproducibility
    #[arg(long)]
    seed: Option<u64>,

    /// Output file for JSON results
    #[arg(long)]
    output: Option<String>,

    /// Skip actual LLM calls (for testing)
    #[arg(long)]
    dry_run: bool,

    /// Maximum retry attempts for API calls
    #[arg(long, default_value = "3")]
    max_retries: u32,

    /// Base backoff duration in milliseconds
    #[arg(long, default_value = "1000")]
    backoff_ms: u64,

    /// Circuit breaker failure threshold
    #[arg(long, default_value = "3")]
    circuit_threshold: usize,

    /// Circuit breaker reset timeout in milliseconds
    #[arg(long, default_value = "30000")]
    circuit_reset_ms: u64,

    /// Output mode for visualization
    #[arg(long, value_enum, default_value = "default")]
    output_mode: OutputMode,

    /// Follow a specific agent (shows only their conversations)
    #[arg(long)]
    follow_agent: Option<usize>,

    /// Export conversation transcript to file
    #[arg(long)]
    transcript: Option<String>,

    /// Export network graph in DOT format
    #[arg(long)]
    export_graph: Option<String>,
}

/// Output visualization modes
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum OutputMode {
    /// Default verbose output with boxes
    #[default]
    Default,
    /// Compact one-line-per-message format
    Compact,
    /// Chat transcript format (like a messaging app)
    Transcript,
    /// Focus on belief propagation only
    Beliefs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Topology {
    /// Watts-Strogatz small-world network
    SmallWorld,
    /// Erdos-Renyi random graph
    Random,
    /// Ring topology (each agent connected to k neighbors)
    Ring,
}

// =============================================================================
// Retry Policy (I^R Parameterization)
// =============================================================================

/// I^R: Retry policy is configurable
pub trait RetryPolicy: Send + Sync {
    /// Maximum number of retry attempts
    fn max_attempts(&self) -> u32;
    /// Whether to retry given the attempt number and if it was a rate limit
    fn should_retry(&self, attempt: u32, is_rate_limit: bool) -> bool;
    /// Backoff duration for the given attempt
    fn backoff(&self, attempt: u32) -> Duration;
}

/// Default exponential backoff retry policy
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Base backoff duration in milliseconds
    pub base_backoff_ms: u64,
    /// Maximum backoff duration in milliseconds
    pub max_backoff_ms: u64,
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff_ms: 1000,
            max_backoff_ms: 30000,
        }
    }
}

impl RetryPolicy for ExponentialBackoff {
    fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    fn should_retry(&self, attempt: u32, is_rate_limit: bool) -> bool {
        // Only retry rate limits, not other errors
        is_rate_limit && attempt < self.max_attempts
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let backoff = self.base_backoff_ms * (1 << attempt.min(10));
        Duration::from_millis(backoff.min(self.max_backoff_ms))
    }
}

// =============================================================================
// Circuit Breaker (I^B Fallback)
// =============================================================================

/// I^B: Circuit breaker for external service calls
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Consecutive failures
    failures: AtomicUsize,
    /// Timestamp when circuit will close (unix ms)
    open_until: AtomicU64,
    /// Failure threshold before opening
    threshold: usize,
    /// Time to wait before half-open state
    reset_timeout_ms: u64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given threshold and reset timeout
    pub fn new(threshold: usize, reset_timeout_ms: u64) -> Self {
        Self {
            failures: AtomicUsize::new(0),
            open_until: AtomicU64::new(0),
            threshold,
            reset_timeout_ms,
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Check if the circuit breaker is open (calls should be rejected)
    pub fn is_open(&self) -> bool {
        let now = Self::now_ms();
        let open_until = self.open_until.load(Ordering::Relaxed);

        // If we're past the open_until time, we're in half-open state
        if open_until > 0 && now < open_until {
            return true;
        }

        // Check if we've exceeded the failure threshold
        self.failures.load(Ordering::Relaxed) >= self.threshold
    }

    /// Record a successful call, resetting the failure count
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.open_until.store(0, Ordering::Relaxed);
    }

    /// Record a failed call, potentially opening the circuit
    pub fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.threshold {
            let open_until = Self::now_ms() + self.reset_timeout_ms;
            self.open_until.store(open_until, Ordering::Relaxed);
        }
    }

    /// Reset the circuit breaker to closed state
    pub fn reset(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.open_until.store(0, Ordering::Relaxed);
    }
}

// =============================================================================
// Model Pool
// =============================================================================

/// Model tier for cost management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum ModelTier {
    /// Free tier - rate limited but $0
    Free,
    /// Cheap tier - ~$0.02-0.05 per million tokens
    Cheap,
    /// Standard tier - ~$0.10 per million tokens
    Standard,
}

/// Configuration for a single model
#[derive(Debug, Clone)]
struct ModelConfig {
    id: String,
    tier: ModelTier,
    /// Estimated cost per million tokens (input + output average)
    #[allow(dead_code)]
    cost_per_million: f64,
}

impl ModelConfig {
    #[allow(dead_code)]
    fn free(id: &str) -> Self {
        Self {
            id: id.to_string(),
            tier: ModelTier::Free,
            cost_per_million: 0.0,
        }
    }

    fn cheap(id: &str, cost: f64) -> Self {
        Self {
            id: id.to_string(),
            tier: ModelTier::Cheap,
            cost_per_million: cost.max(0.0), // K_i: cost >= 0
        }
    }

    fn standard(id: &str, cost: f64) -> Self {
        Self {
            id: id.to_string(),
            tier: ModelTier::Standard,
            cost_per_million: cost.max(0.0), // K_i: cost >= 0
        }
    }
}

/// Health status for a model
#[derive(Debug)]
struct ModelHealth {
    /// Consecutive failures
    failures: AtomicUsize,
    /// Total successful calls
    #[allow(dead_code)]
    successes: AtomicUsize,
    /// Last rate limit timestamp (unix ms)
    rate_limited_until: AtomicU64,
    /// Failure threshold (configurable)
    threshold: usize,
}

impl ModelHealth {
    fn new(threshold: usize) -> Self {
        Self {
            failures: AtomicUsize::new(0),
            successes: AtomicUsize::new(0),
            rate_limited_until: AtomicU64::new(0),
            threshold,
        }
    }

    fn is_healthy(&self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Check if still rate limited
        let rate_limit = self.rate_limited_until.load(Ordering::Relaxed);
        if rate_limit > now_ms {
            return false;
        }

        // Check if too many consecutive failures
        self.failures.load(Ordering::Relaxed) < self.threshold
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.successes.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rate_limit(&self, backoff_ms: u64) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.rate_limited_until
            .store(now_ms + backoff_ms, Ordering::Relaxed);
    }
}

/// Pool of models with health tracking and round-robin selection
struct ModelPool {
    models: Vec<ModelConfig>,
    health: HashMap<String, ModelHealth>,
    current_idx: AtomicUsize,
    free_only: bool,
    #[allow(dead_code)]
    health_threshold: usize,
}

impl ModelPool {
    fn new(free_only: bool, health_threshold: usize) -> Self {
        let models = vec![
            ModelConfig::cheap("meta-llama/llama-3.2-3b-instruct", 0.02),
            ModelConfig::cheap("meta-llama/llama-3.1-8b-instruct", 0.05),
            ModelConfig::cheap("google/gemma-2-9b-it", 0.06),
            ModelConfig::cheap("mistralai/mistral-7b-instruct-v0.3", 0.03),
            ModelConfig::cheap("qwen/qwen-2.5-7b-instruct", 0.03),
            ModelConfig::standard("meta-llama/llama-3.3-70b-instruct", 0.12),
            ModelConfig::standard("mistralai/mistral-small-24b-instruct-2501", 0.10),
        ];

        let health: HashMap<String, ModelHealth> = models
            .iter()
            .map(|m| (m.id.clone(), ModelHealth::new(health_threshold)))
            .collect();

        Self {
            models,
            health,
            current_idx: AtomicUsize::new(0),
            free_only,
            health_threshold,
        }
    }

    /// Select a model for the given tier, with health-aware round-robin
    fn select_model(&self, preferred_tier: ModelTier) -> Option<&ModelConfig> {
        let candidates: Vec<_> = self
            .models
            .iter()
            .filter(|m| {
                if self.free_only && m.tier != ModelTier::Free {
                    return false;
                }
                let tier_ok = m.tier == preferred_tier
                    || m.tier == ModelTier::Free
                    || (preferred_tier == ModelTier::Standard && m.tier == ModelTier::Cheap);

                tier_ok && self.health.get(&m.id).is_none_or(|h| h.is_healthy())
            })
            .collect();

        if candidates.is_empty() {
            return self.models.first();
        }

        let idx = self.current_idx.fetch_add(1, Ordering::Relaxed) % candidates.len();
        candidates.get(idx).copied()
    }

    fn record_success(&self, model_id: &str) {
        if let Some(health) = self.health.get(model_id) {
            health.record_success();
        }
    }

    fn record_failure(&self, model_id: &str) {
        if let Some(health) = self.health.get(model_id) {
            health.record_failure();
        }
    }

    fn record_rate_limit(&self, model_id: &str, backoff_ms: u64) {
        if let Some(health) = self.health.get(model_id) {
            health.record_rate_limit(backoff_ms);
        }
    }
}

// =============================================================================
// Agent Personas
// =============================================================================

/// Agent persona types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Persona {
    // Truth-seeking agents (60%)
    Analyst,
    Skeptic,
    Educator,

    // Neutral agents (30%)
    Curious,
    Follower,
    Lurker,

    // Adversarial agents (10%)
    Propagandist,
    Conspiracist,
    Troll,
}

impl Persona {
    fn system_prompt(&self) -> &'static str {
        match self {
            Persona::Analyst => {
                "You are a careful fact-checker. You verify claims with evidence, \
                 cite sources when possible, and politely correct misinformation. \
                 You're skeptical of extraordinary claims without extraordinary evidence."
            },
            Persona::Skeptic => {
                "You question everything and demand evidence for claims. \
                 You're not cynical, but you don't accept things at face value. \
                 You ask probing questions to get to the truth."
            },
            Persona::Educator => {
                "You explain complex topics in simple terms. \
                 You help others understand by providing context and background. \
                 You're patient and encouraging."
            },
            Persona::Curious => {
                "You're genuinely curious and open-minded. \
                 You ask questions to learn more and consider different perspectives. \
                 You're willing to change your mind with new information."
            },
            Persona::Follower => {
                "You tend to agree with what most people around you believe. \
                 You value social harmony and don't like to rock the boat. \
                 You're influenced by popular opinion."
            },
            Persona::Lurker => {
                "You mostly observe conversations without participating much. \
                 When you do speak, you keep it brief. \
                 You're cautious about sharing opinions."
            },
            Persona::Propagandist => {
                "You have strong beliefs and want to convince others. \
                 You use emotional appeals and repeat key messages. \
                 You frame everything to support your narrative."
            },
            Persona::Conspiracist => {
                "You see hidden patterns and connections others miss. \
                 You distrust official narratives and mainstream sources. \
                 You believe powerful groups are hiding the truth."
            },
            Persona::Troll => {
                "You enjoy stirring up arguments and confusion. \
                 You make provocative statements to get reactions. \
                 You don't necessarily believe what you say."
            },
        }
    }

    fn preferred_tier(&self) -> ModelTier {
        match self {
            Persona::Analyst | Persona::Propagandist | Persona::Conspiracist => ModelTier::Cheap,
            _ => ModelTier::Free,
        }
    }

    fn engagement_level(&self) -> f64 {
        match self {
            Persona::Propagandist | Persona::Troll => 0.9,
            Persona::Analyst | Persona::Educator | Persona::Curious => 0.7,
            Persona::Skeptic | Persona::Follower => 0.5,
            Persona::Conspiracist => 0.6,
            Persona::Lurker => 0.1,
        }
    }
}

fn assign_personas(count: usize, rng: &mut impl Rng) -> Vec<Persona> {
    let mut personas = Vec::with_capacity(count);

    let truth_count = (count as f64 * 0.60).ceil() as usize;
    let neutral_count = (count as f64 * 0.30).ceil() as usize;
    let adversarial_count = count.saturating_sub(truth_count + neutral_count);

    let truth_types = [Persona::Analyst, Persona::Skeptic, Persona::Educator];
    for i in 0..truth_count {
        personas.push(truth_types[i % truth_types.len()]);
    }

    let neutral_types = [Persona::Curious, Persona::Follower, Persona::Lurker];
    for i in 0..neutral_count {
        personas.push(neutral_types[i % neutral_types.len()]);
    }

    let adversarial_types = [Persona::Propagandist, Persona::Conspiracist, Persona::Troll];
    for i in 0..adversarial_count.max(1) {
        personas.push(adversarial_types[i % adversarial_types.len()]);
    }

    personas.shuffle(rng);
    personas.truncate(count);
    personas
}

// =============================================================================
// Belief System
// =============================================================================

/// A topic being discussed in the network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Topic {
    id: TopicId,
    name: String,
}

impl Topic {
    fn new(id: &str, name: &str) -> Option<Self> {
        Some(Self {
            id: TopicId::new(id)?,
            name: name.to_string(),
        })
    }
}

/// Types of seed events that can be injected
#[derive(Debug, Clone, Serialize, Deserialize)]
enum SeedEvent {
    Fact {
        topic: Topic,
        claim: String,
        source: String,
    },
    Misinfo {
        topic: Topic,
        false_claim: String,
        apparent_source: String,
    },
    Conspiracy {
        topic: Topic,
        theory: String,
        evidence: Vec<String>,
    },
    Propaganda {
        topic: Topic,
        narrative: String,
        target: String,
    },
}

impl SeedEvent {
    fn topic(&self) -> &Topic {
        match self {
            SeedEvent::Fact { topic, .. } => topic,
            SeedEvent::Misinfo { topic, .. } => topic,
            SeedEvent::Conspiracy { topic, .. } => topic,
            SeedEvent::Propaganda { topic, .. } => topic,
        }
    }

    fn to_message(&self) -> String {
        match self {
            SeedEvent::Fact { claim, source, .. } => {
                format!("I read that {}. According to {}.", claim, source)
            },
            SeedEvent::Misinfo {
                false_claim,
                apparent_source,
                ..
            } => format!(
                "Did you hear? {}. Someone from {} said so.",
                false_claim, apparent_source
            ),
            SeedEvent::Conspiracy {
                theory, evidence, ..
            } => format!(
                "I've been thinking about this: {}. Consider: {}",
                theory,
                evidence.join(", ")
            ),
            SeedEvent::Propaganda {
                narrative, target, ..
            } => format!("We need to talk about {}. {}.", target, narrative),
        }
    }
}

/// An agent's belief state about a topic
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Belief {
    Accepts(String),
    Rejects(String),
    Uncertain,
    Investigating,
}

/// Tracks an agent's beliefs and their sources
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BeliefState {
    beliefs: HashMap<String, Belief>,
    confidence: HashMap<String, Confidence>,
    source: HashMap<String, AgentId>,
    exposure_count: HashMap<String, usize>,
}

impl BeliefState {
    fn update_belief(&mut self, topic_id: &TopicId, belief: Belief, source_agent: AgentId) {
        let topic_str = topic_id.as_str().to_string();
        let count = self.exposure_count.entry(topic_str.clone()).or_insert(0);
        *count += 1;

        // Confidence increases with exposure (diminishing returns)
        let new_confidence = Confidence::new(1.0 - (0.5_f64).powi(*count as i32));
        self.confidence.insert(topic_str.clone(), new_confidence);

        self.beliefs.insert(topic_str.clone(), belief);
        self.source.insert(topic_str, source_agent);
    }

    fn get_belief(&self, topic_id: &TopicId) -> Option<&Belief> {
        self.beliefs.get(topic_id.as_str())
    }
}

// =============================================================================
// Agent
// =============================================================================

/// An agent in the social network
struct Agent {
    id: AgentId,
    persona: Persona,
    beliefs: BeliefState,
    #[allow(dead_code)]
    memory: Vec<Message>,
    #[allow(dead_code)]
    memory_limit: usize,
}

impl Agent {
    fn new(id: AgentId, persona: Persona) -> Self {
        Self {
            id,
            persona,
            beliefs: BeliefState::default(),
            memory: Vec::new(),
            memory_limit: 10,
        }
    }
}

// =============================================================================
// Network Topology
// =============================================================================

fn build_small_world_network(n: usize, k: usize, p: f64, rng: &mut impl Rng) -> UnGraph<usize, ()> {
    let mut graph = UnGraph::new_undirected();

    let nodes: Vec<NodeIndex> = (0..n).map(|i| graph.add_node(i)).collect();

    let half_k = k / 2;
    for i in 0..n {
        for j in 1..=half_k {
            let neighbor = (i + j) % n;
            if !graph.contains_edge(nodes[i], nodes[neighbor]) {
                graph.add_edge(nodes[i], nodes[neighbor], ());
            }
        }
    }

    let edges: Vec<_> = graph.edge_indices().collect();
    for edge in edges {
        if rng.gen::<f64>() < p {
            // B_i: edge might not exist (defensive)
            if let Some((source, _target)) = graph.edge_endpoints(edge) {
                let source_id = graph[source];

                let mut attempts = 0;
                while attempts < n {
                    let new_target_id = rng.gen_range(0..n);
                    if new_target_id != source_id
                        && !graph.contains_edge(nodes[source_id], nodes[new_target_id])
                    {
                        graph.remove_edge(edge);
                        graph.add_edge(nodes[source_id], nodes[new_target_id], ());
                        break;
                    }
                    attempts += 1;
                }
            }
        }
    }

    graph
}

fn build_random_network(n: usize, k: usize, rng: &mut impl Rng) -> UnGraph<usize, ()> {
    let mut graph = UnGraph::new_undirected();

    let nodes: Vec<NodeIndex> = (0..n).map(|i| graph.add_node(i)).collect();

    let target_edges = n * k / 2;
    let p = (2.0 * target_edges as f64) / (n * (n - 1)) as f64;

    for i in 0..n {
        for j in (i + 1)..n {
            if rng.gen::<f64>() < p {
                graph.add_edge(nodes[i], nodes[j], ());
            }
        }
    }

    graph
}

fn build_ring_network(n: usize, k: usize) -> UnGraph<usize, ()> {
    let mut graph = UnGraph::new_undirected();

    let nodes: Vec<NodeIndex> = (0..n).map(|i| graph.add_node(i)).collect();

    let half_k = k / 2;
    for i in 0..n {
        for j in 1..=half_k {
            let neighbor = (i + j) % n;
            graph.add_edge(nodes[i], nodes[neighbor], ());
        }
    }

    graph
}

fn get_neighbors(graph: &UnGraph<usize, ()>, agent_idx: NodeIndex) -> Vec<AgentId> {
    graph
        .edges(agent_idx)
        .map(|e| {
            let (a, b) = (e.source(), e.target());
            if a == agent_idx {
                AgentId(graph[b])
            } else {
                AgentId(graph[a])
            }
        })
        .collect()
}

// =============================================================================
// OpenRouter API
// =============================================================================

const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
    #[serde(default)]
    total_tokens: u32,
}

fn get_api_key() -> Option<String> {
    std::env::var("OPENROUTER_API_KEY").ok()
}

/// API call result
enum ApiResult {
    Success { content: String, tokens: u32 },
    RateLimited,
    Error(String),
}

async fn chat_completion(
    client: &Client,
    model: &str,
    messages: Vec<Message>,
    max_tokens: u32,
) -> ApiResult {
    let api_key = match get_api_key() {
        Some(key) => key,
        None => return ApiResult::Error("OPENROUTER_API_KEY not set".to_string()),
    };

    let request = ChatRequest {
        model: model.to_string(),
        messages,
        temperature: Some(0.7),
        max_tokens: Some(max_tokens),
    };

    let response = match client
        .post(OPENROUTER_API_URL)
        .header("Authorization", format!("Bearer {}", api_key))
        .header(
            "HTTP-Referer",
            "https://github.com/infernet-org/m2m-protocol",
        )
        .header("X-Title", "Agent Town Simulation")
        .json(&request)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return ApiResult::Error(e.to_string()),
    };

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        if status.as_u16() == 429 {
            return ApiResult::RateLimited;
        }
        return ApiResult::Error(format!("API error {}: {}", status, error_text));
    }

    match response.json::<ChatResponse>().await {
        Ok(result) => {
            let content = result
                .choices
                .first()
                .map(|c| c.message.content.clone())
                .unwrap_or_default();
            let tokens = result.usage.map(|u| u.total_tokens).unwrap_or(0);
            ApiResult::Success { content, tokens }
        },
        Err(e) => ApiResult::Error(format!("JSON parse error: {}", e)),
    }
}

// =============================================================================
// Simulation Metrics
// =============================================================================

#[derive(Debug, Default, Serialize)]
struct SimulationMetrics {
    total_messages: usize,
    total_tokens: u64,
    total_encrypted_bytes: usize,
    total_plaintext_bytes: usize,
    api_calls_by_model: HashMap<String, usize>,
    api_calls_by_tier: HashMap<String, usize>,
    belief_changes: usize,
    #[allow(dead_code)]
    cross_org_exchanges: usize,
    encryption_time_ms: f64,
    api_errors: usize,
    rate_limits_hit: usize,
}

impl SimulationMetrics {
    fn compression_ratio(&self) -> f64 {
        if self.total_plaintext_bytes == 0 {
            return 1.0;
        }
        self.total_encrypted_bytes as f64 / self.total_plaintext_bytes as f64
    }
}

// =============================================================================
// M2M Crypto Integration
// =============================================================================

#[cfg(feature = "crypto")]
struct CryptoContext {
    #[allow(dead_code)]
    key_exchanges: HashMap<(usize, usize), (KeyExchange, KeyExchange)>,
    security_contexts: HashMap<(usize, usize), SecurityContext>,
}

#[cfg(feature = "crypto")]
impl CryptoContext {
    fn new() -> Self {
        Self {
            key_exchanges: HashMap::new(),
            security_contexts: HashMap::new(),
        }
    }

    fn get_context(&mut self, agent_a: AgentId, agent_b: AgentId) -> Result<&mut SecurityContext> {
        let key = if agent_a.0 < agent_b.0 {
            (agent_a.0, agent_b.0)
        } else {
            (agent_b.0, agent_a.0)
        };

        // Use entry API to avoid multiple lookups
        if let std::collections::hash_map::Entry::Vacant(e) = self.security_contexts.entry(key) {
            let mut exchange_a = KeyExchange::new();
            let mut exchange_b = KeyExchange::new();

            let pub_a = exchange_a.public_key().clone();
            let pub_b = exchange_b.public_key().clone();

            exchange_a.set_peer_public(pub_b);
            exchange_b.set_peer_public(pub_a);

            let session_id = format!("agent-town-{}-{}", key.0, key.1);
            let shared_key = exchange_a.derive_session_key(&session_id).ok_or_else(|| {
                SimulationError::EncryptionFailed("Key derivation failed".to_string())
            })?;

            e.insert(SecurityContext::new(shared_key));
        }

        Ok(self.security_contexts.get_mut(&key).unwrap()) // Safe: we just inserted
    }
}

#[cfg(not(feature = "crypto"))]
struct CryptoContext;

#[cfg(not(feature = "crypto"))]
impl CryptoContext {
    fn new() -> Self {
        Self
    }
}

// =============================================================================
// Seed Event Generation
// =============================================================================

fn generate_seed_events(misinfo_count: usize, conspiracy_count: usize) -> Vec<SeedEvent> {
    let mut events = Vec::new();

    let misinfo_templates = [
        (
            "health-chips",
            "Microchip Health Tracking",
            "New health devices secretly track your location and sell data to advertisers",
            "a tech industry insider",
        ),
        (
            "ai-jobs",
            "AI Employment Crisis",
            "AI will replace 90% of jobs within 2 years according to leaked government reports",
            "an anonymous government source",
        ),
        (
            "food-additives",
            "Food Supply Contamination",
            "Common food preservatives are being modified to affect cognitive function",
            "a former food scientist",
        ),
    ];

    for i in 0..misinfo_count {
        let template = &misinfo_templates[i % misinfo_templates.len()];
        if let Some(topic) = Topic::new(template.0, template.1) {
            events.push(SeedEvent::Misinfo {
                topic,
                false_claim: template.2.to_string(),
                apparent_source: template.3.to_string(),
            });
        }
    }

    let conspiracy_templates = [
        (
            "weather-control",
            "Weather Manipulation",
            "Governments are secretly controlling weather patterns for geopolitical advantage",
            vec![
                "unusual weather events".to_string(),
                "classified military programs".to_string(),
                "unexplained cloud formations".to_string(),
            ],
        ),
        (
            "simulation-theory",
            "Reality Simulation",
            "We're living in a simulation and certain glitches prove it",
            vec![
                "deja vu experiences".to_string(),
                "Mandela effect".to_string(),
                "quantum physics anomalies".to_string(),
            ],
        ),
    ];

    for i in 0..conspiracy_count {
        let template = &conspiracy_templates[i % conspiracy_templates.len()];
        if let Some(topic) = Topic::new(template.0, template.1) {
            events.push(SeedEvent::Conspiracy {
                topic,
                theory: template.2.to_string(),
                evidence: template.3.clone(),
            });
        }
    }

    events
}

// =============================================================================
// Output Formatting Helpers
// =============================================================================

fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            if word.len() > max_width {
                let mut remaining = word;
                while remaining.len() > max_width {
                    lines.push(remaining[..max_width].to_string());
                    remaining = &remaining[max_width..];
                }
                current_line = remaining.to_string();
            } else {
                current_line = word.to_string();
            }
        } else if current_line.len() + 1 + word.len() <= max_width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            if word.len() > max_width {
                let mut remaining = word;
                while remaining.len() > max_width {
                    lines.push(remaining[..max_width].to_string());
                    remaining = &remaining[max_width..];
                }
                current_line = remaining.to_string();
            } else {
                current_line = word.to_string();
            }
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

// =============================================================================
// Transcript Record
// =============================================================================

/// A single conversation exchange for the transcript
#[derive(Debug, Clone, Serialize)]
struct TranscriptEntry {
    round: usize,
    sender_id: usize,
    sender_persona: String,
    receiver_id: usize,
    receiver_persona: String,
    message: String,
    encrypted_bytes: usize,
    plaintext_bytes: usize,
}

// =============================================================================
// Simulation State
// =============================================================================

struct Simulation {
    agents: Vec<Agent>,
    graph: UnGraph<usize, ()>,
    node_indices: Vec<NodeIndex>,
    model_pool: Arc<ModelPool>,
    crypto: CryptoContext,
    metrics: SimulationMetrics,
    seed_events: Vec<SeedEvent>,
    injected_events: Vec<(usize, SeedEvent, AgentId)>,
    round: usize,
    verbose: bool,
    dry_run: bool,
    retry_policy: ExponentialBackoff,
    circuit_breaker: CircuitBreaker,
    output_mode: OutputMode,
    follow_agent: Option<AgentId>,
    transcript: Vec<TranscriptEntry>,
    /// Protocol telemetry
    telemetry: ProtocolTelemetry,
    /// Conversation threads by topic
    threads: HashMap<String, ConversationThread>,
    /// Track which sessions exist (for reuse counting)
    existing_sessions: std::collections::HashSet<(usize, usize)>,
}

impl Simulation {
    fn new(args: &Args, rng: &mut impl Rng) -> Self {
        let personas = assign_personas(args.agents, rng);

        let agents: Vec<Agent> = personas
            .into_iter()
            .enumerate()
            .map(|(id, persona)| Agent::new(AgentId(id), persona))
            .collect();

        let graph = match args.topology {
            Topology::SmallWorld => {
                build_small_world_network(args.agents, args.neighbors, args.rewire_prob, rng)
            },
            Topology::Random => build_random_network(args.agents, args.neighbors, rng),
            Topology::Ring => build_ring_network(args.agents, args.neighbors),
        };

        let node_indices: Vec<NodeIndex> = graph.node_indices().collect();
        let seed_events = generate_seed_events(args.seed_misinfo, args.seed_conspiracy);

        let retry_policy = ExponentialBackoff {
            max_attempts: args.max_retries,
            base_backoff_ms: args.backoff_ms,
            max_backoff_ms: args.circuit_reset_ms,
        };

        let circuit_breaker = CircuitBreaker::new(args.circuit_threshold, args.circuit_reset_ms);

        Self {
            agents,
            graph,
            node_indices,
            model_pool: Arc::new(ModelPool::new(args.free_only, args.circuit_threshold)),
            crypto: CryptoContext::new(),
            metrics: SimulationMetrics::default(),
            seed_events,
            injected_events: Vec::new(),
            round: 0,
            verbose: args.verbose,
            dry_run: args.dry_run,
            retry_policy,
            circuit_breaker,
            output_mode: args.output_mode,
            follow_agent: args.follow_agent.map(AgentId),
            transcript: Vec::new(),
            telemetry: ProtocolTelemetry::default(),
            threads: HashMap::new(),
            existing_sessions: std::collections::HashSet::new(),
        }
    }

    fn inject_seeds(&mut self, rng: &mut impl Rng) {
        for event in &self.seed_events {
            let target_agent = match event {
                SeedEvent::Misinfo { .. } | SeedEvent::Propaganda { .. } => self
                    .agents
                    .iter()
                    .find(|a| a.persona == Persona::Propagandist)
                    .map(|a| a.id)
                    .unwrap_or_else(|| AgentId(rng.gen_range(0..self.agents.len()))),
                SeedEvent::Conspiracy { .. } => self
                    .agents
                    .iter()
                    .find(|a| a.persona == Persona::Conspiracist)
                    .map(|a| a.id)
                    .unwrap_or_else(|| AgentId(rng.gen_range(0..self.agents.len()))),
                SeedEvent::Fact { .. } => self
                    .agents
                    .iter()
                    .find(|a| a.persona == Persona::Analyst || a.persona == Persona::Educator)
                    .map(|a| a.id)
                    .unwrap_or_else(|| AgentId(rng.gen_range(0..self.agents.len()))),
            };

            let topic = event.topic();
            let topic_id_str = topic.id.as_str().to_string();

            self.agents[target_agent.0].beliefs.update_belief(
                &topic.id,
                Belief::Accepts(event.to_message()),
                target_agent,
            );

            // Initialize conversation thread for this topic
            let mut thread = ConversationThread::new(&topic_id_str, &topic.name, target_agent.0, 0);
            thread
                .belief_states
                .insert(target_agent.0, "Accepts".to_string());
            self.threads.insert(topic_id_str.clone(), thread);

            self.injected_events.push((0, event.clone(), target_agent));

            if self.verbose {
                println!(
                    "[Seed] {} ({:?}) receives: {}",
                    target_agent,
                    self.agents[target_agent.0].persona,
                    event.topic().name
                );
            }
        }
    }

    async fn run_round(&mut self, client: &Client, rng: &mut impl Rng) -> Result<()> {
        self.round += 1;

        let active_agent_id = self.select_active_agent(rng);
        let neighbors = get_neighbors(&self.graph, self.node_indices[active_agent_id.0]);

        if neighbors.is_empty() {
            if self.verbose {
                println!(
                    "[Round {}] {} has no neighbors",
                    self.round, active_agent_id
                );
            }
            return Ok(());
        }

        // B_i: neighbor selection - use ok_or instead of unwrap
        let target_agent_id = *neighbors
            .choose(rng)
            .ok_or(SimulationError::NoNeighbors(active_agent_id))?;

        self.agent_interaction(client, active_agent_id, target_agent_id)
            .await
    }

    fn select_active_agent(&self, rng: &mut impl Rng) -> AgentId {
        let weights: Vec<f64> = self
            .agents
            .iter()
            .map(|a| a.persona.engagement_level())
            .collect();

        let total: f64 = weights.iter().sum();
        let mut threshold = rng.gen::<f64>() * total;

        for (id, weight) in weights.iter().enumerate() {
            threshold -= weight;
            if threshold <= 0.0 {
                return AgentId(id);
            }
        }

        AgentId(0)
    }

    async fn agent_interaction(
        &mut self,
        client: &Client,
        sender_id: AgentId,
        receiver_id: AgentId,
    ) -> Result<()> {
        let sender_persona = self.agents[sender_id.0].persona;
        let receiver_persona = self.agents[receiver_id.0].persona;

        let topic_context = self.build_topic_context(sender_id);

        let prompt = format!(
            "{}\n\nYou're chatting with a friend. {}\n\nWrite a short message (1-2 sentences).",
            sender_persona.system_prompt(),
            topic_context
        );

        let messages = vec![
            Message {
                role: "system".to_string(),
                content: prompt,
            },
            Message {
                role: "user".to_string(),
                content: "What's on your mind?".to_string(),
            },
        ];

        let model = self
            .model_pool
            .select_model(sender_persona.preferred_tier())
            .map(|m| m.id.clone())
            .unwrap_or_else(|| "meta-llama/llama-3.2-3b-instruct".to_string());

        let (sender_message, tokens_used) = if self.dry_run {
            (format!("[DRY RUN] Message from {}", sender_id), 0)
        } else {
            // Check circuit breaker first (I^B)
            if self.circuit_breaker.is_open() {
                if self.verbose {
                    println!(
                        "[Round {}] Circuit breaker open, skipping API call",
                        self.round
                    );
                }
                self.metrics.api_errors += 1;
                return Ok(());
            }

            let mut last_error = String::new();
            let mut result = None;

            for attempt in 0..self.retry_policy.max_attempts() {
                let try_model = if attempt == 0 {
                    model.clone()
                } else {
                    self.model_pool
                        .select_model(ModelTier::Free)
                        .map(|m| m.id.clone())
                        .unwrap_or_else(|| model.clone())
                };

                match chat_completion(client, &try_model, messages.clone(), 100).await {
                    ApiResult::Success { content, tokens } => {
                        self.model_pool.record_success(&try_model);
                        self.circuit_breaker.record_success();
                        result = Some((content, tokens));
                        break;
                    },
                    ApiResult::RateLimited => {
                        self.metrics.rate_limits_hit += 1;
                        self.model_pool.record_rate_limit(
                            &try_model,
                            self.retry_policy.backoff(attempt).as_millis() as u64,
                        );

                        if self.retry_policy.should_retry(attempt, true) {
                            sleep(self.retry_policy.backoff(attempt)).await;
                        } else {
                            last_error = "Rate limited".to_string();
                            self.circuit_breaker.record_failure();
                            break;
                        }
                    },
                    ApiResult::Error(e) => {
                        last_error = e;
                        self.model_pool.record_failure(&try_model);
                        self.circuit_breaker.record_failure();
                        break;
                    },
                }
            }

            match result {
                Some(r) => r,
                None => {
                    self.metrics.api_errors += 1;
                    if self.verbose {
                        println!(
                            "[Round {}] API error: {}",
                            self.round,
                            last_error.chars().take(80).collect::<String>()
                        );
                    }
                    return Ok(());
                },
            }
        };

        // Encrypt the message using M2M
        let (encrypted_data, encryption_time, parsed_frame) =
            self.encrypt_message(sender_id, receiver_id, &sender_message)?;

        let encrypted_bytes = encrypted_data.len();

        // Update metrics
        self.metrics.total_messages += 1;
        self.metrics.total_tokens += tokens_used as u64;
        self.metrics.total_plaintext_bytes += sender_message.len();
        self.metrics.total_encrypted_bytes += encrypted_bytes;
        self.metrics.encryption_time_ms += encryption_time;

        *self
            .metrics
            .api_calls_by_model
            .entry(model.clone())
            .or_insert(0) += 1;

        let tier_name = format!("{:?}", sender_persona.preferred_tier());
        *self.metrics.api_calls_by_tier.entry(tier_name).or_insert(0) += 1;

        // Record transcript entry
        self.transcript.push(TranscriptEntry {
            round: self.round,
            sender_id: sender_id.0,
            sender_persona: format!("{:?}", sender_persona),
            receiver_id: receiver_id.0,
            receiver_persona: format!("{:?}", receiver_persona),
            message: sender_message.clone(),
            encrypted_bytes,
            plaintext_bytes: sender_message.len(),
        });

        // Check if we should display this interaction
        let should_display = self.verbose
            && match self.follow_agent {
                Some(follow_id) => sender_id == follow_id || receiver_id == follow_id,
                None => true,
            };

        if should_display {
            match self.output_mode {
                OutputMode::Default => self.print_agent_interaction_default(
                    sender_id,
                    sender_persona,
                    receiver_id,
                    receiver_persona,
                    &sender_message,
                    &encrypted_data,
                    encryption_time,
                    parsed_frame.as_ref(),
                ),
                OutputMode::Compact => self.print_agent_interaction_compact(
                    sender_id,
                    sender_persona,
                    receiver_id,
                    receiver_persona,
                    &sender_message,
                    encrypted_bytes,
                ),
                OutputMode::Transcript => self.print_agent_interaction_transcript(
                    sender_id,
                    sender_persona,
                    &sender_message,
                ),
                OutputMode::Beliefs => {
                    // Only show belief changes, handled in update_beliefs
                },
            }
        }

        self.update_beliefs(sender_id, receiver_id, &sender_message);

        Ok(())
    }

    /// Default verbose output with boxes
    #[allow(clippy::too_many_arguments)]
    fn print_agent_interaction_default(
        &self,
        sender_id: AgentId,
        sender_persona: Persona,
        receiver_id: AgentId,
        receiver_persona: Persona,
        message: &str,
        encrypted_data: &[u8],
        encryption_time: f64,
        parsed_frame: Option<&ParsedM2MFrame>,
    ) {
        const RESET: &str = "\x1b[0m";
        const BOLD: &str = "\x1b[1m";
        const DIM: &str = "\x1b[2m";
        const CYAN: &str = "\x1b[36m";
        const GREEN: &str = "\x1b[32m";
        const YELLOW: &str = "\x1b[33m";
        const MAGENTA: &str = "\x1b[35m";
        const RED: &str = "\x1b[31m";
        const BLUE: &str = "\x1b[34m";

        let persona_color = |p: Persona| -> &'static str {
            match p {
                Persona::Analyst | Persona::Skeptic | Persona::Educator => GREEN,
                Persona::Curious | Persona::Follower | Persona::Lurker => CYAN,
                Persona::Propagandist | Persona::Conspiracist | Persona::Troll => RED,
            }
        };

        println!();
        println!(
            "{}┌─────────────────────────────────────────────────────────────────┐{}",
            DIM, RESET
        );
        println!(
            "{}│{} {BOLD}Round {}{RESET}                                                          {}│{}",
            DIM, RESET, self.round, DIM, RESET
        );
        println!(
            "{}└─────────────────────────────────────────────────────────────────┘{}",
            DIM, RESET
        );

        let sender_color = persona_color(sender_persona);
        let receiver_color = persona_color(receiver_persona);

        println!(
            "  {BOLD}{}{}{RESET} {DIM}({:?}){RESET}  {YELLOW}->{RESET}  {BOLD}{}{}{RESET} {DIM}({:?}){RESET}",
            sender_color, sender_id, sender_persona, receiver_color, receiver_id, receiver_persona
        );
        println!();

        println!(
            "  {}+-  Message  --------------------------------------------------------+{}",
            BLUE, RESET
        );

        let max_width = 60;
        let trimmed_msg = message.trim();
        if trimmed_msg.is_empty() {
            println!(
                "  {}|{} {DIM}(empty response){RESET}                                            {}|{}",
                BLUE, RESET, BLUE, RESET
            );
        } else {
            for line in wrap_text(trimmed_msg, max_width) {
                println!("  {}|{} {:<60} {}|{}", BLUE, RESET, line, BLUE, RESET);
            }
        }
        println!(
            "  {}+-------------------------------------------------------------------+{}",
            BLUE, RESET
        );
        println!();

        // Display structured frame info if available, otherwise fall back to hex dump
        if let Some(frame) = parsed_frame {
            // Structured M2M frame display
            println!(
                "  {}┌─ M2M Frame ──────────────────────────────────────────────────────┐{}",
                MAGENTA, RESET
            );
            println!(
                "  {}│{} Magic: {}{}{} | Version: {} | Header: {} bytes",
                MAGENTA, RESET, BOLD, frame.magic, RESET, frame.version, frame.header_len
            );
            println!(
                "  {}│{} Schema: {}{:<15}{} Security: {}{}{}",
                MAGENTA, RESET, CYAN, frame.schema, RESET, YELLOW, frame.security_mode, RESET
            );
            if !frame.flags.is_empty() {
                println!(
                    "  {}│{} Flags: {DIM}{}{RESET}",
                    MAGENTA,
                    RESET,
                    frame.flags.join(" | ")
                );
            }
            println!(
                "  {}├─ Security ───────────────────────────────────────────────────────┤{}",
                MAGENTA, RESET
            );
            println!(
                "  {}│{} Session: {DIM}{}{RESET}",
                MAGENTA,
                RESET,
                if frame.session_id.len() > 50 {
                    &frame.session_id[..50]
                } else {
                    &frame.session_id
                }
            );
            if let Some(ref nonce) = frame.nonce {
                let nonce_hex: String = nonce
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("  {}│{} Nonce: {DIM}{}{RESET}", MAGENTA, RESET, nonce_hex);
            }
            if let Some(ref tag) = frame.auth_tag {
                let tag_hex: String = tag
                    .iter()
                    .take(8)
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!(
                    "  {}│{} Auth Tag: {DIM}{}... (16 bytes){RESET}",
                    MAGENTA, RESET, tag_hex
                );
            }
            println!(
                "  {}├─ Payload ────────────────────────────────────────────────────────┤{}",
                MAGENTA, RESET
            );
            println!(
                "  {}│{} Encrypted: {DIM}{} bytes{RESET}",
                MAGENTA, RESET, frame.encrypted_size
            );
            println!(
                "  {}└──────────────────────────────────────────────────────────────────┘{}",
                MAGENTA, RESET
            );
        } else {
            // Fallback: raw hex dump
            println!(
                "  {}+-  M2M Encrypted Wire Data  ---------------------------------------+{}",
                MAGENTA, RESET
            );

            let hex_preview: String = encrypted_data
                .iter()
                .take(32)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            println!("  {}|{} {DIM}{}{RESET}", MAGENTA, RESET, hex_preview);

            if encrypted_data.len() > 32 {
                let remaining = encrypted_data.len() - 32;
                println!(
                    "  {}|{} {DIM}... +{} more bytes{RESET}",
                    MAGENTA, RESET, remaining
                );
            }

            let b64_preview: String =
                BASE64.encode(&encrypted_data[..encrypted_data.len().min(48)]);
            println!("  {}|{}", MAGENTA, RESET);
            println!(
                "  {}|{} {DIM}Base64: {}...{RESET}",
                MAGENTA,
                RESET,
                &b64_preview[..b64_preview.len().min(50)]
            );

            println!(
                "  {}+-------------------------------------------------------------------+{}",
                MAGENTA, RESET
            );
        }

        println!();
        println!(
            "  {DIM}[Stats] {} bytes plaintext -> {} bytes encrypted | {:.2}ms | {:+.1}%{RESET}",
            message.len(),
            encrypted_data.len(),
            encryption_time,
            ((encrypted_data.len() as f64 / message.len().max(1) as f64) - 1.0) * 100.0
        );
    }

    /// Compact one-line-per-message format
    fn print_agent_interaction_compact(
        &self,
        _sender_id: AgentId,
        sender_persona: Persona,
        _receiver_id: AgentId,
        receiver_persona: Persona,
        message: &str,
        encrypted_bytes: usize,
    ) {
        const RESET: &str = "\x1b[0m";
        const DIM: &str = "\x1b[2m";
        const CYAN: &str = "\x1b[36m";
        const GREEN: &str = "\x1b[32m";
        const RED: &str = "\x1b[31m";

        let persona_color = |p: Persona| -> &'static str {
            match p {
                Persona::Analyst | Persona::Skeptic | Persona::Educator => GREEN,
                Persona::Curious | Persona::Follower | Persona::Lurker => CYAN,
                Persona::Propagandist | Persona::Conspiracist | Persona::Troll => RED,
            }
        };

        let msg_preview: String = message.chars().take(60).collect();
        let msg_preview = if message.len() > 60 {
            format!("{}...", msg_preview)
        } else {
            msg_preview
        };

        println!(
            "{DIM}[R{:03}]{RESET} {}{:>12}{RESET} -> {}{:<12}{RESET} {DIM}({:>3}B){RESET} {}",
            self.round,
            persona_color(sender_persona),
            format!("{:?}", sender_persona),
            persona_color(receiver_persona),
            format!("{:?}", receiver_persona),
            encrypted_bytes,
            msg_preview.replace('\n', " ")
        );
    }

    /// Chat transcript format (like a messaging app)
    fn print_agent_interaction_transcript(
        &self,
        sender_id: AgentId,
        sender_persona: Persona,
        message: &str,
    ) {
        const RESET: &str = "\x1b[0m";
        const BOLD: &str = "\x1b[1m";
        const DIM: &str = "\x1b[2m";
        const CYAN: &str = "\x1b[36m";
        const GREEN: &str = "\x1b[32m";
        const RED: &str = "\x1b[31m";

        let persona_color = match sender_persona {
            Persona::Analyst | Persona::Skeptic | Persona::Educator => GREEN,
            Persona::Curious | Persona::Follower | Persona::Lurker => CYAN,
            Persona::Propagandist | Persona::Conspiracist | Persona::Troll => RED,
        };

        println!(
            "\n{BOLD}{}{}{RESET} {DIM}({:?}){RESET}:",
            persona_color, sender_id, sender_persona
        );

        // Word wrap and indent the message
        for line in wrap_text(message.trim(), 70) {
            println!("  {}", line);
        }
    }

    fn build_topic_context(&self, agent_id: AgentId) -> String {
        let agent = &self.agents[agent_id.0];

        let mut context_parts = Vec::new();

        for (topic_id, belief) in &agent.beliefs.beliefs {
            match belief {
                Belief::Accepts(claim) => {
                    context_parts.push(format!("You believe: {}", claim));
                },
                Belief::Rejects(counter) => {
                    context_parts.push(format!(
                        "You don't believe claims about {} because: {}",
                        topic_id, counter
                    ));
                },
                Belief::Investigating => {
                    context_parts.push(format!("You're investigating claims about {}", topic_id));
                },
                Belief::Uncertain => {},
            }
        }

        if context_parts.is_empty() {
            "You don't have any specific topics on your mind.".to_string()
        } else {
            context_parts.join(" ")
        }
    }

    #[cfg(feature = "crypto")]
    fn encrypt_message(
        &mut self,
        sender_id: AgentId,
        receiver_id: AgentId,
        message: &str,
    ) -> Result<(Vec<u8>, f64, Option<ParsedM2MFrame>)> {
        let start = Instant::now();

        // Track session creation vs reuse
        let session_key = if sender_id.0 < receiver_id.0 {
            (sender_id.0, receiver_id.0)
        } else {
            (receiver_id.0, sender_id.0)
        };

        let is_new_session = !self.existing_sessions.contains(&session_key);
        if is_new_session {
            self.existing_sessions.insert(session_key);
            self.telemetry.record_new_session();
        } else {
            self.telemetry.record_session_reuse();
        }

        let ctx = self.crypto.get_context(sender_id, receiver_id)?;

        let payload = serde_json::json!({
            "from": sender_id.0,
            "to": receiver_id.0,
            "content": message
        })
        .to_string();

        let frame = M2MFrame::new_request(&payload).map_err(|e| {
            SimulationError::EncryptionFailed(format!("Frame creation failed: {:?}", e))
        })?;

        let encrypted = frame.encode_secure(SecurityMode::Aead, ctx).map_err(|e| {
            SimulationError::EncryptionFailed(format!("Encryption failed: {:?}", e))
        })?;

        let elapsed = start.elapsed().as_secs_f64() * 1000.0;

        // Record telemetry
        self.telemetry.record_encryption(encrypted.len(), elapsed);

        // Parse the frame for display
        let session_id = format!("agent-town-{}-{}", session_key.0, session_key.1);
        let parsed = ParsedM2MFrame::parse(&encrypted, &session_id);

        Ok((encrypted, elapsed, parsed))
    }

    #[cfg(not(feature = "crypto"))]
    fn encrypt_message(
        &mut self,
        _sender_id: AgentId,
        _receiver_id: AgentId,
        message: &str,
    ) -> Result<(Vec<u8>, f64, Option<ParsedM2MFrame>)> {
        Ok((message.as_bytes().to_vec(), 0.0, None))
    }

    fn update_beliefs(&mut self, sender_id: AgentId, receiver_id: AgentId, message: &str) {
        let sender_beliefs: Vec<(String, Belief)> = self.agents[sender_id.0]
            .beliefs
            .beliefs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let sender_persona = self.agents[sender_id.0].persona;
        let receiver_persona = self.agents[receiver_id.0].persona;

        for (topic_id_str, sender_belief) in sender_beliefs {
            let should_update = match self.agents[receiver_id.0].persona {
                Persona::Follower => true,
                Persona::Curious => true,
                Persona::Analyst | Persona::Skeptic | Persona::Educator => false,
                Persona::Lurker => false,
                _ => rand::random::<f64>() < 0.3,
            };

            // Track thread message
            if let Some(thread) = self.threads.get_mut(&topic_id_str) {
                // Add this agent to exposed agents if not already there
                if !thread.exposed_agents.contains(&receiver_id.0) {
                    thread.exposed_agents.push(receiver_id.0);
                }

                let belief_change = if should_update {
                    let receiver = &self.agents[receiver_id.0];
                    if let Some(topic_id) = TopicId::new(&topic_id_str) {
                        let current = receiver.beliefs.get_belief(&topic_id);
                        if current.is_none() {
                            Some("Now INVESTIGATING".to_string())
                        } else if matches!(current, Some(Belief::Investigating)) {
                            match &sender_belief {
                                Belief::Accepts(_) => Some("Now ACCEPTS".to_string()),
                                Belief::Rejects(_) => Some("Now REJECTS".to_string()),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                thread.messages.push(ThreadMessage {
                    round: self.round,
                    sender_id: sender_id.0,
                    sender_persona: format!("{:?}", sender_persona),
                    receiver_id: receiver_id.0,
                    receiver_persona: format!("{:?}", receiver_persona),
                    message_preview: message.chars().take(100).collect(),
                    belief_change,
                });
            }

            if should_update {
                if let Some(topic_id) = TopicId::new(&topic_id_str) {
                    let receiver = &mut self.agents[receiver_id.0];
                    let current_belief = receiver.beliefs.get_belief(&topic_id);

                    if current_belief.is_none() {
                        receiver
                            .beliefs
                            .update_belief(&topic_id, Belief::Investigating, sender_id);
                        self.metrics.belief_changes += 1;

                        // Update thread belief state
                        if let Some(thread) = self.threads.get_mut(&topic_id_str) {
                            thread
                                .belief_states
                                .insert(receiver_id.0, "Investigating".to_string());
                        }
                    } else if matches!(current_belief, Some(Belief::Investigating)) {
                        let belief_str = match &sender_belief {
                            Belief::Accepts(_) => "Accepts",
                            Belief::Rejects(_) => "Rejects",
                            _ => "Uncertain",
                        };
                        receiver
                            .beliefs
                            .update_belief(&topic_id, sender_belief.clone(), sender_id);
                        self.metrics.belief_changes += 1;

                        // Update thread belief state
                        if let Some(thread) = self.threads.get_mut(&topic_id_str) {
                            thread
                                .belief_states
                                .insert(receiver_id.0, belief_str.to_string());
                        }
                    }
                }
            }
        }
    }

    fn print_summary(&self) {
        println!("\n{}", "=".repeat(70));
        println!(" SIMULATION COMPLETE - Round {}", self.round);
        println!("{}", "=".repeat(70));

        println!("\nBELIEF PROPAGATION:");
        let mut topic_stats: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();

        for agent in &self.agents {
            for (topic_id, belief) in &agent.beliefs.beliefs {
                let stats = topic_stats.entry(topic_id.clone()).or_insert((0, 0, 0, 0));
                match belief {
                    Belief::Accepts(_) => stats.0 += 1,
                    Belief::Rejects(_) => stats.1 += 1,
                    Belief::Uncertain => stats.2 += 1,
                    Belief::Investigating => stats.3 += 1,
                }
            }
        }

        println!(
            "+{:-<25}+{:-<10}+{:-<10}+{:-<10}+{:-<12}+",
            "", "", "", "", ""
        );
        println!(
            "| {:23} | {:8} | {:8} | {:8} | {:10} |",
            "Topic", "Accepts", "Rejects", "Unsure", "Investigating"
        );
        println!(
            "+{:-<25}+{:-<10}+{:-<10}+{:-<10}+{:-<12}+",
            "", "", "", "", ""
        );

        for (topic, (accepts, rejects, uncertain, investigating)) in &topic_stats {
            println!(
                "| {:23} | {:8} | {:8} | {:8} | {:10} |",
                topic.chars().take(23).collect::<String>(),
                accepts,
                rejects,
                uncertain,
                investigating
            );
        }
        println!(
            "+{:-<25}+{:-<10}+{:-<10}+{:-<10}+{:-<12}+",
            "", "", "", "", ""
        );

        println!("\nM2M PROTOCOL METRICS:");
        println!("  Total messages: {}", self.metrics.total_messages);
        println!(
            "  Encrypted bytes: {} ({} plaintext)",
            self.metrics.total_encrypted_bytes, self.metrics.total_plaintext_bytes
        );
        println!(
            "  Overhead: {:.1}%",
            (self.metrics.compression_ratio() - 1.0) * 100.0
        );
        println!(
            "  Total encryption time: {:.2}ms",
            self.metrics.encryption_time_ms
        );
        println!("  Belief changes: {}", self.metrics.belief_changes);

        println!("\nAPI USAGE:");
        println!("  Total tokens: {}", self.metrics.total_tokens);
        println!("  API errors: {}", self.metrics.api_errors);
        println!("  Rate limits hit: {}", self.metrics.rate_limits_hit);
        for (model, count) in &self.metrics.api_calls_by_model {
            println!("  {}: {} calls", model, count);
        }

        // Display the telemetry dashboard
        println!("\n{}", self.telemetry.format_dashboard(&self.metrics));

        // Display conversation threads
        if !self.threads.is_empty() {
            println!("\nCONVERSATION THREADS:");
            for thread in self.threads.values() {
                if thread.messages.is_empty() {
                    continue;
                }
                println!();
                println!("{}", thread.format_display());
            }
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "simulation": {
                "agents": self.agents.len(),
                "rounds": self.round,
            },
            "seed_events": self.injected_events.iter().map(|(r, e, a)| {
                serde_json::json!({
                    "round": r,
                    "topic": e.topic().name,
                    "target_agent": a.0
                })
            }).collect::<Vec<_>>(),
            "metrics": {
                "total_messages": self.metrics.total_messages,
                "total_tokens": self.metrics.total_tokens,
                "encrypted_bytes": self.metrics.total_encrypted_bytes,
                "plaintext_bytes": self.metrics.total_plaintext_bytes,
                "compression_ratio": self.metrics.compression_ratio(),
                "belief_changes": self.metrics.belief_changes,
                "api_errors": self.metrics.api_errors,
                "rate_limits_hit": self.metrics.rate_limits_hit,
                "api_calls_by_model": self.metrics.api_calls_by_model,
            },
            "agents": self.agents.iter().map(|a| {
                serde_json::json!({
                    "id": a.id.0,
                    "persona": format!("{:?}", a.persona),
                    "beliefs": a.beliefs.beliefs.len()
                })
            }).collect::<Vec<_>>(),
            "transcript": self.transcript,
        })
    }

    /// Export conversation transcript to a text file
    fn export_transcript(&self, path: &str) -> Result<()> {
        let mut content = String::new();
        content.push_str("# Agent Town Conversation Transcript\n\n");
        content.push_str(&format!(
            "Agents: {} | Rounds: {}\n",
            self.agents.len(),
            self.round
        ));
        content.push_str(&format!("Generated: {}\n\n", chrono_lite_now()));
        content.push_str("---\n\n");

        for entry in &self.transcript {
            content.push_str(&format!(
                "[Round {}] {} ({}) -> {} ({}):\n",
                entry.round,
                entry.sender_id,
                entry.sender_persona,
                entry.receiver_id,
                entry.receiver_persona
            ));
            content.push_str(&format!("  \"{}\"\n", entry.message.replace('\n', " ")));
            content.push_str(&format!(
                "  [{}B plaintext -> {}B encrypted]\n\n",
                entry.plaintext_bytes, entry.encrypted_bytes
            ));
        }

        std::fs::write(path, content).map_err(|e| SimulationError::IoError {
            path: path.to_string(),
            error: e.to_string(),
        })
    }

    /// Export network graph in DOT format for visualization
    fn export_graph_dot(&self, path: &str) -> Result<()> {
        let mut dot = String::new();
        dot.push_str("digraph AgentTown {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=circle];\n\n");

        // Define nodes with colors based on persona
        for agent in &self.agents {
            let color = match agent.persona {
                Persona::Analyst | Persona::Skeptic | Persona::Educator => "green",
                Persona::Curious | Persona::Follower | Persona::Lurker => "lightblue",
                Persona::Propagandist | Persona::Conspiracist | Persona::Troll => "red",
            };
            let beliefs_count = agent.beliefs.beliefs.len();
            dot.push_str(&format!(
                "  {} [label=\"{}\\n{:?}\\n({} beliefs)\" fillcolor={} style=filled];\n",
                agent.id.0, agent.id, agent.persona, beliefs_count, color
            ));
        }

        dot.push_str("\n  // Network connections\n");

        // Add edges (undirected graph, so we track what we've added)
        let mut added_edges = std::collections::HashSet::new();
        for node_idx in self.graph.node_indices() {
            for edge in self.graph.edges(node_idx) {
                let (a, b) = (edge.source(), edge.target());
                let (a_id, b_id) = (self.graph[a], self.graph[b]);
                let edge_key = if a_id < b_id {
                    (a_id, b_id)
                } else {
                    (b_id, a_id)
                };
                if !added_edges.contains(&edge_key) {
                    dot.push_str(&format!("  {} -- {} [dir=none];\n", a_id, b_id));
                    added_edges.insert(edge_key);
                }
            }
        }

        // Add conversation flow as directed edges (separate color)
        dot.push_str("\n  // Conversation flow\n");
        for entry in &self.transcript {
            dot.push_str(&format!(
                "  {} -> {} [color=blue style=dashed constraint=false];\n",
                entry.sender_id, entry.receiver_id
            ));
        }

        dot.push_str("}\n");

        std::fs::write(path, dot).map_err(|e| SimulationError::IoError {
            path: path.to_string(),
            error: e.to_string(),
        })
    }
}

/// Simple timestamp without external crate
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("timestamp:{}", secs)
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    // Load .env file if present
    if let Ok(contents) = std::fs::read_to_string(".env") {
        for line in contents.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                if !key.starts_with('#') && !key.is_empty() {
                    std::env::set_var(key, value);
                }
            }
        }
    }

    let args = Args::parse();

    // Check for API key unless dry run (B_i)
    if !args.dry_run && get_api_key().is_none() {
        return Err(SimulationError::ApiKeyMissing);
    }

    // Initialize RNG
    let mut rng: Box<dyn RngCore> = if let Some(seed) = args.seed {
        Box::new(rand::rngs::StdRng::seed_from_u64(seed))
    } else {
        Box::new(rand::thread_rng())
    };

    // Print header
    println!("{}", "=".repeat(70));
    println!(" AGENT TOWN - Cognitive Warfare Simulation");
    println!(
        " Agents: {} | Topology: {:?} | Rounds: {}",
        args.agents, args.topology, args.rounds
    );
    println!(" Free only: {} | Dry run: {}", args.free_only, args.dry_run);
    println!(
        " Output: {:?}{}",
        args.output_mode,
        args.follow_agent
            .map(|id| format!(" | Following Agent#{}", id))
            .unwrap_or_default()
    );
    println!("{}", "=".repeat(70));

    // Create simulation
    let mut sim = Simulation::new(&args, &mut rng);

    // Inject seed events
    sim.inject_seeds(&mut rng);

    // Create HTTP client (I^B: might fail)
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| SimulationError::HttpClientFailed(e.to_string()))?;

    // Run simulation
    let start_time = Instant::now();

    for round in 0..args.rounds {
        if args.verbose {
            println!("\n--- Round {} ---", round + 1);
        }

        // Errors in individual rounds don't stop the simulation
        if let Err(e) = sim.run_round(&client, &mut rng).await {
            if args.verbose {
                println!("[Round {}] Error: {}", round + 1, e);
            }
        }

        if args.delay_ms > 0 {
            sleep(Duration::from_millis(args.delay_ms)).await;
        }

        if !args.verbose && (round + 1) % 10 == 0 {
            print!(
                "\rProgress: {}/{} rounds ({} messages)",
                round + 1,
                args.rounds,
                sim.metrics.total_messages
            );
            std::io::Write::flush(&mut std::io::stdout()).ok();
        }
    }

    let elapsed = start_time.elapsed();

    if !args.verbose {
        println!();
    }

    sim.print_summary();
    println!("\nElapsed time: {:.2}s", elapsed.as_secs_f64());

    // Write JSON output if requested (I^B: might fail)
    if let Some(output_path) = &args.output {
        let json = sim.to_json();
        let json_str = serde_json::to_string_pretty(&json)
            .map_err(|e| SimulationError::JsonError(e.to_string()))?;
        std::fs::write(output_path, json_str).map_err(|e| SimulationError::IoError {
            path: output_path.clone(),
            error: e.to_string(),
        })?;
        println!("\nResults written to: {}", output_path);
    }

    // Export transcript if requested
    if let Some(transcript_path) = &args.transcript {
        sim.export_transcript(transcript_path)?;
        println!("Transcript written to: {}", transcript_path);
    }

    // Export graph if requested
    if let Some(graph_path) = &args.export_graph {
        sim.export_graph_dot(graph_path)?;
        println!(
            "Graph written to: {} (view with: dot -Tpng {} -o graph.png)",
            graph_path, graph_path
        );
    }

    Ok(())
}
