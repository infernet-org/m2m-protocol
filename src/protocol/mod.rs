//! M2M Protocol negotiation and session management.
//!
//! Implements the M2M Protocol v3.0 handshake for agent-to-agent communication
//! with capability negotiation, version checks, and session lifecycle management.
//!
//! # Protocol Overview
//!
//! The M2M Protocol uses a session-based model where agents establish connections
//! through a capability handshake before exchanging compressed data.
//!
//! ## Message Flow
//!
//! ```text
//! Client                            Server
//!    |                                |
//!    |-------- HELLO (caps) -------->|  Initiate with capabilities
//!    |                                |
//!    |<----- ACCEPT (caps) ----------|  Session established
//!    |     or REJECT (reason)        |  or rejected with code
//!    |                                |
//!    |======= DATA (compressed) =====>|  Exchange payloads
//!    |<===== DATA (compressed) =======|
//!    |                                |
//!    |-------- PING ---------------->|  Keep-alive
//!    |<------- PONG -----------------|
//!    |                                |
//!    |-------- CLOSE --------------->|  Terminate session
//! ```
//!
//! ## State Machine
//!
//! Sessions transition through these states:
//!
//! | State       | Description                       | Valid Transitions        |
//! |-------------|-----------------------------------|--------------------------|
//! | `Initial`   | New session, no handshake yet     | → HelloSent, Established |
//! | `HelloSent` | HELLO sent, awaiting response     | → Established, Closed    |
//! | `Established`| Ready for data exchange          | → Closing                |
//! | `Closing`   | Graceful shutdown initiated       | → Closed                 |
//! | `Closed`    | Session terminated                | (terminal)               |
//!
//! ## Capabilities
//!
//! During handshake, agents advertise their capabilities:
//!
//! - **Compression**: Supported algorithms (Token, Brotli, Dictionary)
//! - **Security**: Threat detection, blocking mode, confidence threshold
//! - **Extensions**: Custom key-value pairs for future features
//!
//! ## Rejection Codes
//!
//! | Code                | Meaning                          |
//! |---------------------|----------------------------------|
//! | `VersionMismatch`   | Protocol version incompatible    |
//! | `NoCommonAlgorithm` | No mutually supported algorithm  |
//! | `SecurityPolicy`    | Security policy violation        |
//! | `RateLimited`       | Too many requests                |
//! | `Unknown`           | Other/unspecified error          |
//!
//! # Usage
//!
//! ## Client Side
//!
//! ```rust,ignore
//! use m2m_core::protocol::{Session, Capabilities};
//!
//! // Create session with default capabilities
//! let mut client = Session::new(Capabilities::default());
//!
//! // Initiate handshake
//! let hello = client.create_hello();
//! // Send hello to server, receive response...
//! ```
//!
//! ## Server Side
//!
//! ```rust,ignore
//! use m2m_core::protocol::{Session, Capabilities, MessageType};
//!
//! let mut server = Session::new(Capabilities::default());
//!
//! // Process incoming HELLO
//! let response = server.process_hello(&incoming_hello)?;
//! match response.msg_type {
//!     MessageType::Accept => { /* session established */ }
//!     MessageType::Reject => { /* negotiation failed */ }
//!     _ => unreachable!(),
//! }
//! ```
//!
//! ## Data Exchange
//!
//! ```rust,ignore
//! // After session established
//! let data_msg = session.compress(r#"{"model":"gpt-4o"}"#)?;
//! let content = session.decompress(&incoming_data)?;
//! ```

mod capabilities;
mod message;
mod session;

pub use capabilities::{Capabilities, CompressionCaps, NegotiatedCaps, SecurityCaps};
pub use message::{Message, MessageType, RejectionCode, RejectionInfo};
pub use session::{Session, SessionState, SessionStats};

/// Protocol version
pub const PROTOCOL_VERSION: &str = "3.0";

/// Maximum session idle time (5 minutes)
pub const SESSION_TIMEOUT_SECS: u64 = 300;
