//! M2M Protocol CLI binary.
//!
//! Machine-to-machine LLM communication protocol.
//!
//! # Commands
//!
//! - `compress` - Compress JSON using multi-codec algorithms
//! - `decompress` - Decompress M2M wire format
//! - `scan` - Security scan content for threats
//! - `models` - List/search model registry
//! - `server` - Start HTTP protocol server

use std::io::{self, Read};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use m2m::{
    codec::{Algorithm, CodecEngine},
    is_m2m_format,
    models::ModelRegistry,
    proxy::{ProxyConfig, ProxyServer},
    security::SecurityScanner,
    server::{create_router, AppState, ServerConfig},
    transport::{QuicTransportConfig, TransportKind},
    VERSION,
};
use serde_json::Value;

#[derive(Parser)]
#[command(name = "m2m")]
#[command(author = "Infernet <hello@infernet.org>")]
#[command(version = VERSION)]
#[command(about = "M2M Protocol - Machine-to-machine LLM communication", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compress JSON to M2M wire format
    Compress {
        /// JSON input (or - for stdin)
        input: Option<String>,

        /// Input file path
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Compression algorithm (token, brotli, dictionary, auto)
        #[arg(short, long, default_value = "auto")]
        algorithm: String,

        /// Show compression statistics
        #[arg(short, long)]
        stats: bool,
    },

    /// Decompress M2M wire format to JSON
    Decompress {
        /// M2M input (or - for stdin)
        input: Option<String>,

        /// Input file path
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output as pretty-printed JSON
        #[arg(long)]
        pretty: bool,
    },

    /// Security scan content for threats
    Scan {
        /// Content to scan (or - for stdin)
        input: Option<String>,

        /// Input file path
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Enable blocking mode
        #[arg(short, long)]
        blocking: bool,

        /// Block threshold (0.0 - 1.0)
        #[arg(short, long, default_value = "0.8")]
        threshold: f32,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Analyze content for compression
    Analyze {
        /// Content to analyze (or - for stdin)
        input: Option<String>,

        /// Input file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// List and search models
    Models {
        #[command(subcommand)]
        action: Option<ModelsAction>,
    },

    /// Start the HTTP protocol server
    Server {
        /// Listen port
        #[arg(short, long, default_value = "3000")]
        port: u16,

        /// Listen host
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Bind to all interfaces
        #[arg(long)]
        bind_all: bool,

        /// Enable security blocking
        #[arg(long)]
        blocking: bool,

        /// Block threshold (0.0 - 1.0)
        #[arg(long, default_value = "0.8")]
        threshold: f32,

        /// Disable security scanning
        #[arg(long)]
        no_security: bool,

        /// Model path for ML routing
        #[arg(long)]
        model: Option<PathBuf>,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// Start the OpenAI-compatible proxy with transport options
    Proxy {
        /// TCP listen port
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Listen host
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Upstream LLM API URL
        #[arg(short, long)]
        upstream: String,

        /// API key for upstream (or use env OPENAI_API_KEY)
        #[arg(short = 'k', long)]
        api_key: Option<String>,

        /// Transport type: tcp, quic, both
        #[arg(short, long, default_value = "tcp")]
        transport: String,

        /// QUIC listen port (default: TCP port + 363)
        #[arg(long)]
        quic_port: Option<u16>,

        /// Path to TLS certificate (for QUIC)
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Path to TLS private key (for QUIC)
        #[arg(long)]
        key: Option<PathBuf>,

        /// Enable security scanning
        #[arg(long)]
        security: bool,

        /// Security blocking threshold (0.0 - 1.0)
        #[arg(long, default_value = "0.8")]
        threshold: f32,

        /// Request timeout in seconds
        #[arg(long, default_value = "120")]
        timeout: u64,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum ModelsAction {
    /// List all known models
    List {
        /// Filter by provider (openai, anthropic, google, meta, etc.)
        #[arg(short, long)]
        provider: Option<String>,
    },

    /// Search for models
    Search {
        /// Search query
        query: String,
    },

    /// Get info about a specific model
    Info {
        /// Model ID or abbreviation
        model: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compress {
            input,
            file,
            output,
            algorithm,
            stats,
        } => cmd_compress(input, file, output, &algorithm, stats),

        Commands::Decompress {
            input,
            file,
            output,
            pretty,
        } => cmd_decompress(input, file, output, pretty),

        Commands::Scan {
            input,
            file,
            blocking,
            threshold,
            json,
        } => cmd_scan(input, file, blocking, threshold, json),

        Commands::Analyze { input, file } => cmd_analyze(input, file),

        Commands::Models { action } => cmd_models(action),

        Commands::Server {
            port,
            host,
            bind_all,
            blocking,
            threshold,
            no_security,
            model,
            verbose,
        } => cmd_server(
            port,
            host,
            bind_all,
            blocking,
            threshold,
            no_security,
            model,
            verbose,
        ),

        Commands::Proxy {
            port,
            host,
            upstream,
            api_key,
            transport,
            quic_port,
            cert,
            key,
            security,
            threshold,
            timeout,
            verbose,
        } => cmd_proxy(
            port, host, upstream, api_key, transport, quic_port, cert, key, security, threshold,
            timeout, verbose,
        ),
    }
}

fn cmd_compress(
    input: Option<String>,
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    algorithm: &str,
    stats: bool,
) -> anyhow::Result<()> {
    let content = read_input(input, file)?;
    let engine = CodecEngine::new();

    // Parse algorithm
    let algo = match algorithm.to_lowercase().as_str() {
        "auto" => None,
        "token" | "t" => Some(Algorithm::Token),
        "brotli" | "br" => Some(Algorithm::Brotli),
        "dictionary" | "dict" | "d" => Some(Algorithm::Dictionary),
        "none" | "n" => Some(Algorithm::None),
        _ => {
            eprintln!("Unknown algorithm: {algorithm}. Use: auto, token, brotli, dictionary, none");
            std::process::exit(1);
        },
    };

    let result = if let Some(algo) = algo {
        engine.compress(&content, algo)?
    } else {
        let (result, _) = engine.compress_auto(&content)?;
        result
    };

    write_output(output, &result.data)?;

    if stats {
        eprintln!();
        eprintln!("Compression Statistics:");
        eprintln!("  Algorithm:    {:?}", result.algorithm);
        eprintln!("  Original:     {} bytes", result.original_bytes);
        eprintln!("  Compressed:   {} bytes", result.compressed_bytes);
        eprintln!("  Ratio:        {:.2}x", result.byte_ratio());

        let savings = result.original_bytes as i64 - result.compressed_bytes as i64;
        let pct = if result.original_bytes > 0 {
            (savings as f64 / result.original_bytes as f64) * 100.0
        } else {
            0.0
        };
        eprintln!("  Saved:        {savings} bytes ({pct:.1}%)");
    }

    Ok(())
}

fn cmd_decompress(
    input: Option<String>,
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    pretty: bool,
) -> anyhow::Result<()> {
    let content = read_input(input, file)?;
    let engine = CodecEngine::new();

    // Check format
    if !is_m2m_format(&content) {
        eprintln!("Warning: Input does not appear to be in M2M format");
    }

    // Decompress
    let decompressed = engine.decompress(&content)?;

    // Format output
    let output_str = if pretty {
        if let Ok(value) = serde_json::from_str::<Value>(&decompressed) {
            serde_json::to_string_pretty(&value)?
        } else {
            decompressed
        }
    } else {
        decompressed
    };

    write_output(output, &output_str)?;

    Ok(())
}

fn cmd_scan(
    input: Option<String>,
    file: Option<PathBuf>,
    blocking: bool,
    threshold: f32,
    json_output: bool,
) -> anyhow::Result<()> {
    let content = read_input(input, file)?;

    let scanner = if blocking {
        SecurityScanner::new().with_blocking(threshold)
    } else {
        SecurityScanner::new()
    };

    let result = scanner.scan(&content)?;

    if json_output {
        let output = serde_json::json!({
            "safe": result.safe,
            "confidence": result.confidence,
            "should_block": result.should_block,
            "threats": result.threats.iter().map(|t| serde_json::json!({
                "name": t.name,
                "category": t.category,
                "severity": t.severity,
                "description": t.description,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if result.safe {
        println!("SAFE (confidence: {:.2})", result.confidence);
    } else {
        println!("UNSAFE (confidence: {:.2})", result.confidence);
        println!();
        println!("Detected threats:");
        for threat in &result.threats {
            println!(
                "  - {} ({}) severity: {:.2}",
                threat.name, threat.category, threat.severity
            );
            println!("    {}", threat.description);
        }

        if result.should_block {
            println!();
            println!("BLOCKED: Content exceeds block threshold");
        }
    }

    if !result.safe && blocking && result.should_block {
        std::process::exit(1);
    }

    Ok(())
}

fn cmd_analyze(input: Option<String>, file: Option<PathBuf>) -> anyhow::Result<()> {
    let content = read_input(input, file)?;
    let engine = CodecEngine::new();
    let analysis = engine.analyze(&content);

    println!("Content Analysis:");
    println!("  Length:           {} bytes", analysis.length);
    println!("  Is JSON:          {}", analysis.is_json);
    println!("  Is LLM API:       {}", analysis.is_llm_api);
    println!("  Has Tools:        {}", analysis.has_tools);
    println!("  Repetition:       {:.2}", analysis.repetition_ratio);
    println!("  Est. Tokens:      ~{}", analysis.estimated_tokens);
    println!();

    let selected = engine.select_algorithm(&analysis);
    println!("Recommended Algorithm: {selected:?}");

    // Try all algorithms
    println!();
    println!("Algorithm Comparison:");
    for algo in [Algorithm::Token, Algorithm::Brotli, Algorithm::Dictionary] {
        if let Ok(result) = engine.compress(&content, algo) {
            println!(
                "  {:?}: {} bytes -> {} bytes (ratio: {:.2}x)",
                algo,
                result.original_bytes,
                result.compressed_bytes,
                result.byte_ratio()
            );
        }
    }

    Ok(())
}

fn cmd_models(action: Option<ModelsAction>) -> anyhow::Result<()> {
    let registry = ModelRegistry::new();

    match action {
        None | Some(ModelsAction::List { provider: None }) => {
            println!("Available Models ({}):", registry.len());
            println!();
            println!(
                "{:<40} {:<10} {:<12} {:>10}",
                "ID", "Abbrev", "Provider", "Context"
            );
            println!("{}", "-".repeat(76));

            for card in registry.iter() {
                println!(
                    "{:<40} {:<10} {:<12} {:>10}",
                    card.id,
                    card.abbrev,
                    format!("{:?}", card.provider),
                    card.context_length
                );
            }
        },

        Some(ModelsAction::List { provider: Some(p) }) => {
            let filter = p.to_lowercase();
            println!("Models from {p}:");
            println!();

            for card in registry.iter() {
                let provider_str = format!("{:?}", card.provider).to_lowercase();
                if provider_str.contains(&filter) {
                    println!(
                        "{:<40} {:<10} {:>10}",
                        card.id, card.abbrev, card.context_length
                    );
                }
            }
        },

        Some(ModelsAction::Search { query }) => {
            let query_lower = query.to_lowercase();
            println!("Search results for '{query}':");
            println!();

            for card in registry.iter() {
                if card.id.to_lowercase().contains(&query_lower)
                    || card.abbrev.to_lowercase().contains(&query_lower)
                {
                    println!("{:<40} {:<10}", card.id, card.abbrev);
                }
            }
        },

        Some(ModelsAction::Info { model }) => match registry.get(&model) {
            Some(card) => {
                println!("Model: {}", card.id);
                println!("Abbreviation: {}", card.abbrev);
                println!("Provider: {:?}", card.provider);
                println!("Encoding: {:?}", card.encoding);
                println!("Context Length: {}", card.context_length);
                println!("Supports Streaming: {}", card.supports_streaming);
                println!("Supports Tools: {}", card.supports_tools);
                println!("Supports Vision: {}", card.supports_vision);

                if let Some(pricing) = &card.pricing {
                    println!();
                    println!("Pricing:");
                    println!("  Prompt: ${}/1M tokens", pricing.prompt * 1_000_000.0);
                    println!(
                        "  Completion: ${}/1M tokens",
                        pricing.completion * 1_000_000.0
                    );
                }
            },
            None => {
                eprintln!("Model not found: {model}");
                eprintln!("Try 'm2m models search {model}' to find similar models");
                std::process::exit(1);
            },
        },
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_server(
    port: u16,
    host: String,
    bind_all: bool,
    blocking: bool,
    threshold: f32,
    no_security: bool,
    model: Option<PathBuf>,
    verbose: bool,
) -> anyhow::Result<()> {
    // Initialize logging
    let log_level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    // Build config
    let mut config = ServerConfig::default().with_port(port);

    if bind_all {
        config = config.bind_all();
    } else {
        let addr: std::net::SocketAddr = format!("{host}:{port}").parse()?;
        config = config.with_addr(addr);
    }

    if no_security {
        config = config.without_security();
    } else if blocking {
        config = config.with_security_blocking(threshold);
    }

    if let Some(path) = model {
        config = config.with_model(&path.to_string_lossy());
    }

    // Create state and router
    let state = Arc::new(AppState::new(config.clone()));
    let app = create_router(state);

    // Start server
    tracing::info!("Starting M2M Protocol server on {}", config.addr);
    tracing::info!(
        "Security: {}",
        if config.security_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    if config.security_blocking {
        tracing::info!("Blocking mode: threshold {}", config.block_threshold);
    }

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(config.addr).await?;
        axum::serve(listener, app).await?;
        Ok::<_, anyhow::Error>(())
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_proxy(
    port: u16,
    host: String,
    upstream: String,
    api_key: Option<String>,
    transport: String,
    quic_port: Option<u16>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    security: bool,
    threshold: f32,
    timeout: u64,
    verbose: bool,
) -> anyhow::Result<()> {
    // Initialize logging
    let log_level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    // Parse transport kind
    let transport_kind = TransportKind::from_str(&transport)
        .map_err(|_| anyhow::anyhow!("Invalid transport: {}. Use: tcp, quic, both", transport))?;

    // Get API key from arg or environment
    let api_key = api_key.or_else(|| std::env::var("OPENAI_API_KEY").ok());

    // Build listen address
    let listen_addr: std::net::SocketAddr = format!("{host}:{port}").parse()?;

    // Build QUIC config if needed
    let quic_config = if matches!(transport_kind, TransportKind::Quic | TransportKind::Both) {
        let quic_addr = std::net::SocketAddr::from((
            listen_addr.ip(),
            quic_port.unwrap_or(port + 363), // Default: TCP port + 363 (8080 -> 8443)
        ));

        let tls = if let (Some(cert_path), Some(key_path)) = (cert, key) {
            m2m::transport::TlsConfig::production(cert_path, key_path)
        } else {
            tracing::warn!("No TLS certificates provided, using self-signed (development only)");
            m2m::transport::TlsConfig::development()
        };

        Some(QuicTransportConfig {
            listen_addr: quic_addr,
            tls,
            ..Default::default()
        })
    } else {
        None
    };

    // Build proxy config
    let config = ProxyConfig {
        listen_addr,
        upstream_url: upstream,
        api_key,
        compress_requests: true,
        compress_responses: true,
        security_scanning: security,
        security_threshold: threshold,
        timeout_secs: timeout,
        transport: transport_kind,
        quic_config,
    };

    // Create and run proxy server
    let server = ProxyServer::new(config).map_err(|e| anyhow::anyhow!("{}", e))?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async { server.run().await.map_err(|e| anyhow::anyhow!("{}", e)) })
}

// Helper functions

fn read_input(input: Option<String>, file: Option<PathBuf>) -> anyhow::Result<String> {
    if let Some(path) = file {
        Ok(std::fs::read_to_string(path)?)
    } else if let Some(s) = input {
        if s == "-" {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            Ok(buffer)
        } else {
            Ok(s)
        }
    } else {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer)
    }
}

fn write_output(output: Option<PathBuf>, content: &str) -> anyhow::Result<()> {
    if let Some(path) = output {
        std::fs::write(path, content)?;
    } else {
        println!("{content}");
    }
    Ok(())
}
