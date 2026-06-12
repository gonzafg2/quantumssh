//! `QuantumSSH` server binary — a thin entrypoint (ADR-0017): parse the
//! CLI, construct the log subscriber (ADR-0024), build the Tokio
//! runtime (ADR-0022), and hand off to `quantumssh_core`.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use std::sync::Arc;

use quantumssh_core::host_key::HostKey;
use quantumssh_core::server::{Config, Server};
use tracing::error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

const DEFAULT_LISTEN: &str = "127.0.0.1:2222";
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

const USAGE: &str = "\
quantumssh — memory-safe, post-quantum-first SSH server (pre-alpha)

USAGE:
    quantumssh [OPTIONS]

OPTIONS:
    --listen <ADDR>               Address to bind (default: 127.0.0.1:2222)
    --host-key <PATH>             Ed25519 host key file (openssh-key-v1,
                                  unencrypted; ssh-keygen -t ed25519).
                                  Required.
    --handshake-timeout <SECS>    Budget from TCP accept to handshake
                                  completion (default: 30; ADR-0022)
    --log-format <FORMAT>         'json' or 'human' (default: json when
                                  stderr is not a TTY, human when it is)
    --help                        Print this help
    --version                     Print version
";

/// Log output format. JSON is the shipping default whenever stderr —
/// the stream all logs are written to (threat model §2.7) — is not a
/// TTY; human-readable is the interactive-development default
/// (ADR-0024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Json,
    Human,
}

#[derive(Debug)]
struct Cli {
    listen: SocketAddr,
    host_key_path: Option<String>,
    handshake_timeout: Duration,
    log_format: LogFormat,
}

enum CliOutcome {
    Run(Cli),
    Exit(ExitCode),
}

fn parse_cli(args: &[String]) -> Result<CliOutcome, String> {
    let mut listen: SocketAddr = DEFAULT_LISTEN
        .parse()
        .map_err(|e| format!("internal default listen address invalid: {e}"))?;
    let mut host_key_path: Option<String> = None;
    let mut handshake_timeout = Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS);
    let mut log_format = if std::io::stderr().is_terminal() {
        LogFormat::Human
    } else {
        LogFormat::Json
    };

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => {
                let value = it.next().ok_or("--listen requires an address")?;
                listen = value
                    .parse()
                    .map_err(|e| format!("invalid --listen address '{value}': {e}"))?;
            }
            "--host-key" => {
                let value = it.next().ok_or("--host-key requires a path")?;
                host_key_path = Some(value.clone());
            }
            "--handshake-timeout" => {
                let value = it.next().ok_or("--handshake-timeout requires seconds")?;
                let secs: u64 = value
                    .parse()
                    .map_err(|e| format!("invalid --handshake-timeout '{value}': {e}"))?;
                if secs == 0 {
                    return Err("--handshake-timeout must be at least 1 second".into());
                }
                handshake_timeout = Duration::from_secs(secs);
            }
            "--log-format" => {
                let value = it.next().ok_or("--log-format requires 'json' or 'human'")?;
                log_format = match value.as_str() {
                    "json" => LogFormat::Json,
                    "human" => LogFormat::Human,
                    other => return Err(format!("invalid --log-format '{other}'")),
                };
            }
            "--help" => {
                print!("{USAGE}");
                return Ok(CliOutcome::Exit(ExitCode::SUCCESS));
            }
            "--version" => {
                println!("quantumssh {}", env!("CARGO_PKG_VERSION"));
                return Ok(CliOutcome::Exit(ExitCode::SUCCESS));
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }

    Ok(CliOutcome::Run(Cli {
        listen,
        host_key_path,
        handshake_timeout,
        log_format,
    }))
}

/// One formatting layer (JSON or human) writing to stderr.
fn fmt_layer<S>(format: LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    let base = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    match format {
        LogFormat::Json => base.json().boxed(),
        LogFormat::Human => base.boxed(),
    }
}

/// Installs the global subscriber: the ADR-0024 two-layer design.
///
/// All output goes to stderr — the sink threat-model §2.7 names;
/// stdout is reserved and unused by logging.
///
/// - **General tier**: governed by `RUST_LOG` (`EnvFilter`), with the
///   `audit` target excluded — the audit layer owns it.
/// - **Audit tier**: a separate layer whose filter is compiled in and
///   never consults the environment, so no `RUST_LOG` directive can
///   suppress the §2.7-mandated trail. The first audit events land in
///   the auth milestone; the layer is in place from the first crate so
///   the guarantee exists before its first consumer.
fn init_logging(format: LogFormat) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let general = fmt_layer(format)
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            meta.target() != "audit"
        }))
        .with_filter(env_filter);

    let audit = fmt_layer(format).with_filter(tracing_subscriber::filter::filter_fn(|meta| {
        meta.target() == "audit"
    }));

    tracing_subscriber::registry()
        .with(general)
        .with(audit)
        .init();
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_cli(&args) {
        Ok(CliOutcome::Run(cli)) => cli,
        Ok(CliOutcome::Exit(code)) => return code,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    init_logging(cli.log_format);

    // Host key: read once at startup with std::fs (ADR-0022's
    // deliberate non-async file I/O).
    let Some(host_key_path) = cli.host_key_path else {
        error!(message = "--host-key is required", "server.config_error");
        return ExitCode::FAILURE;
    };
    let pem = match std::fs::read_to_string(&host_key_path) {
        Ok(pem) => pem,
        Err(e) => {
            error!(message = %format!("cannot read host key {host_key_path}: {e}"), "server.config_error");
            return ExitCode::FAILURE;
        }
    };
    let host_key = match HostKey::from_openssh_pem(&pem) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            error!(message = %format!("cannot load host key {host_key_path}: {e}"), "server.config_error");
            return ExitCode::FAILURE;
        }
    };

    let config = Config {
        listen: cli.listen,
        handshake_timeout: cli.handshake_timeout,
        host_key,
    };
    let server = match Server::bind(&config).await {
        Ok(server) => server,
        Err(e) => {
            error!(message = %format!("cannot bind {}: {e}", cli.listen), "server.config_error");
            return ExitCode::FAILURE;
        }
    };

    match server.serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(message = %format!("accept loop failed: {e}"), "server.config_error");
            ExitCode::FAILURE
        }
    }
}
