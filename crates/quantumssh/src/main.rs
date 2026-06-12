//! `QuantumSSH` server binary — a thin entrypoint (ADR-0017): parse the
//! CLI, construct the log subscriber (ADR-0024), build the Tokio
//! runtime (ADR-0022), and hand off to `quantumssh_core`.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::process::ExitCode;

use quantumssh_core::server::{Config, Server};
use tracing::error;
use tracing_subscriber::EnvFilter;

const DEFAULT_LISTEN: &str = "127.0.0.1:2222";

const USAGE: &str = "\
quantumssh — memory-safe, post-quantum-first SSH server (pre-alpha)

USAGE:
    quantumssh [OPTIONS]

OPTIONS:
    --listen <ADDR>          Address to bind (default: 127.0.0.1:2222)
    --log-format <FORMAT>    'json' or 'human' (default: json when
                             stderr is not a TTY, human when it is)
    --help                   Print this help
    --version                Print version
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

    Ok(CliOutcome::Run(Cli { listen, log_format }))
}

/// Installs the global subscriber. All output goes to stderr — the
/// sink threat-model §2.7 names; stdout is reserved and unused by
/// logging (ADR-0024).
fn init_logging(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Json => builder.json().init(),
        LogFormat::Human => builder.init(),
    }
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

    let config = Config { listen: cli.listen };
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
