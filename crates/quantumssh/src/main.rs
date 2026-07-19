//! `QuantumSSH` server binary — a thin entrypoint (ADR-0017): parse the
//! CLI, load the optional TOML config (RFC-0010 / ADR-0029), construct
//! the log subscriber (ADR-0024), build the Tokio runtime (ADR-0022),
//! and hand off to `quantumssh_core`.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use std::sync::Arc;

use quantumssh_core::admission::Limits;
use quantumssh_core::auth::AuthorizedKeys;
use quantumssh_core::host_key::HostKey;
use quantumssh_core::server::{Config, Server};
use quantumssh_core::transport::RekeyThresholds;
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use zeroize::Zeroizing;

mod config;
mod log_fields;
use config::{ConfigFile, LogFormat, TrustedClass};
use log_fields::EscapingFields;

const DEFAULT_LISTEN: &str = "127.0.0.1:2222";
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 30;
/// ADR-0028: graceful-shutdown drain deadline default.
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;
/// ADR-0028: each exec holds up to four `spawn_blocking` tasks
/// (stdout/stderr/stdin pumps and the reap), so the blocking pool is
/// sized from the connection cap — admission control, not thread-pool
/// starvation, is what bounds concurrency.
const BLOCKING_THREADS_PER_CONNECTION: usize = 4;

const USAGE: &str = "\
quantumssh — memory-safe, post-quantum-first SSH server (pre-alpha)

USAGE:
    quantumssh [OPTIONS]

OPTIONS:
    --config <PATH>               TOML configuration file (RFC-0010,
                                  schema v1). Optional; flags override
                                  its values (CLI > config > default)
    --listen <ADDR>               Address to bind (default: 127.0.0.1:2222)
    --host-key <PATH>             Ed25519 host key file (openssh-key-v1,
                                  unencrypted; ssh-keygen -t ed25519).
                                  Required (flag or [server].host_key).
    --authorized-keys <PATH>      authorized_keys file (one ssh-ed25519
                                  key per line). Required (flag or
                                  [auth].authorized_keys).
    --handshake-timeout <SECS>    Budget from TCP accept to handshake
                                  completion (default: 30; ADR-0022)
    --log-format <FORMAT>         'json' or 'human' (default: json when
                                  stderr is not a TTY, human when it is)
    --help                        Print this help
    --version                     Print version
";

/// Parsed command line. Every value an operator can also set in the
/// config file is an `Option` here — `None` means "not given on the
/// CLI", which the precedence merge ([`resolve`]) needs to tell a
/// default apart from an explicit flag (ADR-0029).
#[derive(Debug, Default)]
struct Cli {
    config_path: Option<String>,
    listen: Option<SocketAddr>,
    host_key_path: Option<String>,
    authorized_keys_path: Option<String>,
    handshake_timeout: Option<Duration>,
    log_format: Option<LogFormat>,
}

enum CliOutcome {
    Run(Cli),
    Exit(ExitCode),
}

fn parse_cli(args: &[String]) -> Result<CliOutcome, String> {
    let mut cli = Cli::default();

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => {
                let value = it.next().ok_or("--config requires a path")?;
                cli.config_path = Some(value.clone());
            }
            "--listen" => {
                let value = it.next().ok_or("--listen requires an address")?;
                cli.listen = Some(
                    value
                        .parse()
                        .map_err(|e| format!("invalid --listen address '{value}': {e}"))?,
                );
            }
            "--host-key" => {
                let value = it.next().ok_or("--host-key requires a path")?;
                cli.host_key_path = Some(value.clone());
            }
            "--authorized-keys" => {
                let value = it.next().ok_or("--authorized-keys requires a path")?;
                cli.authorized_keys_path = Some(value.clone());
            }
            "--handshake-timeout" => {
                let value = it.next().ok_or("--handshake-timeout requires seconds")?;
                let secs: u64 = value
                    .parse()
                    .map_err(|e| format!("invalid --handshake-timeout '{value}': {e}"))?;
                if secs == 0 {
                    return Err("--handshake-timeout must be at least 1 second".into());
                }
                cli.handshake_timeout = Some(Duration::from_secs(secs));
            }
            "--log-format" => {
                let value = it.next().ok_or("--log-format requires 'json' or 'human'")?;
                cli.log_format = Some(match value.as_str() {
                    "json" => LogFormat::Json,
                    "human" => LogFormat::Human,
                    other => return Err(format!("invalid --log-format '{other}'")),
                });
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

    Ok(CliOutcome::Run(cli))
}

/// The fully-resolved configuration after the `CLI > config > default`
/// merge (ADR-0029).
#[derive(Debug)]
struct Resolved {
    listen: SocketAddr,
    host_key_path: Option<String>,
    authorized_keys_path: Option<String>,
    handshake_timeout: Duration,
    log_format: LogFormat,
    /// ADR-0028 admission knobs — config-file-only (RFC-0010:
    /// everything new lives only in the file).
    limits: Limits,
    /// ADR-0028 drain deadline — config-file-only.
    drain_timeout: Duration,
    /// Keys where an explicit flag overrode a set config value — each
    /// is logged at info so the override is visible (RFC-0010).
    overrides: Vec<&'static str>,
}

/// One key's merge: flag wins, then config, then default; a flag
/// shadowing a set config value is recorded for the startup log.
fn pick<T>(
    cli: Option<T>,
    file: Option<T>,
    default: T,
    key: &'static str,
    overrides: &mut Vec<&'static str>,
) -> T {
    if cli.is_some() && file.is_some() {
        overrides.push(key);
    }
    cli.or(file).unwrap_or(default)
}

/// [`pick`] for values with no default (the required paths).
fn pick_opt<T>(
    cli: Option<T>,
    file: Option<T>,
    key: &'static str,
    overrides: &mut Vec<&'static str>,
) -> Option<T> {
    if cli.is_some() && file.is_some() {
        overrides.push(key);
    }
    cli.or(file)
}

fn resolve(
    cli: Cli,
    file: Option<&ConfigFile>,
    default_listen: SocketAddr,
    tty_default: LogFormat,
) -> Resolved {
    let server = file.map(|f| &f.server);
    let mut overrides = Vec::new();
    let listen = pick(
        cli.listen,
        server.and_then(|s| s.listen),
        default_listen,
        "listen",
        &mut overrides,
    );
    let host_key_path = pick_opt(
        cli.host_key_path,
        server.and_then(|s| s.host_key.clone()),
        "host_key",
        &mut overrides,
    );
    let authorized_keys_path = pick_opt(
        cli.authorized_keys_path,
        file.and_then(|f| f.auth.authorized_keys.clone()),
        "authorized_keys",
        &mut overrides,
    );
    let handshake_timeout = pick(
        cli.handshake_timeout,
        server
            .and_then(|s| s.handshake_timeout)
            .map(Duration::from_secs),
        Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
        "handshake_timeout",
        &mut overrides,
    );
    let log_format = pick(
        cli.log_format,
        file.and_then(|f| f.logging.format),
        tty_default,
        "log_format",
        &mut overrides,
    );
    let defaults = Limits::default();
    let limits_section = file.map(|f| &f.limits);
    let get = |value: fn(&config::LimitsSection) -> Option<usize>, default: usize| {
        limits_section.and_then(value).unwrap_or(default)
    };
    let get32 = |value: fn(&config::LimitsSection) -> Option<u32>, default: u32| {
        limits_section.and_then(value).unwrap_or(default)
    };
    let limits = Limits {
        max_connections: get(|l| l.max_connections, defaults.max_connections),
        max_half_open: get(|l| l.max_half_open, defaults.max_half_open),
        max_per_source: get(|l| l.max_per_source, defaults.max_per_source),
        accept_rate: get32(|l| l.accept_rate, defaults.accept_rate),
        accept_burst: get32(|l| l.accept_burst, defaults.accept_burst),
    };
    let drain_timeout = Duration::from_secs(
        server
            .and_then(|s| s.drain_timeout)
            .unwrap_or(DEFAULT_DRAIN_TIMEOUT_SECS),
    );
    Resolved {
        listen,
        host_key_path,
        authorized_keys_path,
        handshake_timeout,
        log_format,
        limits,
        drain_timeout,
        overrides,
    }
}

/// One formatting layer (JSON or human) writing to stderr.
fn fmt_layer<S>(format: LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    let base = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    match format {
        // serde escapes control bytes; no custom formatter needed.
        LogFormat::Json => base.json().boxed(),
        // The ADR-0024 field formatter: control bytes in field values
        // rendered as visible `\xNN`, never live (§5.4.3).
        LogFormat::Human => base.fmt_fields(EscapingFields).boxed(),
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

/// Loads and checks the optional config file — `StrictModes` on the
/// file itself first, per RFC-0010.
fn load_config_file(cli: &Cli) -> Result<Option<ConfigFile>, config::ConfigError> {
    cli.config_path.as_deref().map_or(Ok(None), |p| {
        // Read the canonical path the check returns — the checked file
        // is the read file, even if the given name is a symlink.
        let canon = config::check_trusted_file(Path::new(p), TrustedClass::Input)?;
        config::load(&canon).map(Some)
    })
}

/// `StrictModes` (ADR-0029 — the host key is a secret *and* a trusted
/// input), then read once at startup with `std::fs` (ADR-0022's
/// deliberate non-async file I/O). Logs and returns `None` on failure.
fn load_host_key(path: &str) -> Option<Arc<HostKey>> {
    // Read the canonical path the check returns — the checked file is
    // the read file, even if the given name is a symlink.
    let canon = match config::check_trusted_file(Path::new(path), TrustedClass::Secret) {
        Ok(canon) => canon,
        Err(e) => {
            error!(message = %e, "server.config_error");
            return None;
        }
    };
    // Zeroizing: the PEM holds the private seed; erase the buffer on
    // drop instead of leaving it readable for the process lifetime
    // (threat model §4.3).
    let pem = match std::fs::read_to_string(&canon) {
        Ok(pem) => Zeroizing::new(pem),
        Err(e) => {
            error!(message = %format!("cannot read host key {}: {e}", canon.display()), "server.config_error");
            return None;
        }
    };
    match HostKey::from_openssh_pem(&pem) {
        Ok(k) => Some(Arc::new(k)),
        Err(e) => {
            error!(message = %format!("cannot load host key {}: {e}", canon.display()), "server.config_error");
            None
        }
    }
}

/// `StrictModes`, then read once at startup (ADR-0022). Logs and
/// returns `None` on failure.
fn load_authorized_keys(path: &str) -> Option<Arc<AuthorizedKeys>> {
    // Same canonical-read rule as the host key.
    let canon = match config::check_trusted_file(Path::new(path), TrustedClass::Input) {
        Ok(canon) => canon,
        Err(e) => {
            error!(message = %e, "server.config_error");
            return None;
        }
    };
    match AuthorizedKeys::load(&canon) {
        Ok(k) => Some(Arc::new(k)),
        Err(e) => {
            error!(message = %format!("cannot load authorized_keys {}: {e}", canon.display()), "server.config_error");
            None
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_cli(&args) {
        Ok(CliOutcome::Run(cli)) => cli,
        Ok(CliOutcome::Exit(code)) => return code,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let default_listen: SocketAddr = match DEFAULT_LISTEN.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("error: internal default listen address invalid: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tty_default = if std::io::stderr().is_terminal() {
        LogFormat::Human
    } else {
        LogFormat::Json
    };

    // The config file loads before the subscriber exists — its own
    // `[logging] format` may decide the format — so on failure the
    // subscriber is initialised with the CLI-or-TTY format first: a
    // config failure must reach `server.config_error`, not stderr
    // prose (RFC-0010 §Failure modes).
    let resolved = match load_config_file(&cli) {
        Err(e) => {
            init_logging(cli.log_format.unwrap_or(tty_default));
            error!(message = %e, "server.config_error");
            return ExitCode::FAILURE;
        }
        Ok(file) => resolve(cli, file.as_ref(), default_listen, tty_default),
    };
    init_logging(resolved.log_format);
    for key in &resolved.overrides {
        info!(key = %key, "command-line flag overrides the config file value");
    }

    // The binary constructs the runtime (ADR-0022), sized per
    // ADR-0028: blocking threads scale with the connection cap.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(
            BLOCKING_THREADS_PER_CONNECTION
                .saturating_mul(resolved.limits.max_connections)
                .max(1),
        )
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            error!(message = %format!("cannot build the runtime: {e}"), "server.config_error");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run(resolved))
}

/// The SIGTERM/SIGINT listener (ADR-0028): the first signal broadcasts
/// the drain deadline; a second broadcasts an immediate one, skipping
/// what remains of the drain.
async fn signal_listener(tx: broadcast::Sender<Instant>, drain: Duration) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        tracing::warn!("cannot install SIGTERM/SIGINT handlers; graceful shutdown unavailable");
        return;
    };
    tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
    info!(
        drain_seconds = drain.as_secs(),
        "shutdown signal received; draining"
    );
    let _ = tx.send(Instant::now() + drain);
    tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
    info!("second shutdown signal received; aborting the drain");
    let _ = tx.send(Instant::now());
}

async fn run(resolved: Resolved) -> ExitCode {
    let Some(host_key_path) = resolved.host_key_path else {
        error!(
            message = "host key is required (--host-key or [server].host_key)",
            "server.config_error"
        );
        return ExitCode::FAILURE;
    };
    let Some(host_key) = load_host_key(&host_key_path) else {
        return ExitCode::FAILURE;
    };
    let Some(authorized_keys_path) = resolved.authorized_keys_path else {
        error!(
            message = "authorized_keys is required (--authorized-keys or [auth].authorized_keys)",
            "server.config_error"
        );
        return ExitCode::FAILURE;
    };
    let Some(authorized_keys) = load_authorized_keys(&authorized_keys_path) else {
        return ExitCode::FAILURE;
    };

    let config = Config {
        listen: resolved.listen,
        handshake_timeout: resolved.handshake_timeout,
        host_key,
        authorized_keys,
        // ADR-0026 BSI defaults (1 GiB / 1 h); the re-key completion budget
        // mirrors the handshake budget.
        rekey: RekeyThresholds::bsi_defaults(resolved.handshake_timeout),
        limits: resolved.limits,
    };
    let server = match Server::bind(&config).await {
        Ok(server) => server,
        Err(e) => {
            error!(message = %format!("cannot bind {}: {e}", resolved.listen), "server.config_error");
            return ExitCode::FAILURE;
        }
    };

    // Graceful shutdown (ADR-0028): the signal listener drives the
    // broadcast the accept loop and every connection subscribe to.
    // Exit code is 0 on both the drained and the aborted path — the
    // shutdown completed as commanded.
    let (shutdown_tx, initial_rx) = broadcast::channel(4);
    drop(initial_rx);
    drop(tokio::spawn(signal_listener(
        shutdown_tx.clone(),
        resolved.drain_timeout,
    )));
    match server.serve(shutdown_tx).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(message = %format!("accept loop failed: {e}"), "server.config_error");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    fn run(list: &[&str]) -> Cli {
        match parse_cli(&args(list)).expect("parse") {
            CliOutcome::Run(cli) => cli,
            CliOutcome::Exit(_) => panic!("expected Run"),
        }
    }

    #[test]
    fn bare_invocation_sets_nothing() {
        let cli = run(&[]);
        assert!(cli.config_path.is_none());
        assert!(cli.listen.is_none());
        assert!(cli.log_format.is_none());
        assert!(cli.handshake_timeout.is_none());
    }

    #[test]
    fn config_flag_is_parsed() {
        let cli = run(&["--config", "/etc/quantumssh/config.toml"]);
        assert_eq!(
            cli.config_path.as_deref(),
            Some("/etc/quantumssh/config.toml")
        );
    }

    #[test]
    fn zero_handshake_timeout_flag_rejected() {
        assert!(parse_cli(&args(&["--handshake-timeout", "0"])).is_err());
    }

    fn file(text: &str) -> ConfigFile {
        config::parse(text, "test").expect("test config")
    }

    const DEFAULT_ADDR: &str = "127.0.0.1:2222";

    #[test]
    fn resolve_defaults_when_nothing_is_set() {
        let r = resolve(
            Cli::default(),
            None,
            DEFAULT_ADDR.parse().unwrap(),
            LogFormat::Json,
        );
        assert_eq!(r.listen, DEFAULT_ADDR.parse().unwrap());
        assert_eq!(r.handshake_timeout, Duration::from_secs(30));
        assert_eq!(r.log_format, LogFormat::Json);
        assert!(r.host_key_path.is_none());
        assert!(r.overrides.is_empty());
    }

    #[test]
    fn resolve_config_beats_default() {
        let f = file(
            "schema_version = 1\n[server]\nlisten = \"0.0.0.0:22\"\nhandshake_timeout = 5\n[logging]\nformat = \"human\"",
        );
        let r = resolve(
            Cli::default(),
            Some(&f),
            DEFAULT_ADDR.parse().unwrap(),
            LogFormat::Json,
        );
        assert_eq!(r.listen, "0.0.0.0:22".parse().unwrap());
        assert_eq!(r.handshake_timeout, Duration::from_secs(5));
        assert_eq!(r.log_format, LogFormat::Human);
        assert!(r.overrides.is_empty());
    }

    #[test]
    fn resolve_cli_beats_config_and_records_the_override() {
        let f =
            file("schema_version = 1\n[server]\nlisten = \"0.0.0.0:22\"\nhost_key = \"/cfg/key\"");
        let cli = Cli {
            listen: Some("127.0.0.1:2200".parse().unwrap()),
            host_key_path: Some("/cli/key".to_string()),
            ..Cli::default()
        };
        let r = resolve(
            cli,
            Some(&f),
            DEFAULT_ADDR.parse().unwrap(),
            LogFormat::Json,
        );
        assert_eq!(r.listen, "127.0.0.1:2200".parse().unwrap());
        assert_eq!(r.host_key_path.as_deref(), Some("/cli/key"));
        assert_eq!(r.overrides, vec!["listen", "host_key"]);
    }

    #[test]
    fn resolve_paths_fall_through_to_config() {
        let f = file("schema_version = 1\n[auth]\nauthorized_keys = \"/cfg/ak\"");
        let r = resolve(
            Cli::default(),
            Some(&f),
            DEFAULT_ADDR.parse().unwrap(),
            LogFormat::Json,
        );
        assert_eq!(r.authorized_keys_path.as_deref(), Some("/cfg/ak"));
        assert!(r.overrides.is_empty());
    }
}
