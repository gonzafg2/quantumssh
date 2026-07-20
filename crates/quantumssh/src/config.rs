//! Configuration loading (RFC-0010, ADR-0029): TOML schema v1 and the
//! `StrictModes` startup checks.
//!
//! The file is operator-trusted, read once in the synchronous startup
//! path (ADR-0022), never on the pre-auth surface. Everything here
//! fails closed: unknown keys and sections are `deny_unknown_fields`
//! errors from the deserializer — the attribute sits on the root
//! struct too, because only root coverage rejects an unknown *section*
//! (a premature `[limits]` must refuse to start, not be ignored) — a
//! `schema_version` the binary does not know refuses to start, and a
//! trusted file that fails a permission predicate is never read.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Startup configuration failures, classified by the ADR-0029 message
/// values. `Display` renders `class: detail` — the stable class is a
/// machine-parseable prefix of the `server.config_error` `message`
/// field, and the detail still names the file and predicate the ADR
/// requires.
#[derive(Debug)]
pub enum ConfigError {
    /// A check or read could not run at all: missing file, unreadable
    /// path component, dangling symlink (`file_unavailable`).
    FileUnavailable(String),
    /// The TOML failed against schema v1: unknown key or section, type
    /// mismatch, missing `schema_version` (`schema_error`).
    SchemaError(String),
    /// `schema_version` outside the accepted set (`version_unsupported`).
    VersionUnsupported(String),
    /// A `StrictModes` predicate failed (`insecure_permissions`).
    InsecurePermissions(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileUnavailable(d) => write!(f, "file_unavailable: {d}"),
            Self::SchemaError(d) => write!(f, "schema_error: {d}"),
            Self::VersionUnsupported(d) => write!(f, "version_unsupported: {d}"),
            Self::InsecurePermissions(d) => write!(f, "insecure_permissions: {d}"),
        }
    }
}

/// Log output format (ADR-0024). Defined here so `[logging] format`
/// deserializes straight into it: an invalid value is a `schema_error`
/// from the deserializer, carrying line/column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Structured JSON — the shipping default when stderr is not a TTY.
    Json,
    /// Human-readable — the interactive-development default.
    Human,
}

/// Schema v1 root (ADR-0029).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Mandatory from v1 (RFC-0010): the compatibility gate.
    pub schema_version: u32,
    /// `[server]` — listener and handshake budget.
    #[serde(default)]
    pub server: ServerSection,
    /// `[auth]` — the trust files.
    #[serde(default)]
    pub auth: AuthSection,
    /// `[logging]` — output format.
    #[serde(default)]
    pub logging: LoggingSection,
    /// `[limits]` — admission control (ADR-0028).
    #[serde(default)]
    pub limits: LimitsSection,
}

/// `[server]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Address to bind.
    pub listen: Option<SocketAddr>,
    /// Ed25519 host key path (openssh-key-v1, unencrypted).
    pub host_key: Option<String>,
    /// Handshake budget in integer seconds (ADR-0029: no
    /// duration-string grammar).
    pub handshake_timeout: Option<u64>,
    /// Graceful-shutdown drain deadline in integer seconds
    /// (ADR-0028; default 30).
    pub drain_timeout: Option<u64>,
}

/// `[auth]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    /// `authorized_keys` path.
    pub authorized_keys: Option<String>,
}

/// `[logging]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingSection {
    /// `"json"` or `"human"`.
    pub format: Option<LogFormat>,
}

/// `[limits]` — the ADR-0028 admission caps and per-source rate limit.
/// Key names match the structured `limit` field on
/// `connection.refused`, so the event points at the knob.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Global concurrent-connection cap (default 256).
    pub max_connections: Option<usize>,
    /// Total half-open (pre-auth) cap (default 100).
    pub max_half_open: Option<usize>,
    /// Per-source half-open cap (default 10; IPv4 per address, IPv6
    /// per /64).
    pub max_per_source: Option<usize>,
    /// Per-source token-bucket refill, tokens per second (default 1).
    pub accept_rate: Option<u32>,
    /// Per-source token-bucket burst capacity (default 10).
    pub accept_burst: Option<u32>,
}

/// The `schema_version` values this binary understands (ADR-0029: the
/// set widens only with a documented compatibility rule).
const SUPPORTED_SCHEMA_VERSIONS: [u32; 1] = [1];

/// Parses schema v1, fail-closed. `origin` names the source in errors.
pub fn parse(text: &str, origin: &str) -> Result<ConfigFile, ConfigError> {
    let file: ConfigFile = basic_toml::from_str(text)
        .map_err(|e| ConfigError::SchemaError(format!("{origin}: {e}")))?;
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&file.schema_version) {
        return Err(ConfigError::VersionUnsupported(format!(
            "{origin}: schema_version {} is newer than this binary understands (supported: 1)",
            file.schema_version
        )));
    }
    // Fail-closed zero rejection: a zero cap refuses everything, a
    // zero rate never refills, a zero deadline cannot bound anything.
    let zeros = [
        (
            file.server.handshake_timeout == Some(0),
            "server.handshake_timeout",
        ),
        (file.server.drain_timeout == Some(0), "server.drain_timeout"),
        (
            file.limits.max_connections == Some(0),
            "limits.max_connections",
        ),
        (file.limits.max_half_open == Some(0), "limits.max_half_open"),
        (
            file.limits.max_per_source == Some(0),
            "limits.max_per_source",
        ),
        (file.limits.accept_rate == Some(0), "limits.accept_rate"),
        (file.limits.accept_burst == Some(0), "limits.accept_burst"),
    ];
    if let Some((_, key)) = zeros.iter().find(|(is_zero, _)| *is_zero) {
        return Err(ConfigError::SchemaError(format!(
            "{origin}: {key} must be at least 1"
        )));
    }
    Ok(file)
}

/// Reads and parses the config file. The `StrictModes` check on the file
/// itself ([`check_trusted_file`]) must run before this.
pub fn load(path: &Path) -> Result<ConfigFile, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        ConfigError::FileUnavailable(format!("{}: cannot read: {e}", path.display()))
    })?;
    parse(&text, &path.display().to_string())
}

/// How a trusted file is checked (ADR-0029): every trusted input gets
/// the integrity predicates; a `Secret` (the private host key) must
/// additionally not be group/world-readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedClass {
    /// Config file, `authorized_keys`: integrity only.
    Input,
    /// The private host key: integrity plus confidentiality.
    Secret,
}

/// Group- or world-writable bits.
const WRITE_OTHERS: u32 = 0o022;
/// Group- or world-readable bits.
const READ_OTHERS: u32 = 0o044;

/// The file-level predicates, pure so they are exhaustively testable.
/// Returns the offending predicate, or `None` when the file passes.
fn file_violation(mode: u32, owner: u32, process_uid: u32, class: TrustedClass) -> Option<String> {
    if mode & WRITE_OTHERS != 0 {
        return Some(format!("group/world-writable (mode {:04o})", mode & 0o7777));
    }
    if owner != 0 && owner != process_uid {
        return Some(format!(
            "owned by uid {owner}, not root or the process uid {process_uid}"
        ));
    }
    if class == TrustedClass::Secret && mode & READ_OTHERS != 0 {
        return Some(format!(
            "group/world-readable private key (mode {:04o})",
            mode & 0o7777
        ));
    }
    None
}

/// The ancestor-directory predicate — writability only (ADR-0029).
fn ancestor_violation(mode: u32) -> Option<String> {
    (mode & WRITE_OTHERS != 0).then(|| {
        format!(
            "group/world-writable ancestor directory (mode {:04o})",
            mode & 0o7777
        )
    })
}

/// The full `StrictModes` check (ADR-0029): canonicalise first — a
/// lexical walk over a symlink's ancestors would check the wrong
/// directories — then apply the file predicates and walk every
/// ancestor of the canonical path. Returns the canonical path so the
/// caller reads the file that was checked, not the pre-resolution name
/// (a symlink retargeted after the check would otherwise redirect the
/// read). Stat-based and best-effort against the residual stat-to-open
/// race, matching OpenSSH `secure_filename()`.
pub fn check_trusted_file(path: &Path, class: TrustedClass) -> Result<PathBuf, ConfigError> {
    let canon = std::fs::canonicalize(path).map_err(|e| {
        ConfigError::FileUnavailable(format!("{}: cannot canonicalise: {e}", path.display()))
    })?;
    let process_uid = rustix::process::geteuid().as_raw();
    let st = stat_or_unavailable(&canon)?;
    if let Some(violation) = file_violation(mode_of(&st), st.st_uid, process_uid, class) {
        return Err(ConfigError::InsecurePermissions(format!(
            "{}: {violation}",
            canon.display()
        )));
    }
    for dir in canon.ancestors().skip(1) {
        let st = stat_or_unavailable(dir)?;
        if let Some(violation) = ancestor_violation(mode_of(&st)) {
            return Err(ConfigError::InsecurePermissions(format!(
                "{}: {violation} at {}",
                canon.display(),
                dir.display()
            )));
        }
    }
    Ok(canon)
}

fn stat_or_unavailable(path: &Path) -> Result<rustix::fs::Stat, ConfigError> {
    rustix::fs::stat(path)
        .map_err(|e| ConfigError::FileUnavailable(format!("{}: cannot stat: {e}", path.display())))
}

fn mode_of(st: &rustix::fs::Stat) -> u32 {
    // `st_mode` is u16 on the libc (macOS) backend and u32 on
    // linux_raw; the conversion is identity on the latter.
    #[allow(clippy::useless_conversion)]
    u32::from(st.st_mode)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    // ---- schema ----

    #[test]
    fn parses_full_valid_config() {
        let file = parse(
            r#"
schema_version = 1
[server]
listen = "0.0.0.0:2222"
host_key = "/etc/quantumssh/hostkey"
handshake_timeout = 10
[auth]
authorized_keys = "/etc/quantumssh/authorized_keys"
[logging]
format = "human"
"#,
            "test",
        )
        .expect("valid config");
        assert_eq!(file.schema_version, 1);
        assert_eq!(file.server.listen, Some("0.0.0.0:2222".parse().unwrap()));
        assert_eq!(file.server.handshake_timeout, Some(10));
        assert_eq!(file.logging.format, Some(LogFormat::Human));
    }

    #[test]
    fn minimal_config_defaults_every_section() {
        let file = parse("schema_version = 1", "test").expect("minimal config");
        assert!(file.server.listen.is_none());
        assert!(file.auth.authorized_keys.is_none());
        assert!(file.logging.format.is_none());
    }

    #[test]
    fn unknown_root_section_is_schema_error() {
        // The fail-closed guarantee for deferred sections (ADR-0029):
        // a premature [session] refuses to start, never boots ignored.
        // ([limits] graduated with the ADR-0028 implementation.)
        let err = parse("schema_version = 1\n[session]\naccept_env = []", "test").unwrap_err();
        assert!(matches!(err, ConfigError::SchemaError(_)), "{err}");
    }

    #[test]
    fn limits_section_parses_with_partial_keys() {
        let file = parse(
            "schema_version = 1\n[limits]\nmax_per_source = 4\naccept_burst = 20",
            "test",
        )
        .expect("limits config");
        assert_eq!(file.limits.max_per_source, Some(4));
        assert_eq!(file.limits.accept_burst, Some(20));
        assert!(file.limits.max_connections.is_none());
    }

    #[test]
    fn zero_limit_keys_are_schema_errors() {
        for snippet in [
            "[limits]\nmax_connections = 0",
            "[limits]\nmax_half_open = 0",
            "[limits]\nmax_per_source = 0",
            "[limits]\naccept_rate = 0",
            "[limits]\naccept_burst = 0",
            "[server]\ndrain_timeout = 0",
        ] {
            let err = parse(&format!("schema_version = 1\n{snippet}"), "test").unwrap_err();
            assert!(
                matches!(err, ConfigError::SchemaError(_)),
                "{snippet}: {err}"
            );
        }
    }

    #[test]
    fn unknown_key_in_section_is_schema_error() {
        let err = parse("schema_version = 1\n[server]\nport = 22", "test").unwrap_err();
        assert!(matches!(err, ConfigError::SchemaError(_)), "{err}");
    }

    #[test]
    fn type_mismatch_is_schema_error() {
        let err = parse(
            "schema_version = 1\n[server]\nhandshake_timeout = \"30s\"",
            "test",
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::SchemaError(_)), "{err}");
    }

    #[test]
    fn missing_schema_version_is_schema_error() {
        let err = parse("[server]\nhandshake_timeout = 30", "test").unwrap_err();
        assert!(matches!(err, ConfigError::SchemaError(_)), "{err}");
    }

    #[test]
    fn newer_schema_version_refuses_to_start() {
        let err = parse("schema_version = 2", "test").unwrap_err();
        assert!(matches!(err, ConfigError::VersionUnsupported(_)), "{err}");
    }

    #[test]
    fn zero_handshake_timeout_is_schema_error() {
        let err = parse(
            "schema_version = 1\n[server]\nhandshake_timeout = 0",
            "test",
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::SchemaError(_)), "{err}");
    }

    #[test]
    fn invalid_log_format_is_schema_error() {
        let err = parse("schema_version = 1\n[logging]\nformat = \"xml\"", "test").unwrap_err();
        assert!(matches!(err, ConfigError::SchemaError(_)), "{err}");
    }

    #[test]
    fn invalid_listen_address_is_schema_error() {
        let err = parse("schema_version = 1\n[server]\nlisten = \"nope\"", "test").unwrap_err();
        assert!(matches!(err, ConfigError::SchemaError(_)), "{err}");
    }

    // ---- pure predicates ----

    const UID: u32 = 1000;

    #[test]
    fn input_owner_modes_pass() {
        for mode in [0o600, 0o644, 0o640, 0o400] {
            assert_eq!(file_violation(mode, UID, UID, TrustedClass::Input), None);
        }
    }

    #[test]
    fn root_owned_input_passes() {
        assert_eq!(file_violation(0o644, 0, UID, TrustedClass::Input), None);
    }

    #[test]
    fn group_or_world_writable_file_fails() {
        for mode in [0o620, 0o602, 0o666, 0o622] {
            assert!(file_violation(mode, UID, UID, TrustedClass::Input).is_some());
        }
    }

    #[test]
    fn foreign_owner_fails() {
        assert!(file_violation(0o600, UID + 1, UID, TrustedClass::Input).is_some());
    }

    #[test]
    fn secret_readable_by_group_or_world_fails() {
        for mode in [0o640, 0o604, 0o644] {
            assert!(file_violation(mode, UID, UID, TrustedClass::Secret).is_some());
            // The same modes are fine for a non-secret trusted input.
            assert_eq!(file_violation(mode, UID, UID, TrustedClass::Input), None);
        }
    }

    #[test]
    fn secret_0600_passes() {
        assert_eq!(file_violation(0o600, UID, UID, TrustedClass::Secret), None);
    }

    #[test]
    fn ancestor_writability_is_the_only_ancestor_predicate() {
        assert!(ancestor_violation(0o775).is_some());
        assert!(ancestor_violation(0o757).is_some());
        assert_eq!(ancestor_violation(0o755), None);
        assert_eq!(ancestor_violation(0o700), None);
    }

    // ---- end-to-end walk over the real filesystem ----
    //
    // Trees live under the workspace `target/` (the checkout's ancestor
    // chain must itself pass the walk — the same assumption the interop
    // harness makes), one unique root per test to survive parallel runs.

    fn tree(name: &str) -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/strictmodes-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create test tree");
        set_mode(&root, 0o700);
        root
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set test mode");
    }

    fn write_file(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, "test").expect("write test file");
        set_mode(&path, mode);
        path
    }

    #[test]
    fn e2e_secret_0600_in_0700_dir_passes() {
        let root = tree("ok");
        let key = write_file(&root, "hostkey", 0o600);
        check_trusted_file(&key, TrustedClass::Secret).expect("0600 secret must pass");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn e2e_world_readable_secret_is_insecure_permissions() {
        let root = tree("readable");
        let key = write_file(&root, "hostkey", 0o644);
        let err = check_trusted_file(&key, TrustedClass::Secret).unwrap_err();
        assert!(matches!(err, ConfigError::InsecurePermissions(_)), "{err}");
        assert!(err.to_string().contains("readable"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn e2e_group_writable_parent_is_insecure_permissions() {
        let root = tree("parent");
        let sub = root.join("sub");
        std::fs::create_dir(&sub).expect("create subdir");
        set_mode(&sub, 0o770);
        let file = write_file(&sub, "authorized_keys", 0o600);
        let err = check_trusted_file(&file, TrustedClass::Input).unwrap_err();
        assert!(matches!(err, ConfigError::InsecurePermissions(_)), "{err}");
        assert!(err.to_string().contains("ancestor"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn e2e_symlink_is_checked_against_the_target_chain() {
        // The canonicalisation requirement: a clean-looking symlink to a
        // file inside a group-writable directory must fail on the
        // target's ancestry, not pass on the symlink's.
        let root = tree("symlink");
        let clean = root.join("clean");
        let dirty = root.join("dirty");
        std::fs::create_dir(&clean).expect("create clean dir");
        std::fs::create_dir(&dirty).expect("create dirty dir");
        set_mode(&clean, 0o700);
        set_mode(&dirty, 0o770);
        let target = write_file(&dirty, "authorized_keys", 0o600);
        let link = clean.join("authorized_keys");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        let err = check_trusted_file(&link, TrustedClass::Input).unwrap_err();
        assert!(matches!(err, ConfigError::InsecurePermissions(_)), "{err}");
        assert!(err.to_string().contains("dirty"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn e2e_missing_file_is_file_unavailable() {
        let root = tree("missing");
        let err = check_trusted_file(&root.join("nope"), TrustedClass::Input).unwrap_err();
        assert!(matches!(err, ConfigError::FileUnavailable(_)), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
