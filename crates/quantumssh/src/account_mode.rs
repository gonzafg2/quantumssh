//! Account mode's startup in the binary (RFC-0019, RFC-0020; ADR-0066,
//! ADR-0070): the launcher's checks as root, and the network server's
//! own start under the launcher.

use std::collections::HashSet;
use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use quantumssh_core::account::{self, AccountRecord, ResolveError};
use quantumssh_core::auth::{AccountKeys, AccountMode, AuthorizedKeys};
use quantumssh_core::launcher::{self, Malformed, Reply};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
use tracing::warn;

use crate::config::{AccountEntry, ConfigError};

/// The service account the network server runs as (ADR-0066 §1).
pub const SERVICE_ACCOUNT: &str = "quantumssh";

/// The network server's first steps under the launcher, before any thread
/// exists (ADR-0066 §2): `no_new_privs`, the check of its own privileges,
/// and the listening socket from stdin.
///
/// # Errors
///
/// A step failed; the caller exits with failure.
pub fn server_preflight() -> Result<std::net::TcpListener, String> {
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("no_new_privs: {e}"))?;
    check_unprivileged()?;
    let stdin = io::stdin();
    let fd = receive_listener(stdin.as_fd()).map_err(|e| format!("listener: {e}"))?;
    Ok(std::net::TcpListener::from(fd))
}

/// ADR-0066 §2, step 2: no root IDs, saved ones included, no groups, and
/// no capability, or the server refuses to run.
fn check_unprivileged() -> Result<(), String> {
    use rustix::process::{Gid, Uid, getegid, geteuid, getgid, getgroups, getuid};
    use rustix::thread::{capabilities, set_thread_res_gid, set_thread_res_uid};
    if getuid().is_root() || geteuid().is_root() || getgid() == Gid::ROOT || getegid() == Gid::ROOT
    {
        return Err("the network server runs as root".to_string());
    }
    if !getgroups().is_ok_and(|g| g.is_empty()) {
        return Err("the network server has supplementary groups".to_string());
    }
    let caps = capabilities(None).map_err(|e| format!("capget: {e}"))?;
    if !(caps.permitted.is_empty() && caps.effective.is_empty() && caps.inheritable.is_empty()) {
        return Err("the network server holds capabilities".to_string());
    }
    if set_thread_res_uid(Uid::ROOT, Uid::ROOT, Uid::ROOT).is_ok()
        || set_thread_res_gid(Gid::ROOT, Gid::ROOT, Gid::ROOT).is_ok()
    {
        return Err("the network server could regain root".to_string());
    }
    Ok(())
}

/// Reads `listener` and its one descriptor (ADR-0063 §4, ADR-0066 §2).
fn receive_listener(socket: impl AsFd) -> io::Result<OwnedFd> {
    let mut buf = [0u8; 16];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = rustix::net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut buf)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut fds: Vec<OwnedFd> = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    let reply = launcher::parse_reply(&buf[..msg.bytes])
        .map_err(|Malformed(rule)| io::Error::other(rule))?;
    if reply != Reply::Listener || msg.flags.contains(ReturnFlags::CTRUNC) || fds.len() != 1 {
        return Err(io::Error::other("no listener from the launcher"));
    }
    fds.pop().ok_or_else(|| io::Error::other("no listener"))
}

/// What the launcher's checks resolved (ADR-0066 §1).
pub struct Checked {
    /// The service account's UID and GID.
    pub service: (u32, u32),
    /// The listed names.
    pub accounts: HashSet<String>,
}

/// ADR-0066 §1 and ADR-0070 §3's checks, as root: RFC-0019 §8's file
/// check on every file that grants access, the launcher's own executable,
/// every listed account, and the service account. An account that cannot
/// be reached leaves a diagnostic record and does not stop the start
/// (ADR-0070 §4).
///
/// # Errors
///
/// The first failure, with its ADR-0070 §3 class.
pub fn check_as_root(
    config_path: &Path,
    ca_path: Option<&str>,
    entries: &[AccountEntry],
) -> Result<Checked, ConfigError> {
    let root_file = |path: &Path| {
        account::check_root_file(path).map_err(|e| match e {
            account::FileCheck::Unavailable(d) => ConfigError::FileUnavailable(d),
            account::FileCheck::Insecure(d) => ConfigError::InsecurePermissions(d),
        })
    };
    root_file(config_path)?;
    if let Some(ca) = ca_path {
        root_file(Path::new(ca))?;
    }
    for entry in entries {
        if let Some(keys) = &entry.authorized_keys {
            root_file(Path::new(keys))?;
        }
    }
    root_file(Path::new(account::PASSWD))?;
    root_file(Path::new(account::GROUP))?;
    let exe = std::fs::canonicalize("/proc/self/exe").map_err(|e| {
        ConfigError::FileUnavailable(format!("/proc/self/exe: cannot canonicalise: {e}"))
    })?;
    root_file(&exe)?;

    let service = account::resolve(SERVICE_ACCOUNT).map_err(|e| {
        ConfigError::AccountMode(format!(
            "service account {SERVICE_ACCOUNT:?}: {}",
            unresolved(&e)
        ))
    })?;
    if service.uid == 0 || service.gid == 0 {
        return Err(ConfigError::AccountMode(format!(
            "service account {SERVICE_ACCOUNT:?}: its UID and primary GID must not be 0"
        )));
    }
    let mut accounts = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let here = format!("account #{} ({:?})", i + 1, entry.name);
        match account::resolve(&entry.name) {
            Ok(AccountRecord { uid: 0, .. }) => {
                return Err(ConfigError::AccountMode(format!(
                    "{here}: UID 0 cannot be listed"
                )));
            }
            Ok(record) if record.uid == service.uid => {
                return Err(ConfigError::AccountMode(format!(
                    "service account {SERVICE_ACCOUNT:?}: UID {} is also {here}",
                    service.uid
                )));
            }
            Ok(_) => {}
            Err(ResolveError::Unresolved(reason)) => {
                warn!(
                    account = entry.name.as_str(),
                    reason = reason.as_str(),
                    "account unreachable"
                );
            }
            Err(ResolveError::File(e)) => return Err(ConfigError::FileUnavailable(e.to_string())),
        }
        accounts.insert(entry.name.clone());
    }
    Ok(Checked {
        service: (service.uid, service.gid),
        accounts,
    })
}

fn unresolved(e: &ResolveError) -> String {
    match e {
        ResolveError::Unresolved(reason) => reason.as_str().to_string(),
        ResolveError::File(e) => e.to_string(),
    }
}

/// The network server's credentials in account mode: every account's key
/// file, and the read of `/etc/passwd` and `/etc/group` (RFC-0019 §4, §5).
/// An account whose file holds no key, with no CA set, leaves a
/// diagnostic record (ADR-0070 §4).
///
/// # Errors
///
/// A key file that cannot be loaded: the detail of an
/// `invalid_authorized_keys` record (ADR-0070 §3).
pub fn credentials(entries: &[AccountEntry], ca_set: bool) -> Result<AccountMode, String> {
    let mut keys = AccountKeys::default();
    for (i, entry) in entries.iter().enumerate() {
        let loaded = match &entry.authorized_keys {
            Some(path) => AuthorizedKeys::load_account(Path::new(path))
                .map_err(|e| format!("account #{} ({:?}): {path}: {e}", i + 1, entry.name))?,
            None => AuthorizedKeys::none(),
        };
        if loaded.is_empty() && !ca_set {
            warn!(
                account = entry.name.as_str(),
                reason = "no_key",
                "account unreachable"
            );
        }
        keys.insert(entry.name.clone(), loaded);
    }
    Ok(AccountMode {
        keys,
        resolve: Arc::new(account::resolve),
    })
}
