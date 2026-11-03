//! `quantumssh keygen <PATH>` end to end (RFC-0018, ADR-0058 §4): the real
//! binary writes the pair with the modes it reports, refuses every unsafe
//! target without leaving a file behind, and rejects every usage-error
//! shape. The keys are generated at run time; no key fixture is committed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use quantumssh_core::host_key::{HostKey, base64_encode_nopad};

const BIN: &str = env!("CARGO_BIN_EXE_quantumssh");

/// A private directory under `target/`. The ancestor rule refuses a
/// directory below a group- or world-writable one, such as `/tmp` or a
/// `target/` created under `umask 002`, so the directories this repository
/// owns on the way lose their group and world write bits, as the interop
/// script does for `target/`.
fn tree(name: &str) -> PathBuf {
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let base = target.join("keygen-tests");
    std::fs::create_dir_all(&base).expect("create test base");
    for dir in [&target, &base] {
        chmod(dir, mode(dir) & !0o022);
    }
    let root = base.join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create test tree");
    chmod(&root, 0o700);
    std::fs::canonicalize(&root).expect("canonicalize")
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

fn keygen(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("run quantumssh")
}

/// The sorted names in `dir`.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
        .collect();
    names.sort();
    names
}

fn pub_path(key: &Path) -> PathBuf {
    let mut name = key.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Checks a successful run: the report, the modes, and a pair the loader
/// reads back with the fingerprint `keygen` printed.
fn assert_written(output: &Output, key: &Path) {
    let stdout = String::from_utf8(output.stdout.clone()).expect("utf-8");
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let public = pub_path(key);
    assert_eq!(mode(key), 0o600);
    assert_eq!(mode(&public), 0o644);

    let loaded = HostKey::from_openssh_pem(&std::fs::read_to_string(key).expect("read key"))
        .expect("the loader reads the key keygen wrote");
    let mut b64 = base64_encode_nopad(&loaded.public_key_blob());
    while !b64.len().is_multiple_of(4) {
        b64.push('=');
    }
    assert_eq!(
        std::fs::read_to_string(&public).expect("read .pub"),
        format!("ssh-mldsa44-ed25519 {b64}\n")
    );
    assert_eq!(
        stdout,
        format!(
            "wrote {} (private, 0600)\nwrote {} (public, 0644)\n{}\n",
            key.display(),
            public.display(),
            loaded.fingerprint_sha256()
        )
    );
}

/// Checks a refused run: a failure, nothing on stdout, and `dir` left with
/// exactly `before`.
fn assert_refused(output: &Output, dir: &Path, before: &[String], why: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "keygen succeeded: {why}");
    assert!(output.stdout.is_empty(), "{why}: stdout not empty");
    assert!(stderr.contains(why), "expected {why:?} in: {stderr}");
    assert_eq!(entries(dir), before, "{why}: the directory changed");
}

#[test]
fn writes_the_pair_with_its_modes() {
    let dir = tree("ok");
    let key = dir.join("hk");
    assert_written(&keygen(&["keygen", key.to_str().unwrap()]), &key);
}

#[test]
fn a_bare_file_name_is_written_in_the_working_directory() {
    let dir = tree("bare");
    let output = Command::new(BIN)
        .args(["keygen", "hk"])
        .current_dir(&dir)
        .output()
        .expect("run quantumssh");
    assert_written(&output, &dir.join("hk"));
}

/// RFC-0018 §3: a umask of 077 still gives the public file 0644.
#[test]
fn a_hardened_umask_still_gives_a_readable_public_file() {
    let dir = tree("umask");
    let key = dir.join("hk");
    let output = Command::new("sh")
        .args(["-c", r#"umask 077 && exec "$0" keygen "$1""#, BIN])
        .arg(&key)
        .output()
        .expect("run sh");
    assert_written(&output, &key);
}

#[test]
fn an_existing_key_is_never_replaced() {
    let dir = tree("exists");
    let key = dir.join("hk");
    std::fs::write(&key, "operator's file").unwrap();
    let before = entries(&dir);
    let output = keygen(&["keygen", key.to_str().unwrap()]);
    assert_refused(&output, &dir, &before, "already exists");
    assert_eq!(std::fs::read_to_string(&key).unwrap(), "operator's file");
}

/// Only the `.pub` exists: the private file this run created is removed,
/// and the operator's `.pub` is left as it was.
#[test]
fn an_existing_public_file_is_never_replaced() {
    let dir = tree("pub-exists");
    let key = dir.join("hk");
    std::fs::write(pub_path(&key), "operator's file").unwrap();
    let before = entries(&dir);
    let output = keygen(&["keygen", key.to_str().unwrap()]);
    assert_refused(&output, &dir, &before, "hk.pub: already exists");
    assert_eq!(
        std::fs::read_to_string(pub_path(&key)).unwrap(),
        "operator's file"
    );
}

#[test]
fn a_symlink_leaf_is_never_followed() {
    let dir = tree("symlink-leaf");
    let key = dir.join("hk");
    std::os::unix::fs::symlink(dir.join("elsewhere"), &key).unwrap();
    let before = entries(&dir);
    let output = keygen(&["keygen", key.to_str().unwrap()]);
    assert_refused(&output, &dir, &before, "already exists");
    assert!(!dir.join("elsewhere").exists());
}

/// RFC-0018 §3: the parent is checked after it is canonicalized, so a
/// symlink to a `0777` directory is refused.
#[test]
fn a_symlinked_parent_to_a_world_writable_directory_is_refused() {
    let dir = tree("symlink-parent");
    let open = dir.join("open");
    std::fs::create_dir(&open).unwrap();
    chmod(&open, 0o777);
    std::os::unix::fs::symlink(&open, dir.join("link")).unwrap();
    let output = keygen(&["keygen", dir.join("link/hk").to_str().unwrap()]);
    assert_refused(&output, &open, &[], "group/world-writable");
}

#[test]
fn a_group_writable_ancestor_is_refused() {
    let dir = tree("ancestor");
    let shared = dir.join("shared");
    let inner = shared.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    chmod(&shared, 0o770);
    chmod(&inner, 0o700);
    let output = keygen(&["keygen", inner.join("hk").to_str().unwrap()]);
    assert_refused(&output, &inner, &[], "group/world-writable");
}

/// ADR-0058 §1: every shape but `keygen <PATH>` is a usage error, and
/// `keygen` is never combined with server flags.
#[test]
fn every_other_shape_is_a_usage_error() {
    for args in [
        &["keygen"][..],
        &["keygen", "a", "b"],
        &["keygen", "-f"],
        &["keygen", "--help"],
        &["keygen", "--listen", "127.0.0.1:2222"],
    ] {
        let output = keygen(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{args:?} succeeded");
        assert!(
            stderr.contains("error: usage: quantumssh keygen <PATH>"),
            "{args:?}: {stderr}"
        );
    }
    let output = keygen(&["--listen", "127.0.0.1:2222", "keygen", "hk"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown argument 'keygen'"));
}

#[test]
fn help_lists_the_subcommand() {
    let output = keygen(&["--help"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(
        "SUBCOMMANDS:\n    keygen <PATH>                 Write a new ssh-mldsa44-ed25519 host key (RFC-0018)"
    ));
}
