# Deploying QuantumSSH under systemd

This guide installs QuantumSSH as a systemd service with the reference
unit [`contrib/systemd/quantumssh.service`](../contrib/systemd/quantumssh.service).
[ADR-0043](adr/0043-systemd-notify-service-and-reference-unit.md) records
why the unit looks the way it does. CI runs these same steps under a
real systemd ([`tests/systemd/`](../tests/systemd/)). Clients need
OpenSSH 10.6 or newer (§10). Windows runs the server through WSL2 (§11),
and Homebrew offers a single-user evaluation path (§12). On Linux,
account mode runs each session as its own account instead (§4,
"Account mode").

QuantumSSH is **alpha**. Read the next section before you expose it
to anyone.

## What a Phase-2 deployment is

By default QuantumSSH runs as one dedicated, unprivileged account
([ADR-0016](adr/0016-phase-1-service-account-uid-model.md)), and every
session runs as that account. That is service-account mode. Account
mode, on Linux, runs each session as its own account instead (§4,
"Account mode"). In service-account mode:

- Every key in `authorized_keys` carries the account's full
  authority. The supported posture is one operator, one set of keys,
  one account.
- Every session can read what the account can read, including the
  host private key, which the account must own (step 3).
- Sessions start in the account's home directory and can reach any
  path the account can reach.

## 1. Install the binary

From `0.2.0` on, each release publishes a static binary for Linux on
`x86_64` and `aarch64` ([RFC-0017](rfcs/0017-alpha-distribution.md)).
Download one and verify it before you install it, or build from source.

### From a release

Download the tarball for your machine, `x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl`, with the release's checksums and their
signature:

```sh
V=0.2.0
T=x86_64-unknown-linux-musl
base="https://github.com/gonzafg2/quantumssh/releases/download/v$V"
curl -fsSLO "$base/quantumssh-$V-$T.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
curl -fsSLO "$base/SHA256SUMS.asc"
```

Then verify it, in this order
([ADR-0054](adr/0054-release-artifact-integrity.md) §6):

1. **The signature on `SHA256SUMS`.** Run `scripts/verify-download.sh`
   from a checkout of this repository's `main`. It imports every key of
   the pin set [`keys/release-keys.txt`](../keys/release-keys.txt) into
   a throwaway GnuPG home. It accepts only a signature by the current
   release key, or by a retired key inside its window, and a revoked
   key always fails. A bare `gpg --verify` is not enough: it reports
   "Good signature" for a revoked or expired key.

   ```sh
   git clone --depth 1 https://github.com/gonzafg2/quantumssh.git
   quantumssh/scripts/verify-download.sh "v$V" .
   ```

   Check the current release-key fingerprint it prints against
   [`SECURITY.md`](../SECURITY.md). The current-key path needs only
   `gpg`. A release signed by a retired key also needs `gh` and `jq`,
   because the script reads GitHub's immutable-release record.
2. **The tarball against `SHA256SUMS`:**

   ```sh
   sha256sum --ignore-missing -c SHA256SUMS
   ```

3. **Its provenance (recommended).** The attestation binds the tarball
   to the release workflow, the commit and the tag:

   ```sh
   gh attestation verify "quantumssh-$V-$T.tar.gz" -R gonzafg2/quantumssh \
     --signer-workflow gonzafg2/quantumssh/.github/workflows/release.yml \
     --source-ref "refs/tags/v$V" --deny-self-hosted-runners
   ```

Steps 1 and 2 are the minimum. A user who checks only the attestation
gets no check of the maintainer's signature. Then install the binary where the
unit expects it:

```sh
tar -xzf "quantumssh-$V-$T.tar.gz"
sudo install -m 0755 "quantumssh-$V-$T/quantumssh" /usr/local/bin/quantumssh
```

The tarball also holds the reference unit
(`contrib/systemd/quantumssh.service`, step 5) and `config.toml`, the
configuration of step 4.

### From source

```sh
cargo build --release
sudo install -m 0755 target/release/quantumssh /usr/local/bin/quantumssh
```

## 2. Create the service account

```sh
sudo useradd --system --create-home --home-dir /var/lib/quantumssh \
    --shell /usr/sbin/nologin quantumssh
sudo chmod 0700 /var/lib/quantumssh
```

Give the account no `sudoers` entry. The unit's `NoNewPrivileges=yes`
blocks setuid programs (`sudo`, `su`) in every session anyway. Sessions
run their commands through `/bin/sh`, so the `nologin` shell does not
get in their way.

## 3. Lay out `/etc/quantumssh`

The server refuses to start when a trusted file is writable by anyone
but its owner, or when any directory above it is
([ADR-0029](adr/0029-phase-2-config-file-v1-schema-parser-strictmodes.md),
StrictModes). The host key is also a secret: it must not be readable by
group or others, and its owner must be root or the account.

| Path | Owner | Mode | Why |
|---|---|---|---|
| `/etc/quantumssh/` | `root:root` | `0755` | Not group- or world-writable. |
| `/etc/quantumssh/config.toml` | `root:root` | `0644` | The account cannot change its own configuration. |
| `/etc/quantumssh/ssh_host_mldsa44_ed25519_key` | `quantumssh:quantumssh` | `0600` | The account must read it, so a root-owned `0600` key would not work. |
| `/etc/quantumssh/authorized_keys` | `root:root` | `0644` | The account cannot change who may log in. |
| `/etc/quantumssh/trusted_user_ca_keys` (optional, §4) | `root:root` | `0644` | The account cannot change which CAs it trusts. |

```sh
sudo install -d -m 0755 /etc/quantumssh
sudo quantumssh keygen /etc/quantumssh/ssh_host_mldsa44_ed25519_key
sudo chown quantumssh:quantumssh /etc/quantumssh/ssh_host_mldsa44_ed25519_key
sudo install -m 0644 your_key.pub /etc/quantumssh/authorized_keys
```

The host key is the composite `ssh-mldsa44-ed25519`, the only type the
server accepts ([ADR-0047](adr/0047-host-key-algorithm-ssh-mldsa44-ed25519.md)).
`quantumssh keygen` ([RFC-0018](rfcs/0018-host-key-generation.md)) does
the following:

- It writes the key with mode `0600` and its `.pub` with `0644`.
- It prints both paths and the key's fingerprint, the one `server.started`
  logs. Publish the fingerprint out of band, so clients can check it on
  their first connection.
- `ssh-keyscan` cannot fetch the key. It does not negotiate strict-kex,
  which the server requires, so the server disconnects it with code 3
  (`no-strict-kex`) before it sends a host key. To trust the key before a
  first connection, add the `.pub` line to the client's `known_hosts`
  with the host in front: `[<host>]:<port> ssh-mldsa44-ed25519 AAAA…`, or
  `<host> ssh-mldsa44-ed25519 AAAA…` on port 22.
- It never replaces a file, the key or its `.pub`. To rotate the key,
  move both aside, run `keygen` and the `chown` above again, publish the
  new fingerprint and restart. Each client then removes the old entry
  with `ssh-keygen -R`, as in step 5, and checks the new fingerprint on
  its next connection; otherwise OpenSSH refuses the host with "REMOTE
  HOST IDENTIFICATION HAS CHANGED". Once clients have the new
  fingerprint, destroy the old private key.
- It refuses a directory the server would refuse to read the key from
  (the StrictModes rule above).

`ssh-keygen -t mldsa44-ed25519 -N "" -f <path>` from OpenSSH 10.6 or
later writes the same format and remains an alternative; §10 lists
where each platform gets 10.6. Either way,
generate a new key: do not reuse the Ed25519 half of an existing key
([RFC-0012](rfcs/0012-composite-host-key-cutover.md)). A host key of any
other type, `ssh-ed25519` included, stops the server at startup with
`invalid_host_key`.

`authorized_keys` takes plain `ssh-ed25519` lines. A line with options
(`from=`, `command=`, `restrict` and the like) stops the server from
starting until those options are enforced
([ADR-0040](adr/0040-refuse-authorized-keys-options-until-enforced.md)).

## 4. Write the configuration

```toml
# /etc/quantumssh/config.toml
schema_version = 1

[server]
listen   = "0.0.0.0:2222"
host_key = "/etc/quantumssh/ssh_host_mldsa44_ed25519_key"

[auth]
authorized_keys = "/etc/quantumssh/authorized_keys"
```

```sh
sudo chmod 0644 /etc/quantumssh/config.toml
```

These optional keys exist:

- `[server] handshake_timeout`, the pre-authentication budget in
  seconds (default 30);
- `[server] drain_timeout`, the graceful-shutdown deadline in seconds
  (default 30);
- the `[limits]` admission caps (defaults 256 connections, 100
  half-open, 10 per source);
- `[auth] trusted_user_ca_keys`, the CAs whose user certificates log in
  (below).

ADR-0028 and ADR-0029 define the first three. The log format follows
the stream: under systemd it is JSON.

### User certificates

Instead of listing every key in `authorized_keys`, you can trust a
certificate authority (CA) and give users short-lived certificates
([ADR-0050](adr/0050-accept-openssh-user-certificates.md)). Put the
CA's public key in `trusted_user_ca_keys`, one `ssh-mldsa44-ed25519`
line per CA, with no options, and name the file in `[auth]`:

```sh
ssh-keygen -t mldsa44-ed25519 -f user_ca      # keep user_ca offline
sudo install -m 0644 user_ca.pub /etc/quantumssh/trusted_user_ca_keys
```

```toml
[auth]
authorized_keys      = "/etc/quantumssh/authorized_keys"
trusted_user_ca_keys = "/etc/quantumssh/trusted_user_ca_keys"
```

Sign a user's Ed25519 key with a principal and a validity window:

```sh
ssh-keygen -s user_ca -I alice@laptop -n alice -V +8h alice_key.pub
```

- **Always pass `-V`.** Without it the certificate never expires, and
  expiry is the only revocation: the server keeps no revocation list.
- **The principal is the login name.** `ssh alice@host` needs `alice`
  in `-n`. In service-account mode every session still runs as the
  service account, so the principal does not limit access: every
  certificate the CA issued, for any principal, gets in. Use a CA
  dedicated to this server. In account mode the principal selects the
  account (below).
- **No critical options.** A certificate signed with `-O force-command`,
  `-O source-address` or `-O verify-required` is refused, because the
  server does not enforce them yet.
- **PTY.** A certificate gets a PTY only with the `permit-pty`
  extension, which `ssh-keygen -s` includes unless you pass `-O no-pty`.
- **CA algorithm.** The CA key is `ssh-mldsa44-ed25519` only, which
  OpenSSH 10.6 or later can generate and sign with. An `ssh-ed25519`
  line stops the server with `invalid_trusted_user_ca_keys`
  (ADR-0050 §4). The users' own keys stay Ed25519.

A refused certificate fails like an unknown key. The server records the
reason (for example `expired` or `principal_mismatch`) in a
`certificate refused` diagnostic line.

A version-1 file keeps its meaning on every later release that reads
version 1: later releases only add keys and accepted forms, which an
older binary refuses by name, and a change that would break a version-1
file ships as `schema_version = 2`
([RFC-0016](rfcs/0016-config-schema-v1.md)).

### Account mode

On Linux, account mode runs each session as the account that the
client's user name selects, from a list you write
([RFC-0019](rfcs/0019-identity-model-ssh-user-name-to-os-account.md),
[RFC-0020](rfcs/0020-privilege-separation-root-launcher-and-session-helper.md)).
Use it when each person should log in to their own account.
Service-account mode, above, stays the single-user path, and the only
one on macOS.

**How it runs.** systemd starts the binary as root. That process, the
launcher, never reads the network. It starts the network server as
`quantumssh`, with no groups, no capabilities and `no_new_privs`
([ADR-0066](adr/0066-account-mode-start-readiness-and-stop.md)). It
starts each session as its account, with the account's groups, home
and login shell
([ADR-0065](adr/0065-session-helper-identity-change-checks-and-environment.md)).

**Set it up:**

1. **Keep the service account** `quantumssh` of step 2. The network
   server still runs as it, so it must exist and must not be listed.
2. **Create the accounts,** if they do not exist yet.
3. **Install each account's key file,** owned by root:

   ```sh
   sudo install -d -m 0755 -o root -g root /etc/quantumssh/keys
   sudo install -m 0644 -o root -g root alice.pub /etc/quantumssh/keys/alice
   ```

4. **List the accounts** in `config.toml`, in place of
   `[auth] authorized_keys`, which account mode refuses
   ([ADR-0070](adr/0070-account-sections-grammar-and-startup-errors.md)):

   ```toml
   [auth]
   trusted_user_ca_keys = "/etc/quantumssh/trusted_user_ca_keys"

   [[account]]
   name            = "alice"
   authorized_keys = "/etc/quantumssh/keys/alice"

   [[account]]
   name = "deploy"    # no key file: only a certificate for "deploy" logs in
   ```

   - A key logs in only to the accounts whose key files list it.
   - A certificate logs in only to the listed account its principals
     name.
   - Any other name fails as a wrong key does: `root`, an unlisted
     account, or a name with no account.
   - An entry with no key file needs `[auth] trusted_user_ca_keys`.

5. **Install the account-mode unit** at step 5, in place of the
   reference unit's command, under the same name:

   ```sh
   sudo install -m 0644 contrib/systemd/quantumssh-account-mode.service \
       /etc/systemd/system/quantumssh.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now quantumssh
   ```

   On a host that already runs in service-account mode, use
   `sudo systemctl restart quantumssh` in place of the last command.

   The unit
   ([ADR-0067](adr/0067-account-mode-systemd-unit.md)) differs from
   the reference unit in three ways:
   - **No `User=`,** because the launcher must start as root.
   - **No `NoNewPrivileges=`,** which would reach every session and
     stop `sudo` there.
   - **`--require-account-mode`.**

   Each wrong combination fails the start, and `journalctl -u
   quantumssh` names the reason:
   - an account-mode configuration under the reference unit gives
     `account mode must start as root`;
   - a configuration without accounts under this unit gives
     `--require-account-mode: the configuration lists no account`.

   The launcher binds the port as root, so port 22 needs none of §6.

**File ownership** follows RFC-0019 §8, which is stricter than step 3:

- **Root-owned, with nothing writable above them.** This covers the
  configuration, the CA file and every key file. Each must be owned by
  root and not writable by group or others. Every directory above it
  must be root-owned and not writable by group or others, and no symlink
  is allowed anywhere. The launcher checks the same of `/etc/passwd`,
  `/etc/group` and its own binary. A file that fails stops the start,
  with `insecure_permissions` or `file_unavailable`.
- **The host key** stays owned by `quantumssh` with mode `0600`,
  because the network server reads it.

**When a change takes effect:**

| Change | Takes effect |
|---|---|
| Remove an account from `[[account]]` | at the next restart |
| Remove a key from an account's key file | at the next restart, because key files load at startup |
| `userdel` the account, or give it UID 0 | at its next connection, which fails as a wrong key does |
| Remove the account from a group | at its next session |
| `passwd -l`, or an expiry date | never: account mode does not read `/etc/shadow`. Remove the account from `[[account]]` and restart, or remove it from `/etc/passwd`. Emptying its key file is not enough when `trusted_user_ca_keys` is set, because a certificate whose principals include the name still logs in |

**What a listed account exposes.** The network server parses every
byte a client sends, and it can start a session as any listed account.
Every way a listed account has to become root is therefore within
reach of a compromised server: `sudo`, the `docker` group and the
like. List only accounts whose whole privilege, those paths included,
you accept exposing that way (RFC-0020 §8).

To keep every session from gaining privilege, add
`NoNewPrivileges=yes` with `sudo systemctl edit quantumssh`. The cost
is `sudo` in every session.

**One kernel session keyring for the whole unit.** Every session of
every listed account, and the network server, share one session
keyring. A key that one of them links into it is within reach of the
others (ADR-0065 §4). Do not keep keys in the session keyring until
[#299](https://github.com/gonzafg2/quantumssh/issues/299) closes this.

**Logs.** `server.started` carries `"identity_mode":"account"`.
`exec.started` and `exec.finished` carry the account's name in
`account`, and its UID in `executing_uid` (§7).

## 5. Install and start the unit

From the checkout, or from the extracted tarball of step 1. In account
mode, run the account-mode unit's commands instead (§4, "Account mode",
step 5): installing the reference unit over it would make the next
start fail with `account mode must start as root`. The notes below hold
for both units.

```sh
sudo install -m 0644 contrib/systemd/quantumssh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now quantumssh
```

- `systemctl start` returns once the server listens. A configuration,
  permission, key or bind error fails the start, and
  `journalctl -u quantumssh` shows it as `server.config_error`.
- The `server.started` record names the host-key fingerprint, so you
  can check it before the first connection.
- The client must be OpenSSH 10.6 or newer (§10), because the server
  offers only `mlkem768x25519-sha256` (9.9 or newer) and only the
  `ssh-mldsa44-ed25519` host key (10.6 or newer). An older client fails
  with "no matching host key type found. Their offer:
  ssh-mldsa44-ed25519".
- A client that trusted an Ed25519 key for this host before the switch
  to the composite key must forget it and learn the new fingerprint out
  of band: `ssh-keygen -R <host>` on port 22, and
  `ssh-keygen -R '[<host>]:2222'` for another port, because
  `known_hosts` stores the port with the host. Keeping the old entry trusted keeps
  the classical path open for anyone who can forge Ed25519
  (RFC-0012 §Why exactly one algorithm).

## 6. Serving on port 22

The unit runs unprivileged and grants no capability, so it cannot bind
a port below 1024. You have two options.

**Redirect port 22 with the firewall (recommended).** Keep
`listen = "0.0.0.0:2222"` and redirect incoming connections. The
client's source address is preserved, which the per-source limits rely
on.

```
# /etc/nftables.conf (excerpt)
table inet quantumssh {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 22 redirect to :2222
    }
}
```

The redirect applies to connections from other hosts. Port 2222 stays
reachable directly unless you filter it.

**Grant the capability (with a cost).** A drop-in
(`sudo systemctl edit quantumssh`) with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, and `listen = "0.0.0.0:22"`,
lets the server bind port 22. The ambient capability set survives
`execve`, so **every session inherits it**: any authorized key could
then bind any privileged port on the host.

Either way, move an existing OpenSSH server off port 22 first.

## 7. Logs

The server writes one JSON object per line to stderr, and systemd
stores it in the journal:

```sh
journalctl -u quantumssh -o cat | jq .
```

Each line is one record of the audit-log schema, version 1
([RFC-0014](rfcs/0014-audit-log-schema-v1.md)). A catalogue record names
its `event`, such as `auth.succeeded` or `exec.finished`, and carries
`schema_version`, `timestamp`, `level` and, inside a connection,
`peer_addr`. A diagnostic carries `message` instead and is not part of
the contract. To keep only the contract:

```sh
journalctl -u quantumssh -o cat | jq -c 'select(has("event"))'
```

`RUST_LOG` governs diagnostics only: no directive removes a catalogue
event. Every line lands at the journal's default priority, so filter
on the JSON `level` field rather than with `journalctl -p`. Ship the records to a sink the host
cannot rewrite (threat model §5.5.1).

## 8. Stop, restart and reload

- **`systemctl stop`.** systemd sends SIGTERM to the server alone.
  The server stops accepting connections, and running sessions continue
  until `drain_timeout`, then end. When the server exits, systemd sends
  SIGKILL to whatever sessions left behind, such as `nohup` jobs and
  `setsid` processes. The server extends systemd's stop timeout to
  cover the drain, so a long `drain_timeout` needs no
  `TimeoutStopSec=`.
- **Skipping the rest of a drain.** Signal the server a second time:
  `sudo systemctl kill --kill-whom=main quantumssh`. Without
  `--kill-whom=main`, `systemctl kill` signals every session as well.
- **`systemctl restart`** is a stop then a start, so every session
  ends. One process serves every connection, and there is no
  hand-over to the new one.
- **`systemctl reload`** is refused. The configuration is read once at
  startup, so restart to apply a change
  ([RFC-0010](rfcs/0010-configuration-file.md)).

## 9. Further hardening, and what it does to sessions

Sessions are processes of the same unit, so every sandboxing directive
confines them along with the server. The reference unit therefore sets
only `NoNewPrivileges=yes`. You can add more with
`sudo systemctl edit quantumssh` (threat model §8.8), knowing the
effect:

| Directive | Effect on sessions |
|---|---|
| `ProtectSystem=strict` | The whole file system is read-only except `ReadWritePaths=`. Every write elsewhere fails, in the account's home too unless it is listed. |
| `ProtectHome=yes` | `/home`, `/root` and `/run/user` disappear. That includes the account's home if it lives there; the default `/var/lib/quantumssh` is not affected. |
| `PrivateTmp=yes` | Sessions share a private `/tmp`, separate from the host's. |
| `PrivateDevices=yes` | Only pseudo devices remain in `/dev`. PTYs still work. |
| `RestrictAddressFamilies=` | Sessions lose the address families it omits, network access included. |
| `SystemCallFilter=` | Every program a session runs is held to the allowed system calls. |
| `MemoryDenyWriteExecute=yes` | JIT runtimes (Java, Node.js and others) fail in sessions. |

Per-user identity is account mode (§4, "Account mode"). It confines
no session beyond its account.

## 10. Clients: OpenSSH 10.6 or newer

Every client must be OpenSSH 10.6 or newer, on every platform, and there
is no fallback ([RFC-0017](rfcs/0017-alpha-distribution.md)). An older
client fails with "no matching host key type found. Their offer:
ssh-mldsa44-ed25519". Where 10.6 comes from, as of November 2026:

| Platform | How to get OpenSSH 10.6 or newer |
|---|---|
| Arch, Alpine edge, Debian forky or sid, Fedora rawhide, openSUSE Tumbleweed, Void, NixOS 26.05 | The distribution package |
| Ubuntu (every release), Debian 13, Fedora 44 | Homebrew on Linux (`brew install openssh`), Homebrew's Tier 1 at glibc 2.39 or newer. On Ubuntu 22.04 (glibc 2.35), Homebrew installs its own glibc and supports it only at its Tier 2 |
| RHEL 9 and its rebuilds (glibc 2.34), openSUSE Leap | No supported route. Homebrew's Tier 2 is best effort only. `quantumssh keygen` creates the host key without OpenSSH (step 3) |
| macOS (arm64) | Homebrew's `openssh`, run by full path after `brew unlink openssh`, so the system `ssh` stays in place: `"$(brew --prefix openssh)/bin/ssh"` |
| Windows | A client inside WSL2 (§11). No native Windows build of 10.6 is known to work |

On macOS, the system `ssh` is 10.5p1 and does not connect. If
`~/.ssh/config` sets `UseKeychain`, an option only Apple's `ssh` knows,
Homebrew's `ssh` refuses the whole file ("Bad configuration option:
usekeychain"). Put `IgnoreUnknown UseKeychain` on its first line, before
any `Host`: the option applies only to the lines after it. Homebrew's
`ssh` does not read passphrases from the Keychain either;
`/usr/bin/ssh-add --apple-load-keychain` loads them into the agent.

## 11. Windows through WSL2

QuantumSSH does not run natively on Windows. On Windows 10 or 11, run it
in a WSL2 distribution with the Linux binary for the machine's
architecture. Nothing here is tested in CI.

1. Install a distribution. Arch Linux is the recommended one, because
   it ships OpenSSH 10.6 for the client (§10):

   ```powershell
   wsl --install archlinux
   ```

2. Turn on systemd if the distribution does not, in its
   `/etc/wsl.conf`, then restart it with `wsl --shutdown`:

   ```ini
   [boot]
   systemd=true
   ```

3. Inside the distribution, follow steps 1 to 5 of this guide.

**Reaching the server.** In WSL's default NAT mode, Windows itself
reaches the server on `localhost`, but other machines on the LAN do not.
To reach it from the LAN, use mirrored networking: on Windows 11 22H2 or
newer, set `networkingMode=mirrored` under `[wsl2]` in
`%UserProfile%\.wslconfig`. Then allow the port through the Hyper-V
firewall, in an administrator PowerShell:

```powershell
New-NetFirewallHyperVRule -Name "QuantumSSH" -DisplayName "QuantumSSH" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 2222
```

**A systemd service does not keep WSL running.** The server stops with
the WSL instance, so a WSL2 deployment serves only while the instance is
running.

## 12. Homebrew: a single-user evaluation path

From `0.2.0` on, the tap `gonzafg2/homebrew-quantumssh` installs the
release binary on macOS arm64 and on Linux `x86_64` and `aarch64`
([ADR-0056](adr/0056-homebrew-tap.md)). Its CI checks each `sha256` in
the formula against the signed `SHA256SUMS` before it installs anything.

```sh
brew install gonzafg2/quantumssh/quantumssh openssh
brew unlink openssh
chmod g-w "$(brew --prefix)/etc"
E="$(brew --prefix)/etc/quantumssh"
quantumssh keygen "$E/ssh_host_mldsa44_ed25519_key"
install -m 0644 ~/.ssh/id_ed25519.pub "$E/authorized_keys"
brew services start quantumssh
"$(brew --prefix openssh)/bin/ssh" -p 2222 "$USER@127.0.0.1"
```

- Installing by the full name trusts that formula (Homebrew's tap
  trust).
- The formula writes `$(brew --prefix)/etc/quantumssh/config.toml` once,
  and an upgrade keeps your edits. Its paths point inside that
  directory, and its `listen` is `127.0.0.1:2222`.
- The `chmod`: Homebrew's installer leaves its `etc` group-writable on
  macOS for an account in the `admin` group, and the server refuses its
  configuration and keys below a group-writable directory (step 3).
- `brew install` trusts the formula's `sha256`, not the PGP signature.
  For the full chain, verify the tarball as in step 1.

**This is not the deployment the rest of this guide describes.**
`brew services` runs the server as the user who started it, on macOS
usually an administrator account. That account owns the configuration
under `$(brew --prefix)/etc/quantumssh/`, `authorized_keys` included,
so the server's own account can rewrite its trust anchors, and every
session carries that user's full authority. Steps 2 and 3 instead run it
as a dedicated account that cannot change its configuration or who may
log in ([ADR-0016](adr/0016-phase-1-service-account-uid-model.md)). The
supported server posture stays the Linux deployment.
