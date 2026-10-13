# Deploying QuantumSSH under systemd

This guide installs QuantumSSH as a systemd service with the reference
unit [`contrib/systemd/quantumssh.service`](../contrib/systemd/quantumssh.service).
[ADR-0043](adr/0043-systemd-notify-service-and-reference-unit.md) records
why the unit looks the way it does. CI runs these same steps under a
real systemd ([`tests/systemd/`](../tests/systemd/)).

QuantumSSH is **pre-alpha**. Read the next section before you expose it
to anyone.

## What a Phase-2 deployment is

QuantumSSH runs as one dedicated, unprivileged account
([ADR-0016](adr/0016-phase-1-service-account-uid-model.md)), and every
session runs as that account. Until Phase 3 there is no per-user
identity (threat model §8.12). Concretely:

- Every key in `authorized_keys` carries the account's full
  authority. The supported posture is one operator, one set of keys,
  one account.
- Every session can read what the account can read, including the
  host private key, which the account must own (step 3).
- Sessions and SFTP start in the account's home directory and can
  reach any path the account can reach.

## 1. Install the binary

Build the release binary and install it where the unit expects it:

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
| `/etc/quantumssh/ssh_host_ed25519_key` | `quantumssh:quantumssh` | `0600` | The account must read it, so a root-owned `0600` key would not work. |
| `/etc/quantumssh/authorized_keys` | `root:root` | `0644` | The account cannot change who may log in. |

```sh
sudo install -d -m 0755 /etc/quantumssh
sudo ssh-keygen -t ed25519 -N "" -f /etc/quantumssh/ssh_host_ed25519_key
sudo chown quantumssh:quantumssh /etc/quantumssh/ssh_host_ed25519_key
sudo install -m 0644 your_key.pub /etc/quantumssh/authorized_keys
```

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
host_key = "/etc/quantumssh/ssh_host_ed25519_key"

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
  half-open, 10 per source).

ADR-0028 and ADR-0029 define them. The log format follows the stream:
under systemd it is JSON.

## 5. Install and start the unit

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
- The client must be OpenSSH 9.9 or newer, because the server offers
  only `mlkem768x25519-sha256`.

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

Audit events (`target` `audit`) cannot be silenced by `RUST_LOG`
([ADR-0024](adr/0024-phase-1-log-event-schema.md)). Every line lands
at the journal's default priority, so filter on the JSON `level` field
rather than with `journalctl -p`. Ship the records to a sink the host
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
| `ProtectSystem=strict` | The whole file system is read-only except `ReadWritePaths=`. SFTP uploads and writes elsewhere fail. |
| `ProtectHome=yes` | `/home`, `/root` and `/run/user` disappear. That includes the account's home if it lives there; the default `/var/lib/quantumssh` is not affected. |
| `PrivateTmp=yes` | Sessions share a private `/tmp`, separate from the host's. |
| `PrivateDevices=yes` | Only pseudo devices remain in `/dev`. PTYs still work. |
| `RestrictAddressFamilies=` | Sessions lose the address families it omits, network access included. |
| `SystemCallFilter=` | Every program a session runs is held to the allowed system calls. |
| `MemoryDenyWriteExecute=yes` | JIT runtimes (Java, Node.js and others) fail in sessions. |

Per-session confinement and per-user identity are Phase-3 work
([#43](https://github.com/gonzafg2/quantumssh/issues/43)).
