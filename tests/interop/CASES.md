# The OpenSSH conformance suite: catalogue of cases

This is the catalogue of [ADR-0062](../../docs/adr/0062-conformance-suite-driven-by-the-stock-openssh-client.md).
`run_openssh_client.sh` reads the table below and enforces it:

- A case with no line, or a line with no case, fails the run before any
  case starts.
- Cases run in the order of the table.
- The run fails unless every line reports `ok`, or a skip that both its
  line and the leg allow.

Each case is the function `case_<name>` in [`cases.sh`](cases.sh). It
drives the stock OpenSSH client against the server and asserts one
behaviour that a document of this project states.

## Adding or changing a case

- A PR that adds or changes a behaviour a stock client can reach adds or
  updates its case and its line here, in the same PR.
- The "Checks" cell names the document first. When no document states the
  behaviour, the document gets its sentence in the same PR.
- A refusal case asserts the refusal: the client's message, or the
  server's disconnect code and reason.
- "May skip" is `never`, or the one thing a client may lack. A leg skips a
  case only when the workflow that runs it also names the case in
  `INTEROP_ALLOW_SKIP`. Today only the macOS release leg does. Its client
  is built without OpenSSL and without zlib (ADR-0055 §3), and account
  mode does not exist on macOS (ADR-0068 §1). It skips those four cases
  and every account case.
- An account case runs only on Linux, as root, with
  `INTEROP_ACCOUNT_MODE=1`: it creates accounts and writes under `/etc`
  (ADR-0068). `openssh-interop` sets the variable in its container. To run
  the suite locally with them, run it in the gate image.

## Cases

| Case | Checks | May skip |
|---|---|---|
| openssh_smoke | ADR-0020: `ssh … echo hello` prints `hello` and exits 0 | never |
| openssh_verbose_kex | ADR-0020: the negotiated key exchange is `mlkem768x25519-sha256` | never |
| openssh_hostkey_composite | ADR-0047: the negotiated host key algorithm is `ssh-mldsa44-ed25519` | never |
| openssh_aes_gcm | ADR-0055 §5: a session runs on `aes256-gcm@openssh.com`, the second cipher | a client without AES-GCM |
| server_offer | ADR-0021, ADR-0047: the server's KEXINIT lists are exactly the profile | never |
| negative_no_hybrid | ADR-0020: a classical-only key exchange finds no match, and nothing falls back | never |
| negative_sntrup761 | ADR-0021: another post-quantum hybrid finds no match either | never |
| negative_ed25519_hostkey | ADR-0047: a client limited to `ssh-ed25519` host keys finds no match | never |
| legacy_cipher_refused | ADR-0021: a client limited to `aes256-ctr` finds no match | never |
| compression_none | ADR-0021: a client that asks for compression negotiates `none` | a client without zlib |
| keyscan_refused | `docs/deployment.md` §3: `ssh-keyscan` negotiates no strict-kex and is disconnected with code 3 | never |
| known_hosts_from_pub | `docs/deployment.md` §3: a `known_hosts` line made from the `.pub` file lets strict checking connect, and another key is refused | never |
| openssh_rekey | ADR-0026: the server answers re-keys that the client starts, and the stream survives | never |
| rekey_server_initiated | ADR-0026, RFC-0014: the server starts a re-key after 1 GiB, logged as `initiator: server` | a client without AES-GCM |
| password_auth_not_offered | Threat model §5.3.1, RFC-0011: only `publickey` is offered | never |
| unauthorized_key_refused | Threat model §6.3: a key that `authorized_keys` does not list is refused | never |
| legacy_user_keys_refused | ADR-0050: `ssh-ed25519` is the only user signature algorithm, so RSA and ECDSA keys get nowhere | a client without RSA or ECDSA |
| auth_attempt_budget | Threat model §5.3.1: the twelfth request that does not authenticate ends the connection with code 11 | never |
| openssh_cert | ADR-0050 §8, ADR-0051: a user certificate from the trusted CA authenticates, and is logged | never |
| openssh_cert_refusals | ADR-0050 §8: another principal, an expired certificate and an untrusted CA are refused | never |
| exit_status_propagation | ADR-0023: `exit 3` reports 3 | never |
| exit_signal | ADR-0038 §8: a command killed by a signal reports `exit-signal` | never |
| stdin_round_trip | ADR-0023: 4 MiB sent to the command's stdin come back identical | never |
| stderr_separate | ADR-0023: the command's stderr arrives apart from its stdout | never |
| shell_without_pty | ADR-0038 §1: `shell` with no PTY runs the commands sent on stdin | never |
| openssh_pty | ADR-0038: `ssh -tt` runs the command on a PTY, its controlling terminal | never |
| shell_on_pty | ADR-0038 §1: `shell` on a PTY is an interactive shell with a terminal | never |
| pty_window_change | ADR-0038 §1: the PTY takes the client's window size, and follows a resize | never |
| env_refused | ADR-0038 §1: `env` is refused, and the session runs without the variable | never |
| agent_forwarding_refused | ADR-0038 §1: agent forwarding is refused, and the session has no agent socket | never |
| unknown_subsystem_refused | ADR-0041 §1: a subsystem other than `sftp` is refused | never |
| direct_tcpip_refused | ADR-0023: a forwarding channel is an unknown channel type | never |
| direct_tcpip_refused_during_session | ADR-0023, erratum of 2026-11-21: with a session open, the one-channel rule answers first | never |
| remote_forwarding_refused | ADR-0023: `tcpip-forward`, a global request, gets a failure | never |
| second_session_refused | ADR-0023: one session channel per connection | never |
| client_keepalive | ADR-0023: the client's keepalive, a global request, gets an answer | never |
| client_gone_reaps_command | ADR-0016, ADR-0038: when the client goes away, the command's process group is killed | never |
| openssh_sftp | ADR-0041: an `sftp` batch of mkdir, put, rename, get, ls, rm and rmdir, byte for byte | never |
| openssh_scp | ADR-0041: `scp` up and down, byte for byte | never |
| sftp_attrs_links_resume | ADR-0041 §4: `chmod`, `ln -s` and a resumed download | never |
| sftp_unsupported_extensions | ADR-0041 §6: `statvfs`, `hardlink` and `copy-data` are not supported | never |
| keygen_read_by_ssh_keygen | RFC-0018 §6, ADR-0058 §4: `ssh-keygen` reads the key that `quantumssh keygen` wrote | never |
| keygen_host_key_serves | RFC-0018 §6, ADR-0058 §4: a server started with that key serves the stock client | never |
| account_session_identity | RFC-0020 §4, §5: `id -u`, `id -g`, `id -G`, `pwd -P`, `HOME`, `USER`, `LOGNAME`, `SHELL` and `PATH` match the account's record, its groups and ADR-0065 §3's `PATH` | where account mode cannot run (ADR-0068 §1) |
| account_login_shell | RFC-0020 §4: `shell` on a PTY runs the account's login shell as a login shell, so `$0` is `-bash` | where account mode cannot run (ADR-0068 §1) |
| account_pty_owner | RFC-0020 §4, ADR-0064 §2: the session's terminal is owned by the account, with mode `0600` | where account mode cannot run (ADR-0068 §1) |
| account_session_privileges | RFC-0020 §8, ADR-0065 §2: in a session, `NoNewPrivs` is 0, and `CapPrm`, `CapEff` and `CapInh` are empty | where account mode cannot run (ADR-0068 §1) |
| account_audit_records | RFC-0019 §6, ADR-0024: `server.started` carries `identity_mode` `account`; `exec.started` and `exec.finished` carry `account`, the key's fingerprint and, apart, the account's UID | where account mode cannot run (ADR-0068 §1) |
| account_exit_status | ADR-0064 §3, ADR-0038 §8: `exit 3` reports 3, and `kill -TERM $$` reports `exit-signal`, through the launcher | where account mode cannot run (ADR-0068 §1) |
| account_client_gone_kills | ADR-0064 §4: when the client goes away, the session's process group is killed | where account mode cannot run (ADR-0068 §1) |
| account_sftp_ownership | RFC-0020's Guide: a file put over SFTP belongs to the account and its primary group | where account mode cannot run (ADR-0068 §1) |
| account_nologin | RFC-0020 §5: for an account whose shell is `nologin`, `exec` fails as `nologin` makes it fail, and an `sftp` batch works | where account mode cannot run (ADR-0068 §1) |
| account_unlisted_refused | RFC-0019 §3: `root`, an unlisted account and a name with no entry each get `Permission denied (publickey).`, as a wrong key does | where account mode cannot run (ADR-0068 §1) |
| account_key_bound_to_account | RFC-0019 §5: one account's key does not log in to another listed account | where account mode cannot run (ADR-0068 §1) |
| account_certificate_principal | RFC-0019 §5: a certificate logs in to the account its principal names, and not to another | where account mode cannot run (ADR-0068 §1) |
| account_own_keyring | ADR-0074 §2, §4: where sessions can use keyrings, a key that one account's session links into `@s` is neither found nor read by another account's session; where `keyctl` is blocked as a whole, sessions run on without one | where account mode cannot run (ADR-0068 §1) |

## What is not here

- **X11 forwarding.** Without `xauth` the client fails before it sends the
  request, and the gate image does not install `xauth`.
- **The one-hour re-key** (ADR-0026). No client option shortens the
  server's timer.
- **Input that no stock client sends.** That is the fuzz targets'
  (ADR-0060) and the in-process tests'.
