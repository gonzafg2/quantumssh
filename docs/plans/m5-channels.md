<!--
  Governance status (2026-06-26):
  This file lives in docs/plans/ — a category whose governance contract
  is not yet defined. See issue #79 for the decision.
  This plan guides M5 (channel layer + exec). It is not authoritative
  post-merge; locked-in decisions are recorded in ADRs 0016, 0020,
  0023, 0024.
-->
# Plan M5 — Channel layer + `exec` (`channel.rs`, `exec.rs`)

## Context

M0-M4 merged en `main`:
- M0-M3: workspace, `wire.rs`, `kex.rs`+`host_key.rs`, `transport.rs`+`cipher.rs`
- M4: `auth.rs` — publickey Ed25519, `authorized_keys`, eventos `auth.*`

El transport termina hoy en `Expect<S, AuthAccepted>::reject_channel_open()`
(`transport.rs:832`): su doc dice *"channels land in M5 (ADR-0023)."*

**M5 implementa** el último tramo del walking skeleton: exactamente un canal
`session` con un `exec`, streaming de salida y cierre limpio — para que `ssh
host 'echo hello'` funcione end-to-end contra un OpenSSH 10.x real. Habilita el
**interop hard gate** de ADR-0020 (`integration::openssh_smoke`), que aún no
está en CI porque no existía un camino de `exec` conectable hasta ahora.

---

## Specs de referencia

| Spec | Rol |
|---|---|
| ADR-0023 | Alcance del channel layer: 1 canal `session`, 1 `exec`, flow control, edge cases (autoritativo) |
| ADR-0024 | Eventos de auditoría `exec.started`/`exec.finished` y sus campos |
| ADR-0022 | `std::process::Command` en `spawn_blocking`; sin `tokio::process` en Phase 1 |
| ADR-0016 | UID de servicio + entorno sanitizado; `executing_uid` vía `rustix::process::getuid()` |
| ADR-0020 | Interop hard gate: OpenSSH 10.0p1 fijo, Debian trixie por digest |
| RFC 4254 §5–6 | Mecanismo de canales, requests `exec`/`exit-status` |

---

## Archivos

| Archivo | Acción | Líneas estimadas |
|---|---|---|
| `crates/quantumssh-core/src/channel.rs` | **NUEVO** | ~350 |
| `crates/quantumssh-core/src/exec.rs` | **NUEVO** | ~250 |
| `crates/quantumssh-core/src/transport.rs` | Modificar | +150 |
| `crates/quantumssh-core/src/server.rs` | Modificar | ~30 |
| `crates/quantumssh-core/src/lib.rs` | Modificar | +2 |
| `Cargo.toml` | Modificar | +1 pin (`rustix`) |
| `crates/quantumssh-core/tests/accept.rs` | Modificar | +300 |
| `.github/workflows/` | NUEVO/Modificar | interop gate job |

---

## 1. `transport.rs` — stage `Session` y lectura cancel-safe

### 1.1 Helper de descifrado compartido
Factorizar la lógica crítica de descifrado (`body_len` con cota de longitud →
`open` → `seq_rx.wrapping_add(1)`) en un helper único. `read_sealed`
(handshake, `read_exact`) y el nuevo `read_packet` (`Session`, `read_buf`) lo
comparten: difieren **solo** en cómo obtienen los bytes. No hay un segundo
camino de framing que pueda divergir en la superficie post-auth.

### 1.2 Nuevo stage `Session`
```
struct Session { rx: PacketCipher, tx: PacketCipher,
                 identity: String,   // ak.fingerprint propagado desde authenticate()
                 inbuf: BytesMut }   // buffer reanudable -> read_packet cancel-safe
```
Implementa `SealedRead`/`SealedWrite` (hereda `write_sealed`). Transición
`AuthAccepted → Session` en `authenticate()` (`transport.rs:751`): poblar
`identity` con `ak.fingerprint.clone()` justo donde hoy se emite `auth.succeeded`.

### 1.3 `read_packet` cancel-safe + `write_packet`
`pub(crate) async fn read_packet(&mut self) -> Result<Vec<u8>, TransportError>`:
`read_buf` en `self.stage.inbuf` hasta tener 4 bytes de longitud, acota
`body_len ≤ MAX_PACKET` **antes** de esperar el cuerpo, completa el frame,
descifra con el helper compartido, drena `inbuf`. Cancel-safe porque el progreso
vive en `inbuf` (sobrevive a la cancelación del `select!`). `write_packet`
delega en `write_sealed` (nunca dentro de `select!`).

---

## 2. `channel.rs` — protocolo y driver

### 2.1 Constantes SSH
Mensajes 90–100 (`CHANNEL_OPEN`…`CHANNEL_FAILURE`), `GLOBAL_REQUEST` 80,
`REQUEST_FAILURE` 82; códigos `OPEN_FAILURE` (1 `ADMINISTRATIVELY_PROHIBITED`,
3 `UNKNOWN_CHANNEL_TYPE`); `SSH_EXTENDED_DATA_STDERR` 1.

### 2.2 `ChannelState`
```
enum ChannelState { Idle, Running{client_eof:bool},
                    Draining{status:i32,client_eof:bool}, ServerClosed, Closed }
```

### 2.3 Flow control (ambas direcciones)
- Salida: `out_window:u64`, `out_max_pkt:u32`; chunk = `min(remaining, out_window,
  MAX_PACKET)`; honra `WINDOW_ADJUST` (suma en `u64`, overflow > `u32::MAX` →
  PROTOCOL_ERROR).
- Entrada: invariante `granted = consumed + INITIAL_WINDOW`; `DATA > in_window` →
  PROTOCOL_ERROR; reposición vía `WINDOW_ADJUST` solo cuando el child consume
  stdin (`credit_pending ≥ CREDIT_BATCH`). `INITIAL_WINDOW = 2 MiB`,
  `MAX_PACKET = 32 KiB`, `CREDIT_BATCH = 1 MiB`.

### 2.4 `drive()` loop
Sobre `&mut Expect<S, Session>`. Por iteración: (A) flush `pending_out` mientras
la ventana del cliente lo permita; (B) handoff de un chunk de stdin con
`try_send` (full → re-stash → arm de entrada gated → backpressure de wire); (C)
emitir `WINDOW_ADJUST` si `credit_pending ≥ CREDIT_BATCH`; (D) chequeo terminal;
(E) `tokio::select!` sobre `read_packet` (cancel-safe), mpsc de salida del child,
mpsc de consumed-acks, y oneshot de exit. Ninguna escritura dentro de `select!`.

Dispatch `match` total + fail-closed: solo los 11 números de mensaje; ilegales
por sub-estado (DATA tras EOF, 2º exec, EXTENDED_DATA entrante, frame a canal
desconocido) → PROTOCOL_ERROR. No "ignore and continue".

---

## 3. `exec.rs` — proceso hijo

`spawn_blocking` con `std::process::Command::new("/bin/sh").arg("-c").arg(cmd)`
(ADR-0023: shell fijo; ADR-0016: entorno sanitizado, allowlist `PATH, HOME,
USER, SHELL, LANG, LC_*`). Threads pump separados para stdin/stdout/stderr
(evitan el deadlock std de leer-mientras-se-escribe) + tarea reap. Canales:
`mpsc<ChildChunk>` (stdout/stderr ≤ 32 KiB, bound `OUT_QUEUE=8`),
`mpsc<Vec<u8>>` stdin (`STDIN_QUEUE=8`), `mpsc<u32>` consumed-acks, `oneshot`
exit. `rustix::process::getuid()` en el boundary del exec; kill-on-early-close
vía `rustix::process::kill_process(pid, Signal::Kill)`. Spawn-failure: emitir
`exec.started`, responder `CHANNEL_SUCCESS`, cerrar con exit `127`,
`exec.finished`.

Auditoría (ADR-0024, `target: "audit"`, INFO, espejo de `transport.rs:745`):
`exec.started` { `authenticated_identity`=`%fingerprint`, `executing_uid`,
`command` estructurado, nunca interpolado }; `exec.finished` {
`authenticated_identity`, `executing_uid`, `exit_status` }.

---

## 4. `server.rs` + `lib.rs`

`lib.rs`: `pub mod channel; pub mod exec;`. `server.rs`: el `timeout` de
handshake (30 s) cubre **solo** hasta `authenticate()`; la fase de canal corre
sin timeout (Phase 1 no tiene idle/output timeout post-auth — ver Riesgos).
`run_connection` deja de ser `Infallible` (una sesión limpia retorna `Ok`).

---

## 5. Tests

### 5.1 Unit en `channel.rs` (sync, fixtures `Writer`/`Reader`)
- `parse_channel_open_session` / `rejects_non_session` / `rejects_second_open`
- `exec_honoured_once` / `second_exec_fails` / `other_request_fails`
- `outbound_chunk_respects_window_and_max_packet`
- `inbound_data_over_window_protocol_error` / `data_after_eof_error`
- `window_adjust_overflow_error` / `unknown_channel_id_error` /
  `inbound_extended_data_error`
- `credit_emitted_after_batch`
- `partial_frame_decrypt` — frame en dos mitades, un paquete out, `inbuf` drenado

### 5.2 Integración en `tests/accept.rs` (`SealedClient`, `#[tokio::test]`)
1. `channel_open_session_then_exec_echo` (principal): open → confirmation →
   `exec "echo hello"` → success → `DATA "hello\n"` → `exit-status 0` → EOF → CLOSE
2. `exec_cat_stdin_pipe` — `exec "cat"`, DATA in, mismo DATA out, EOF, exit 0
3. `exec_stderr_extended_data` — stderr → EXTENDED_DATA con código STDERR
4. `second_channel_open_rejected` / `pty_req_failure`
5. `client_early_close_no_orphan`
6. `cancel_safety_under_load` — stdout >> 2 MiB, cliente lee lento + manda stdin;
   fuerza cancelación repetida del arm de lectura; integridad exacta + exit limpio

Reemplazar `auth_success_then_channel_rejection` (obsoleto).

### 5.3 Interop gate (ADR-0020)
`integration::openssh_smoke` (`ssh … echo hello` → `hello`, exit 0),
`openssh_verbose_kex`, `negative_no_hybrid` contra OpenSSH 10.0p1 fijo en Debian
trixie (por digest), como job de CI.

---

## 6. Verificación

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo test --workspace
cargo build --workspace --release
```

---

## 7. Decisiones resueltas

1. ✅ `exec` vía `/bin/sh -c` (ADR-0023 erratum) — interop lo exige; nologin del
   service account impide usar login shell.
2. ✅ `executing_uid` vía `rustix` (ADR-0016 enmendado) sobre `nix` — menor
   superficie; el feature `process` cubre también `kill_process`.
3. ✅ Entorno sanitizado por allowlist (ADR-0016 §31), no herencia completa.
4. ✅ Un solo nodo type-state nuevo (`Session`); sub-estados en enum interno.
5. ✅ Camino de descifrado único compartido (no duplicar framing post-auth).
6. ✅ Spawn-failure: `exec.started` + `CHANNEL_SUCCESS` + exit 127 + `exec.finished`.

## 8. Secuencia de implementación

1. `transport.rs` — helper compartido, `Session`, transición, `read_packet`
2. `channel.rs` — codec + `ChannelState` + ventanas + `drive()` (unit tests)
3. `exec.rs` — `/bin/sh -c` + pumps + reap + `rustix` + auditoría
4. `server.rs` + `lib.rs` — wiring, sacar canal del timeout
5. `tests/accept.rs` — tests de integración (incl. cancel-safety bajo carga)
6. CI interop gate + verificación completa

## 9. Riesgos

- `read_packet` cancel-safe es la bisagra de correctness: una regresión desincroniza
  el stream en silencio. Mitigado por el helper compartido + test partial-frame +
  test cancel-safety bajo carga.
- `/bin/sh -c` interpreta input controlado por atacante (inherente a SSH `exec`;
  acotado por UID de servicio + env sanitizado + scope 1-canal/1-exec).
- Sin idle/output timeout post-auth en Phase 1: un cliente que deja de leer
  estanca el drain (consistente con ADR-0023 + threat-model §8.3; Phase 2 lo cierra).
- Lag de status de ADRs: 0016-0024 siguen `Proposed` aunque el crate aterrizó en
  M1; un sweep a `Accepted` es un PR de governance aparte (issue #79-adyacente).
