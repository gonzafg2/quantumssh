<!--
  Governance status (2026-07-01):
  Non-authoritative design note (ADR-0027). Guided M4 (PR #78).
  Authoritative decisions live in ADRs/RFCs: 0021, 0023, 0024.
  This file is retained for rationale and is not a source of truth.
-->
# Plan M4 — Authentication (`auth.rs`)

## Context

M0-M3 merged en `main`:
- M0: workspace, `unsafe_code = "forbid"`, minimal server binary
- M1: `wire.rs` — sshtype primitives, BPP framing, version exchange
- M2: `kex.rs` + `host_key.rs` — ADR-0021 KEXINIT profile, hybrid `mlkem768x25519-sha256`, Ed25519 host key
- M3: `transport.rs` + `cipher.rs` — type-state machine hasta `ServiceResponse::deny()`, ambos AEAD ciphers

El transport termina en `ServiceResponse::deny()` (código 7). No existe `auth.rs` ni `channel.rs`.

**M4 implementa** autenticación publickey Ed25519 (RFC 4252 §7), `authorized_keys`, y los eventos de auditoría `auth.succeeded`/`auth.failed` (ADR-0024). Deja el transport en un nuevo stage `AuthAccepted` listo para recibir channels en M5.

---

## Specs de referencia

| Spec | Rol |
|---|---|
| RFC 4252 §7 | `publickey` auth method, signed data format |
| ADR-0021 | `ssh-ed25519` único host key y key algorithm |
| ADR-0024 | Eventos de auditoría: `auth.succeeded`/`auth.failed` campos |
| ADR-0016 | Service-account UID model (el child corre como el UID del proceso, no per-user) |
| ADR-0023 | Channel layer scope (M5 — referencia para el `AuthAccepted` terminal) |
| ADR-0022 | `std::fs` para I/O de startup, `std::process::Command` para exec, `tokio::time::timeout` |

---

## Archivos

| Archivo | Acción | Líneas estimadas |
|---|---|---|
| `crates/quantumssh-core/src/auth.rs` | **NUEVO** | ~350 |
| `crates/quantumssh-core/src/transport.rs` | Modificar | +120, ~10 tocadas |
| `crates/quantumssh-core/src/lib.rs` | Modificar | +1 línea |
| `crates/quantumssh-core/src/server.rs` | Modificar | ~20 líneas |
| `crates/quantumssh/src/main.rs` | Modificar | ~15 líneas |
| `crates/quantumssh-core/tests/accept.rs` | Modificar | +150 |

---

## 1. `auth.rs` — módulo nuevo

### 1.1 Constantes SSH

```
SSH_MSG_USERAUTH_REQUEST  = 50
SSH_MSG_USERAUTH_FAILURE  = 51
SSH_MSG_USERAUTH_SUCCESS  = 52
SSH_MSG_USERAUTH_PK_OK    = 60
MAX_AUTH_ATTEMPTS         = 12
AUTH_METHOD_PUBLICKEY     = "publickey"
```

### 1.2 `AuthorizedKeys`

Estructura interna:

```
pub struct AuthorizedKey {
    blob: Vec<u8>,                          // blob wire-format (algo string + key bytes)
    fingerprint: String,                    // "SHA256:" + base64(SHA-256(blob))
    verifying_key: ed25519_dalek::VerifyingKey,
}

pub struct AuthorizedKeys {
    keys: Vec<AuthorizedKey>,
}
```

**`AuthorizedKeys::load(path: &Path) -> Result<Self, AuthError>`**

- `std::fs::read_to_string` (ADR-0022: I/O de startup bloqueante, no async)
- Por cada línea:
  - `trim()`, ignora si vacía o empieza con `#`
  - Ignora opciones (todo antes del primer token que empieza con `ssh-`)
  - Primer token → debe ser `"ssh-ed25519"`; cualquier otro algoritmo → error `UnsupportedKeyType`
  - Segundo token → base64-decode → parsea blob wire-format (string algo + string key)
  - Extrae 32 bytes de Ed25519 public key → construye `VerifyingKey`
  - Calcula `fingerprint = SHA256:` + base64(SHA-256(blob))
  - Tercer token (comment) → ignorado
- Si el archivo está vacío (cero keys parseadas) → `AuthError::Empty`

**`AuthorizedKeys::lookup(&self, key_blob: &[u8]) -> Option<&AuthorizedKey>`**

- Búsqueda lineal byte-a-byte del blob contra `self.keys[].blob`
- Phase 1 asume pocas keys (orden de decenas); si alguna vez escala, se migra a `HashMap`

**`Debug` para `AuthorizedKeys`**

- `finish_non_exhaustive()` — threat model §4.3: nunca exponer key material en `Debug`

### 1.3 `auth_signed_data`

RFC 4252 §7 define los datos que la firma cubre:

```
string   session_id
byte     SSH_MSG_USERAUTH_REQUEST (50)
string   user_name
string   service_name ("ssh-connection")
string   "publickey"
boolean  TRUE
string   key_algorithm ("ssh-ed25519")
string   key_blob
```

La implementación construye esto con `wire::Writer`:

```
pub fn auth_signed_data(session_id: &[u8; 32], payload_without_sig: &[u8]) -> Vec<u8>
```

Donde `payload_without_sig` es el raw payload del USERAUTH_REQUEST desde el byte 0 (SSH_MSG_USERAUTH_REQUEST) hasta justo antes del campo `string signature`. El método prefija `string(session_id)`.

### 1.4 `AuthError`

```
pub enum AuthError {
    /// authorized_keys file cannot be read
    Io(String),
    /// Line is not a valid ssh-ed25519 key
    MalformedLine { line: usize, reason: String },
    /// Key type is not ssh-ed25519
    UnsupportedKeyType { line: usize, found: String },
    /// No valid keys found in file
    Empty,
}
```

---

## 2. `transport.rs` — extensiones del type-state machine

### 2.1 Propagar `session_id`

El `exchange_hash` (`H`, también session identifier) se produce en `NewKeys` y actualmente solo se usa dentro de `exchange_newkeys()` para key derivation. Hay que preservarlo para que `UserAuth.authenticate()` pueda verificar firmas.

Cambios:

1. Añadir `session_id: Zeroizing<[u8; 32]>` a los structs:
   - `ServiceRequest` (línea ~110)
   - `ServiceResponse` (línea ~116)
   - `UserAuth` (nuevo)
   - `AuthAccepted` (nuevo)

2. En `exchange_newkeys()` (~línea 355), en vez de:
   ```rust
   stage: ServiceRequest { rx, tx },
   ```
   Pasar:
   ```rust
   stage: ServiceRequest { rx, tx, session_id: self.stage.exchange_hash },
   ```

3. En `read_service_request()` (~línea 408), pasar `session_id` al `ServiceResponse`:
   ```rust
   let stage = ServiceResponse {
       rx: self.stage.rx,
       tx: self.stage.tx,
       session_id: self.stage.session_id,
   };
   ```

### 2.2 Modificar `ServiceResponse`

Actualmente solo tiene `tx`. Necesita `rx` para `accept()`.

**Nuevo struct:**
```rust
pub struct ServiceResponse {
    rx: PacketCipher,
    tx: PacketCipher,
    session_id: Zeroizing<[u8; 32]>,
}
```

**Añadir impl `SealedRead`:**
```rust
impl SealedRead for ServiceResponse {
    fn rx(&mut self) -> &mut PacketCipher { &mut self.rx }
}
```

**Nuevo método `accept()`:**
```rust
pub async fn accept(mut self) -> Result<Expect<S, UserAuth>, TransportError>
```
- Escribe `SSH_MSG_SERVICE_ACCEPT` sellado
- Transiciona a `UserAuth { rx: self.stage.rx, tx: self.stage.tx, session_id: self.stage.session_id }`

### 2.3 Nuevo stage `UserAuth`

```rust
pub struct UserAuth {
    rx: PacketCipher,
    tx: PacketCipher,
    session_id: Zeroizing<[u8; 32]>,
}
```

Impl `SealedRead` + `SealedWrite`.

**Método `authenticate()`:**

```rust
pub async fn authenticate(
    mut self,
    authorized_keys: &AuthorizedKeys,
) -> Result<(String, Expect<S, AuthAccepted>), TransportError>
```

Loop interno:

1. `self.read_sealed()` → payload del USERAUTH_REQUEST
2. `Reader::new(&payload)` → parse estricto:
   - `byte()` → debe ser `SSH_MSG_USERAUTH_REQUEST`
   - `string(USER_NAME_BOUND)` → user_name
   - `string(SERVICE_NAME_BOUND)` → service_name
   - `string(METHOD_NAME_BOUND)` → method
   - Si `method != "publickey"` → envía `SSH_MSG_USERAUTH_FAILURE` con `"publickey"` como único método permitido, `auth.failed`, continúa
   - `byte()` → boolean `signature_present` (0 o 1)
   - `string(KEY_ALGO_BOUND)` → key_algorithm
   - Si `key_algorithm != "ssh-ed25519"` → FAILURE, `auth.failed`, continúa
   - `string(KEY_BLOB_BOUND)` → key_blob
   - Si `signature_present == 1`:
     - `string(SIGNATURE_BOUND)` → signature
     - `r.finish()` → validación de trailing bytes
     - `authorized_keys.lookup(key_blob)` → si no existe, FAILURE, `auth.failed`, continúa
     - `auth_signed_data(session_id, payload[..offset_of_signature])` + `verifying_key.verify()` → si falla, FAILURE, `auth.failed`, continúa
     - Éxito → `SSH_MSG_USERAUTH_SUCCESS`, `auth.succeeded` (audit tier), retorna `(fingerprint, AuthAccepted { ... })`
   - Si `signature_present == 0`:
     - `r.finish()` → validación
     - `authorized_keys.lookup(key_blob)` → si existe, `SSH_MSG_USERAUTH_PK_OK`, continúa
     - Si no existe, FAILURE, `auth.failed`, continúa
3. Incrementa `failure_count`
4. Si `failure_count >= MAX_AUTH_ATTEMPTS` → DISCONNECT code 11 (`SSH_DISCONNECT_BY_APPLICATION`), `kex.failed`-like rejection
5. Los eventos de auditoría usan `target: "audit"` con campos `auth_method`, `failure_count` (`auth.failed`), y `authenticated_identity` (`auth.succeeded`), todos en el span de la conexión

**Bounds:**
```
USER_NAME_BOUND    = 256   // SSH allows up to 255 octets
SERVICE_NAME_BOUND = 64    // "ssh-connection" = 14 bytes
METHOD_NAME_BOUND  = 32    // "publickey" = 9 bytes
KEY_ALGO_BOUND     = 64    // "ssh-ed25519" = 11 bytes
KEY_BLOB_BOUND     = 1024  // Ed25519 blob ~51 bytes, generous headroom
SIGNATURE_BOUND    = 256   // Ed25519 sig ~64 bytes, generous headroom
```

### 2.4 Nuevo stage `AuthAccepted` (terminal M4)

```rust
pub struct AuthAccepted {
    rx: PacketCipher,
    tx: PacketCipher,
    session_id: Zeroizing<[u8; 32]>,
    authenticated_identity: String,
}
```

Impl `SealedRead` + `SealedWrite`.

**Método `reject_channel_open()`:**

```rust
pub async fn reject_channel_open(mut self) -> TransportError
```

- Lee siguiente paquete sellado
- Si `SSH_MSG_CHANNEL_OPEN` (90): responde con `SSH_MSG_CHANNEL_OPEN_FAILURE` (92), reason code 1 (`SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`), description `"channels land in M5"`, log `connection.closed` en tier general
- Si `SSH_MSG_GLOBAL_REQUEST` (80): responde con `SSH_MSG_REQUEST_FAILURE` (82), log `connection.closed`
- Si `SSH_MSG_DISCONNECT` (1): retorna `TransportError::Rejected("peer-disconnected")` sin enviar nada
- Otro mensaje: DISCONNECT `SSH_DISCONNECT_PROTOCOL_ERROR` (2)

Constantes channel necesarias en este método (preludio de M5):

```
SSH_MSG_CHANNEL_OPEN          = 90
SSH_MSG_CHANNEL_OPEN_FAILURE  = 92
SSH_MSG_GLOBAL_REQUEST        = 80
SSH_MSG_REQUEST_FAILURE       = 82
SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1
```

---

## 3. `server.rs` — wiring

### 3.1 `Config`

Añadir campo:
```rust
pub authorized_keys: Arc<AuthorizedKeys>,
```

### 3.2 `Server::bind`

Pasar `config.authorized_keys` al struct `Server` (clon del `Arc`).

### 3.3 `handle` / `run_connection`

Actualmente `run_connection` retorna `Result<Infallible, TransportError>`. Después de `read_service_request()`:

```rust
let (service, responder) = t.read_service_request().await?;
match service.as_str() {
    "ssh-userauth" => {
        let t = responder.accept().await?;
        let session_id = /* extraído del exchange_hash, ver §3.3.1 */;
        let (identity, t) = t.authenticate(authorized_keys).await?;
        info!(
            target: "audit",
            authenticated_identity = %identity,
            auth_method = "publickey",
            "auth.succeeded"
        );
        Err(t.reject_channel_open().await)
    }
    _ => Err(responder.deny().await),
}
```

**§3.3.1 — session_id**: actualmente `exchange_newkeys()` no retorna el session_id. Opciones:
- **Opción A**: modificar el return type de `exchange_newkeys()` para incluir `Zeroizing<[u8; 32]>`
- **Opción B (elegida)**: el session_id viaja dentro de los stages (`ServiceRequest.session_id → ServiceResponse.session_id → UserAuth.session_id`). `authenticate()` lo usa internamente; `run_connection` no necesita accederlo.

La opción B es la correcta porque el session_id ya está dentro de `UserAuth` y `authenticate()` lo consume. `run_connection` no lo toca.

### 3.4 Campo `authorized_keys` en `Server`

```rust
pub struct Server {
    listener: TcpListener,
    handshake_timeout: Duration,
    host_key: Arc<HostKey>,
    authorized_keys: Arc<AuthorizedKeys>,
}
```

En `serve()`, pasar `Arc::clone(&self.authorized_keys)` a cada `handle()`.

---

## 4. `main.rs` — CLI

### 4.1 Nuevo flag `--authorized-keys <PATH>`

- Requerido (como `--host-key`)
- Se parsea en `parse_cli()`
- Se agrega a la ayuda (`USAGE`)

### 4.2 Carga en `main()`

```rust
let authorized_keys_path = /* del CLI */;
let authorized_keys = match AuthorizedKeys::load(std::path::Path::new(&authorized_keys_path)) {
    Ok(k) => Arc::new(k),
    Err(e) => {
        error!(message = %format!("cannot load authorized_keys {}: {e}", authorized_keys_path), "server.config_error");
        return ExitCode::FAILURE;
    }
};
```

### 4.3 Pasar a `Config`

```rust
let config = Config {
    listen: cli.listen,
    handshake_timeout: cli.handshake_timeout,
    host_key,
    authorized_keys,
};
```

---

## 5. Tests

### 5.1 Unit tests en `auth.rs`

- `parse_single_valid_key` — una línea `ssh-ed25519 AAAA... comment` → extrae blob + fingerprint + verifying_key
- `ignore_comments_and_empty_lines` — `#` y líneas vacías ignoradas
- `ignore_trailing_comment` — todo después del segundo token base64 es ignorado
- `reject_rsa_key` — `ssh-rsa AAAA...` → `UnsupportedKeyType`
- `reject_malformed_base64` — base64 inválido → `MalformedLine`
- `reject_invalid_blob` — base64 válido pero blob no es `ssh-ed25519` wire format → `MalformedLine`
- `reject_empty_file` — archivo sin keys → `Empty`
- `lookup_finds_by_blob` — `lookup()` encuentra blob exacto
- `lookup_rejects_unknown` — `lookup()` retorna `None` para blob desconocido
- `debug_does_not_leak_keys` — `format!("{:?}", keys)` no contiene material sensible
- `auth_signed_data_known_vector` — KAT con valores fijos de session_id + payload

### 5.2 Integración en `tests/accept.rs`

#### Helpers nuevos

```rust
fn temp_authorized_keys(seed: [u8; 32]) -> (tempfile::NamedTempFile, ed25519_dalek::SigningKey) {
    // Genera una signing key, escribe authorized_keys con la pública
    // Retorna el archivo temporal + la signing key para firmar
}

fn sign_auth_request(signing_key: &SigningKey, session_id: &[u8; 32], user: &str) -> Vec<u8> {
    // Construye el payload USERAUTH_REQUEST con firma válida
}
```

#### Tests

1. **`auth_success_then_channel_rejection`** (test principal de M4)
   - Completa handshake M3
   - Envía `SSH_MSG_SERVICE_REQUEST "ssh-userauth"` → recibe `SSH_MSG_SERVICE_ACCEPT`
   - Envía `SSH_MSG_USERAUTH_REQUEST` con firma Ed25519 válida → recibe `SSH_MSG_USERAUTH_SUCCESS`
   - Envía `SSH_MSG_CHANNEL_OPEN "session"` → recibe `SSH_MSG_CHANNEL_OPEN_FAILURE`

2. **`auth_failure_on_wrong_signature`**
   - Misma secuencia pero firma sobre datos incorrectos → recibe `SSH_MSG_USERAUTH_FAILURE`

3. **`auth_rejects_non_publickey_method`**
   - USERAUTH_REQUEST con `method = "password"` → recibe FAILURE con `"publickey"` en la lista de métodos

4. **`auth_rejects_non_ed25519_key`**
   - USERAUTH_REQUEST con `key_algorithm = "ssh-rsa"` → recibe FAILURE

5. **`auth_pk_ok_for_known_key_without_signature`**
   - USERAUTH_REQUEST con `signature_present = false`, key en authorized_keys → recibe `SSH_MSG_USERAUTH_PK_OK`
   - Luego envía con firma → recibe SUCCESS

6. **`max_auth_attempts_disconnects`**
   - `MAX_AUTH_ATTEMPTS + 1` intentos fallidos con keys no autorizadas → recibe DISCONNECT code 11

---

## 6. Verificación

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
cargo deny check
cargo audit
```

---

## 7. Preguntas abiertas

1. **`MAX_AUTH_ATTEMPTS = 12`** ✅ decidido.
2. **Formato `authorized_keys`: ignorar opciones** ✅ decidido.
3. **`AuthAccepted` con `reject_channel_open()`** ✅ decidido. Usa 4 constantes de RFC 4254 (channel layer = M5) como preludio en M4 para un cierre de conexión protocol-correcto.

---

## 8. Secuencia de implementación

1. `auth.rs` — AuthorizedKeys + auth_signed_data + unit tests
2. `transport.rs` — propagar session_id, modificar ServiceResponse, nuevo UserAuth, nuevo AuthAccepted
3. `server.rs` — actualizar Config, Server, run_connection
4. `main.rs` — nuevo flag CLI, carga de authorized_keys
5. `lib.rs` — `pub mod auth;`
6. `tests/accept.rs` — integration tests
7. Verificación completa (`fmt` + `clippy` + `test` + `build`)
