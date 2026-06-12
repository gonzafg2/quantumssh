//! Core library of the `QuantumSSH` server.
//!
//! `QuantumSSH` is a memory-safe, post-quantum-first SSH server built
//! greenfield on audited cryptographic primitive crates (RFC-0003).
//! This crate holds all server logic; the `quantumssh` binary is a
//! thin entrypoint over it (ADR-0017).
//!
//! The crate is built with `unsafe_code = "forbid"` workspace-wide
//! (ADR-0018) and emits logs exclusively through the [`tracing`]
//! facade — it never installs a subscriber (ADR-0024).
//!
//! Protocol modules (wire framing, key exchange, transport state
//! machine, authentication, channels) land milestone by milestone;
//! only functional code is merged — the project forbids stubs.

pub mod server;
pub mod wire;
