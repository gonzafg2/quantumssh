//! The audit-log JSON line, schema version 1 (RFC-0014 §2). One flat
//! object per record: the envelope keys, then the event's own fields at
//! the top level. The project owns this layout, not `tracing-subscriber`,
//! so no module path, span name or span list reaches the output.
//!
//! Every string is written by [`write_string`], which escapes each
//! character `char::is_control` reports (C0, DEL and C1) as `\u00XX`,
//! the set the human formatter escapes (threat model §5.4.3).

use std::fmt;

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// The `schema_version` every record carries (RFC-0014 §2).
const SCHEMA_VERSION: u32 = 1;

/// The target of the catalogue events (ADR-0024's audit tier).
pub const AUDIT_TARGET: &str = "audit";

/// Envelope keys an event field may not reuse (RFC-0014 §2).
const ENVELOPE_KEYS: [&str; 6] = [
    "schema_version",
    "timestamp",
    "level",
    "event",
    "message",
    "peer_addr",
];

/// The event formatter for `LogFormat::Json`.
pub struct JsonV1;

impl<S, N> FormatEvent<S, N> for JsonV1
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;

        write!(
            writer,
            "{{\"schema_version\":{SCHEMA_VERSION},\"timestamp\":"
        )?;
        write_string(&mut writer, &timestamp)?;
        writer.write_str(",\"level\":")?;
        write_string(&mut writer, event.metadata().level().as_str())?;
        // A catalogue record names its event; a diagnostic carries text.
        let name_key = if event.metadata().target() == AUDIT_TARGET {
            "event"
        } else {
            "message"
        };
        write!(writer, ",\"{name_key}\":")?;
        write_string(&mut writer, fields.message.as_deref().unwrap_or(""))?;
        let peer_addr = ctx.event_scope().and_then(|scope| {
            scope
                .from_root()
                .find_map(|span| span.extensions().get::<PeerAddr>().map(|p| p.0.clone()))
        });
        if let Some(peer_addr) = peer_addr {
            writer.write_str(",\"peer_addr\":")?;
            write_string(&mut writer, &peer_addr)?;
        }
        for (name, value) in &fields.values {
            writer.write_char(',')?;
            write_string(&mut writer, name)?;
            writer.write_char(':')?;
            match value {
                Value::Str(s) => write_string(&mut writer, s)?,
                Value::Raw(raw) => writer.write_str(raw)?,
            }
        }
        writer.write_str("}\n")
    }
}

/// Records the `connection` span's `peer_addr`, so every record emitted
/// inside a connection carries it as an envelope key (RFC-0014 §2).
/// Installed unfiltered, before the formatting layers, so it sees every
/// `connection` span whatever `RUST_LOG` says.
pub struct ConnectionPeer;

/// A `connection` span's `peer_addr`, in the span's extensions.
struct PeerAddr(String);

impl<S> Layer<S> for ConnectionPeer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if attrs.metadata().name() != "connection" {
            return;
        }
        let mut visitor = PeerAddrVisitor(None);
        attrs.record(&mut visitor);
        if let (Some(peer_addr), Some(span)) = (visitor.0, ctx.span(id)) {
            span.extensions_mut().insert(PeerAddr(peer_addr));
        }
    }
}

struct PeerAddrVisitor(Option<String>);

impl Visit for PeerAddrVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "peer_addr" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "peer_addr" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

/// A field value: a string to escape, or a number or boolean written as
/// is.
enum Value {
    Str(String),
    Raw(String),
}

/// The event's `message` (its name, or a diagnostic's text) and its other
/// fields, in callsite order.
#[derive(Default)]
struct Fields {
    message: Option<String>,
    values: Vec<(&'static str, Value)>,
}

impl Fields {
    fn push(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            if let Value::Str(s) = value {
                self.message = Some(s);
            }
        } else if !ENVELOPE_KEYS.contains(&field.name()) {
            self.values.push((field.name(), value));
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, Value::Str(value.to_owned()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, Value::Raw(value.to_string()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, Value::Raw(value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, Value::Raw(value.to_string()));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.push(field, Value::Raw(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.push(field, Value::Raw(value.to_string()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // JSON has no NaN or infinity.
        let value = if value.is_finite() {
            Value::Raw(value.to_string())
        } else {
            Value::Str(value.to_string())
        };
        self.push(field, value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.push(field, Value::Str(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%x` and the message arrive here; both render as their text.
        self.push(field, Value::Str(format!("{value:?}")));
    }
}

/// Writes `s` as a JSON string. `"` and `\` are escaped, and so is every
/// character `char::is_control` reports, as `\u00XX`: C0, DEL and C1 all
/// lie at or below U+009F (RFC-0014 §2; threat model §5.4.3).
fn write_string(writer: &mut Writer<'_>, s: &str) -> fmt::Result {
    writer.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => writer.write_str("\\\"")?,
            '\\' => writer.write_str("\\\\")?,
            c if c.is_control() => write!(writer, "\\u{:04x}", c as u32)?,
            c => writer.write_char(c)?,
        }
    }
    writer.write_char('"')
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The lines `emit` writes through [`JsonV1`], each with its
    /// timestamp replaced by `T`, after checking the timestamp's form.
    fn lines(emit: impl FnOnce()) -> Vec<String> {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(ConnectionPeer).with(
            tracing_subscriber::fmt::layer()
                .with_writer(capture.clone())
                .event_format(JsonV1),
        );
        tracing::subscriber::with_default(subscriber, emit);
        let out = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        out.lines()
            .map(|line| {
                let (head, rest) = line.split_once("\"timestamp\":\"").unwrap();
                let (timestamp, tail) = rest.split_at(27);
                // RFC-0014 §2: RFC 3339, UTC, microseconds, `Z` suffix.
                let shape: String = timestamp
                    .chars()
                    .map(|c| if c.is_ascii_digit() { '0' } else { c })
                    .collect();
                assert_eq!(shape, "0000-00-00T00:00:00.000000Z", "{line}");
                format!("{head}\"timestamp\":\"T{tail}")
            })
            .collect()
    }

    fn one(emit: impl FnOnce()) -> String {
        let mut lines = lines(emit);
        assert_eq!(lines.len(), 1, "{lines:?}");
        lines.remove(0)
    }

    /// Emits `emit` inside a `connection` span, as the accept loop does.
    fn in_connection(emit: impl FnOnce()) -> String {
        one(|| {
            let peer: std::net::SocketAddr = "192.0.2.7:50022".parse().unwrap();
            let _span = tracing::info_span!("connection", peer_addr = %peer).entered();
            emit();
        })
    }

    const HEAD: &str = r#"{"schema_version":1,"timestamp":"T""#;

    #[test]
    fn a_diagnostic_carries_message_and_no_target() {
        let line =
            one(|| tracing::info!(drain_seconds = 30_u64, "shutdown signal received; draining"));
        assert_eq!(
            line,
            format!(
                r#"{HEAD},"level":"INFO","message":"shutdown signal received; draining","drain_seconds":30}}"#
            )
        );
    }

    #[test]
    fn peer_addr_comes_from_the_connection_span() {
        let line = in_connection(|| tracing::info!(target: "audit", "connection.accepted"));
        assert_eq!(
            line,
            format!(
                r#"{HEAD},"level":"INFO","event":"connection.accepted","peer_addr":"192.0.2.7:50022"}}"#
            )
        );
    }

    #[test]
    fn control_characters_are_escaped_c0_del_and_c1() {
        let line = one(|| {
            tracing::warn!(target: "audit", auth_method = "a\n\u{7f}\u{9b}[31m\"\\", failure_count = 1_u64, "auth.failed");
        });
        assert_eq!(
            line,
            format!(
                r#"{HEAD},"level":"WARN","event":"auth.failed","auth_method":"a\u000a\u007f\u009b[31m\"\\","failure_count":1}}"#
            )
        );
    }

    #[test]
    fn an_event_field_cannot_reuse_an_envelope_key() {
        let line =
            one(|| tracing::info!(target: "audit", level = "x", peer_addr = "y", "kex.completed"));
        assert_eq!(
            line,
            format!(r#"{HEAD},"level":"INFO","event":"kex.completed"}}"#)
        );
    }

    /// RFC-0014 §3, one golden line per catalogue event, with the field
    /// types the emitters use. One table, so the count check covers the
    /// whole catalogue.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_version_1_catalogue_lines() {
        let fingerprint = "SHA256:cp4BNirSzGclLcIrv4GSoYcZD47+bqGl0GdHc/vPJE8";
        let cases: Vec<(String, String)> = vec![
            (
                one(
                    || tracing::info!(target: "audit", listen_addr = %"127.0.0.1:2222", host_key_fingerprint = %fingerprint, config_file = %"/etc/quantumssh/config.toml", "server.started"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"server.started","listen_addr":"127.0.0.1:2222","host_key_fingerprint":"{fingerprint}","config_file":"/etc/quantumssh/config.toml"}}"#
                ),
            ),
            (
                one(
                    || tracing::info!(target: "audit", key = "server.listen", "server.config_override"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"server.config_override","key":"server.listen"}}"#
                ),
            ),
            (
                one(
                    || tracing::error!(target: "audit", class = "schema_error", error = %"q.toml: unknown field `port` at line 3 column 1", config_file = %"q.toml", "server.config_error"),
                ),
                format!(
                    r#"{HEAD},"level":"ERROR","event":"server.config_error","class":"schema_error","error":"q.toml: unknown field `port` at line 3 column 1","config_file":"q.toml"}}"#
                ),
            ),
            (
                in_connection(|| tracing::info!(target: "audit", "connection.accepted")),
                format!(
                    r#"{HEAD},"level":"INFO","event":"connection.accepted","peer_addr":"192.0.2.7:50022"}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::info!(target: "audit", limit = "max_per_source", "connection.refused"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"connection.refused","peer_addr":"192.0.2.7:50022","limit":"max_per_source"}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::info!(target: "audit", reason = %"client closed", "connection.closed"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"connection.closed","peer_addr":"192.0.2.7:50022","reason":"client closed"}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::info!(target: "audit", kex_algorithm = "mlkem768x25519-sha256", host_key_algorithm = "ssh-ed25519", "kex.completed"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"kex.completed","peer_addr":"192.0.2.7:50022","kex_algorithm":"mlkem768x25519-sha256","host_key_algorithm":"ssh-ed25519"}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::warn!(target: "audit", reason = "no-hybrid-kex", disconnect_code = 3_u32, "kex.failed"),
                ),
                format!(
                    r#"{HEAD},"level":"WARN","event":"kex.failed","peer_addr":"192.0.2.7:50022","reason":"no-hybrid-kex","disconnect_code":3}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::info!(target: "audit", kex_algorithm = "mlkem768x25519-sha256", host_key_algorithm = "ssh-ed25519", initiator = "server", trigger = "bytes", bytes_rx = 1_u64, bytes_tx = 2_u64, seconds = 3_u64, "rekey.completed"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"rekey.completed","peer_addr":"192.0.2.7:50022","kex_algorithm":"mlkem768x25519-sha256","host_key_algorithm":"ssh-ed25519","initiator":"server","trigger":"bytes","bytes_rx":1,"bytes_tx":2,"seconds":3}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::info!(target: "audit", authenticated_identity = %fingerprint, auth_method = "publickey", "auth.succeeded"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"auth.succeeded","peer_addr":"192.0.2.7:50022","authenticated_identity":"{fingerprint}","auth_method":"publickey"}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::warn!(target: "audit", auth_method = "publickey", failure_count = 1_u32, "auth.failed"),
                ),
                format!(
                    r#"{HEAD},"level":"WARN","event":"auth.failed","peer_addr":"192.0.2.7:50022","auth_method":"publickey","failure_count":1}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::info!(target: "audit", authenticated_identity = %fingerprint, executing_uid = 993_u32, command = %"echo hi", request_type = "exec", pty = false, "exec.started"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"exec.started","peer_addr":"192.0.2.7:50022","authenticated_identity":"{fingerprint}","executing_uid":993,"command":"echo hi","request_type":"exec","pty":false}}"#
                ),
            ),
            (
                in_connection(
                    || tracing::info!(target: "audit", authenticated_identity = %fingerprint, executing_uid = 993_u32, command = %"sftp", request_type = "subsystem", pty = false, exit_status = 0_i32, bytes_received = 10_u64, bytes_sent = 20_u64, "exec.finished"),
                ),
                format!(
                    r#"{HEAD},"level":"INFO","event":"exec.finished","peer_addr":"192.0.2.7:50022","authenticated_identity":"{fingerprint}","executing_uid":993,"command":"sftp","request_type":"subsystem","pty":false,"exit_status":0,"bytes_received":10,"bytes_sent":20}}"#
                ),
            ),
        ];
        assert_eq!(cases.len(), 13, "one case per RFC-0014 §3 event");
        for (got, want) in cases {
            assert_eq!(got, want);
        }
    }
}
