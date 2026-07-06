//! ADR-0024's human-format field formatter: control bytes in field
//! values are escaped to a visible `\xNN` form, so attacker-chosen
//! content (an `exec` `command`, a peer identification line) cannot
//! replay ANSI sequences or forge log lines in an operator's live
//! terminal (threat model §5.4.3). Stock `tracing_subscriber::fmt()`
//! does not do this, which is why the formatter is part of the
//! ADR-0024 decision. The JSON format needs no equivalent — serde
//! escapes control bytes.

use std::fmt::{self, Write as _};

use tracing::field::{Field, Visit};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::Writer;

/// Field formatter for `LogFormat::Human`: the default `name=value`
/// space-separated layout, with every value control-byte-escaped.
pub struct EscapingFields;

impl<'writer> FormatFields<'writer> for EscapingFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut visitor = EscapingVisitor {
            writer: &mut writer,
            result: Ok(()),
            first: true,
        };
        fields.record(&mut visitor);
        visitor.result
    }
}

struct EscapingVisitor<'a, 'writer> {
    writer: &'a mut Writer<'writer>,
    result: fmt::Result,
    first: bool,
}

impl EscapingVisitor<'_, '_> {
    fn record_with(
        &mut self,
        field: &Field,
        write_value: impl FnOnce(&mut Writer<'_>) -> fmt::Result,
    ) {
        if self.result.is_err() {
            return;
        }
        self.result = (|| {
            if !self.first {
                self.writer.write_char(' ')?;
            }
            if field.name() != "message" {
                write!(self.writer, "{}=", field.name())?;
            }
            write_value(self.writer)
        })();
        self.first = false;
    }
}

impl Visit for EscapingVisitor<'_, '_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_with(field, |w| write_escaped(w, value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%`-recorded fields (Display) arrive here too — this is the
        // path an attacker-chosen `command` takes. Formatting streams
        // through the escaping adapter: no intermediate String.
        self.record_with(field, |w| {
            let mut escaping = EscapingWriter(w);
            write!(escaping, "{value:?}")
        });
    }
}

/// `fmt::Write` adapter over the layer's [`Writer`] that escapes
/// control bytes as it writes, so `Debug`/`Display` formatting streams
/// straight through [`write_escaped`] without allocating.
struct EscapingWriter<'a, 'writer>(&'a mut Writer<'writer>);

impl fmt::Write for EscapingWriter<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_escaped(self.0, s)
    }
}

/// Writes `s` with every control character — C0, DEL, and C1,
/// everything `char::is_control` reports, all ≤ U+009F — as a
/// visible `\xNN` (ADR-0024; threat model §5.4.3).
fn write_escaped(writer: &mut Writer<'_>, s: &str) -> fmt::Result {
    for c in s.chars() {
        if c.is_control() {
            write!(writer, "\\x{:02x}", c as u32)?;
        } else {
            writer.write_char(c)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[test]
    fn control_bytes_become_visible_escapes() {
        let mut out = String::new();
        write_escaped(
            &mut Writer::new(&mut out),
            "a\x1b]0;pwned\x07\nb\u{9b}c\x7f",
        )
        .unwrap();
        assert_eq!(out, "a\\x1b]0;pwned\\x07\\x0ab\\x9bc\\x7f");
    }

    #[test]
    fn plain_text_passes_through_unchanged() {
        let mut out = String::new();
        write_escaped(&mut Writer::new(&mut out), "ls -la /tmp — ção").unwrap();
        assert_eq!(out, "ls -la /tmp — ção");
    }

    #[derive(Clone)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn human_layer_escapes_an_attacker_chosen_command() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink(Arc::clone(&buf));
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .fmt_fields(EscapingFields);
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            // The §5.4.3 attack: a command carrying a live OSC title
            // escape plus a newline that forges a second log line.
            let command = "true\x1b]0;pwned\x07\ninfo forged.event";
            tracing::info!(target: "audit", command = %command, "exec.started");
        });

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("command=true\\x1b]0;pwned\\x07\\x0ainfo forged.event"),
            "got: {out}"
        );
        // No live control byte survives except the line's own newline.
        assert!(!out.contains('\x1b'));
        assert_eq!(out.matches('\n').count(), 1);
        assert!(out.ends_with('\n'));
    }
}
