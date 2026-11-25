//! The launcher protocol (ADR-0063): the messages between the network
//! server and the root launcher of account mode (RFC-0020 §2).
//!
//! One message per `SOCK_SEQPACKET` record. Byte 0 is the type, and the
//! fields use RFC 4251 §5's encodings. These are pure functions over byte
//! slices. [`parse_request`] is the one parser in the root process that
//! reads bytes another process chose, so it treats every byte as hostile
//! and has a fuzz target (ADR-0063 §6).

use crate::wire::{self, Reader, Writer};
use crate::{auth, pty};

pub mod client;
#[cfg(target_os = "linux")]
pub mod runtime;

/// The reserved first argument that runs the network server under the
/// launcher (ADR-0066 §2).
pub const SERVER_ARG: &str = "--quantumssh-internal-network-server";

/// The largest record: the sum of the bounds below, rounded up
/// (ADR-0063 §3).
pub const MAX_RECORD: usize = 36 * 1024;

/// An account name's bound: the user-name bound (RFC-0019 §3).
pub const MAX_ACCOUNT: usize = auth::USER_NAME_BOUND;

/// An `exec` command's bound: no SSH packet, and so no `exec` request,
/// can carry more.
pub const MAX_COMMAND: usize = wire::MAX_PACKET as usize;

// Server to launcher.
const READY: u8 = 1;
const START: u8 = 2;
const END: u8 = 3;
// Launcher to server.
const LISTENER: u8 = 16;
const STARTED: u8 = 17;
const REFUSED: u8 = 18;
const EXITED: u8 = 19;

const EXEC: u8 = 1;
const SHELL: u8 = 2;
const SFTP: u8 = 3;

const EXIT_CODE: u8 = 1;
const EXIT_SIGNAL: u8 = 2;

/// The four `pty-req` dimensions, in RFC 4254 order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSize {
    /// Columns.
    pub cols: u32,
    /// Rows.
    pub rows: u32,
    /// Width in pixels.
    pub width_px: u32,
    /// Height in pixels.
    pub height_px: u32,
}

/// The `pty-req` fields a session starts with (ADR-0064 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtyRequest<'a> {
    /// `TERM`: empty, or ADR-0038 §2's pattern.
    pub term: &'a [u8],
    /// The window size.
    pub size: WindowSize,
    /// The encoded terminal modes, which `pty::Modes::parse` accepts.
    pub modes: &'a [u8],
}

/// What a session runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session<'a> {
    /// `exec`, with its command, on pipes or on a PTY.
    Exec {
        /// The client's command, which only the account's shell reads.
        command: &'a [u8],
        /// The PTY, if the channel asked for one.
        pty: Option<PtyRequest<'a>>,
    },
    /// `shell`, on pipes or on a PTY.
    Shell {
        /// The PTY, if the channel asked for one.
        pty: Option<PtyRequest<'a>>,
    },
    /// The SFTP subsystem, on pipes.
    Sftp,
}

/// A message from the server to the launcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    /// The server is ready (ADR-0066 §3).
    Ready,
    /// Start a session as `account`.
    Start {
        /// The listed account's name.
        account: &'a str,
        /// What the session runs.
        session: Session<'a>,
    },
    /// End a session (ADR-0064 §4).
    End {
        /// The identifier the launcher gave the session.
        session: u64,
    },
}

/// Why the launcher refused a start (ADR-0063 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The account is not listed.
    NotListed,
    /// The account does not resolve now.
    Unresolved,
    /// The session limit is reached.
    Limit,
    /// The PTY could not be allocated.
    Pty,
    /// The helper could not be started.
    Helper,
}

impl Refusal {
    const fn code(self) -> u8 {
        match self {
            Self::NotListed => 1,
            Self::Unresolved => 2,
            Self::Limit => 3,
            Self::Pty => 4,
            Self::Helper => 5,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::NotListed),
            2 => Some(Self::Unresolved),
            3 => Some(Self::Limit),
            4 => Some(Self::Pty),
            5 => Some(Self::Helper),
            _ => None,
        }
    }
}

/// How a session's leader ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// It exited with this code.
    Code(u32),
    /// A signal killed it.
    Signal {
        /// The signal number.
        signal: u32,
        /// Whether it dumped core.
        core_dumped: bool,
    },
}

/// A message from the launcher to the server. Its descriptors travel in
/// the same record, as `SCM_RIGHTS` (ADR-0063 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Carries the listening socket.
    Listener,
    /// A session started; carries its stdio ends or its PTY master.
    Started {
        /// The session's identifier.
        session: u64,
        /// The UID it runs under.
        uid: u32,
    },
    /// A start was refused.
    Refused(Refusal),
    /// A session ended, and the launcher reaped it.
    Exited {
        /// The session's identifier.
        session: u64,
        /// How it ended.
        exit: Exit,
    },
}

/// A record that breaks the protocol, and the rule it breaks. The
/// launcher logs the rule, never the bytes (ADR-0063 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

/// Parses a record from the server (ADR-0063 §2, §3).
///
/// # Errors
///
/// [`Malformed`] for a record over [`MAX_RECORD`], an unknown type, a
/// field that is truncated, over its bound or outside its rule, a field
/// the session kind does not take, or trailing bytes.
pub fn parse_request(record: &[u8]) -> Result<Request<'_>, Malformed> {
    if record.len() > MAX_RECORD {
        return Err(Malformed("record over its bound"));
    }
    let mut r = Reader::new(record);
    let request = match r.byte().map_err(|_| Malformed("empty record"))? {
        READY => Request::Ready,
        START => parse_start(&mut r)?,
        END => Request::End {
            session: r.uint64().map_err(|_| truncated())?,
        },
        _ => return Err(Malformed("unknown message type")),
    };
    r.finish().map_err(|_| Malformed("trailing bytes"))?;
    Ok(request)
}

fn parse_start<'a>(r: &mut Reader<'a>) -> Result<Request<'a>, Malformed> {
    let account = r.string(MAX_ACCOUNT).map_err(|_| truncated())?;
    let account = std::str::from_utf8(account)
        .ok()
        .filter(|a| !a.is_empty())
        .ok_or(Malformed("account name empty or not UTF-8"))?;
    let session = match r.byte().map_err(|_| truncated())? {
        EXEC => Session::Exec {
            command: r.string(MAX_COMMAND).map_err(|_| truncated())?,
            pty: parse_pty(r)?,
        },
        SHELL => Session::Shell { pty: parse_pty(r)? },
        SFTP => Session::Sftp,
        _ => return Err(Malformed("unknown session kind")),
    };
    Ok(Request::Start { account, session })
}

fn parse_pty<'a>(r: &mut Reader<'a>) -> Result<Option<PtyRequest<'a>>, Malformed> {
    if !r.boolean().map_err(|_| truncated())? {
        return Ok(None);
    }
    let term = r.string(pty::TERM_BOUND).map_err(|_| truncated())?;
    if !pty::valid_term(term) {
        return Err(Malformed("TERM outside ADR-0038 §2's rule"));
    }
    let mut dim = || r.uint32().map_err(|_| truncated());
    let size = WindowSize {
        cols: dim()?,
        rows: dim()?,
        width_px: dim()?,
        height_px: dim()?,
    };
    let modes = r.string(pty::MODES_BOUND).map_err(|_| truncated())?;
    pty::Modes::parse(modes).map_err(|_| Malformed("terminal modes truncated"))?;
    Ok(Some(PtyRequest { term, size, modes }))
}

const fn truncated() -> Malformed {
    Malformed("field truncated or over its bound")
}

/// Encodes a message to the launcher.
#[must_use]
pub fn encode_request(request: &Request<'_>) -> Vec<u8> {
    let mut w = Writer::new();
    match *request {
        Request::Ready => w.put_byte(READY),
        Request::Start { account, session } => {
            w.put_byte(START);
            w.put_string(account.as_bytes());
            match session {
                Session::Exec { command, pty } => {
                    w.put_byte(EXEC);
                    w.put_string(command);
                    put_pty(&mut w, pty);
                }
                Session::Shell { pty } => {
                    w.put_byte(SHELL);
                    put_pty(&mut w, pty);
                }
                Session::Sftp => w.put_byte(SFTP),
            }
        }
        Request::End { session } => {
            w.put_byte(END);
            w.put_uint64(session);
        }
    }
    w.into_bytes()
}

fn put_pty(w: &mut Writer, pty: Option<PtyRequest<'_>>) {
    w.put_boolean(pty.is_some());
    if let Some(p) = pty {
        w.put_string(p.term);
        w.put_uint32(p.size.cols);
        w.put_uint32(p.size.rows);
        w.put_uint32(p.size.width_px);
        w.put_uint32(p.size.height_px);
        w.put_string(p.modes);
    }
}

/// Encodes a message to the server.
#[must_use]
pub fn encode_reply(reply: &Reply) -> Vec<u8> {
    let mut w = Writer::new();
    match *reply {
        Reply::Listener => w.put_byte(LISTENER),
        Reply::Started { session, uid } => {
            w.put_byte(STARTED);
            w.put_uint64(session);
            w.put_uint32(uid);
        }
        Reply::Refused(refusal) => {
            w.put_byte(REFUSED);
            w.put_byte(refusal.code());
        }
        Reply::Exited { session, exit } => {
            w.put_byte(EXITED);
            w.put_uint64(session);
            match exit {
                Exit::Code(code) => {
                    w.put_byte(EXIT_CODE);
                    w.put_uint32(code);
                    w.put_boolean(false);
                }
                Exit::Signal {
                    signal,
                    core_dumped,
                } => {
                    w.put_byte(EXIT_SIGNAL);
                    w.put_uint32(signal);
                    w.put_boolean(core_dumped);
                }
            }
        }
    }
    w.into_bytes()
}

/// Parses a record from the launcher. Its input comes from root, so it is
/// not fuzzed (ADR-0063 §6); a record it rejects is a launcher fault
/// (ADR-0066 §5).
///
/// # Errors
///
/// [`Malformed`] for an unknown type or value, a truncated field, or
/// trailing bytes.
pub fn parse_reply(record: &[u8]) -> Result<Reply, Malformed> {
    let mut r = Reader::new(record);
    let reply = match r.byte().map_err(|_| Malformed("empty record"))? {
        LISTENER => Reply::Listener,
        STARTED => Reply::Started {
            session: r.uint64().map_err(|_| truncated())?,
            uid: r.uint32().map_err(|_| truncated())?,
        },
        REFUSED => Reply::Refused(
            Refusal::from_code(r.byte().map_err(|_| truncated())?)
                .ok_or(Malformed("unknown refusal reason"))?,
        ),
        EXITED => {
            let session = r.uint64().map_err(|_| truncated())?;
            let how = r.byte().map_err(|_| truncated())?;
            let value = r.uint32().map_err(|_| truncated())?;
            let core_dumped = r.boolean().map_err(|_| truncated())?;
            let exit = match how {
                EXIT_CODE if !core_dumped => Exit::Code(value),
                EXIT_SIGNAL => Exit::Signal {
                    signal: value,
                    core_dumped,
                },
                _ => return Err(Malformed("unknown exit kind")),
            };
            Reply::Exited { session, exit }
        }
        _ => return Err(Malformed("unknown message type")),
    };
    r.finish().map_err(|_| Malformed("trailing bytes"))?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: WindowSize = WindowSize {
        cols: 80,
        rows: 24,
        width_px: 0,
        height_px: 0,
    };

    fn round_trip(request: &Request<'_>) {
        assert_eq!(
            parse_request(&encode_request(request)).as_ref(),
            Ok(request)
        );
    }

    #[test]
    fn every_request_round_trips() {
        let pty = Some(PtyRequest {
            term: b"xterm-256color",
            size: SIZE,
            modes: &[],
        });
        round_trip(&Request::Ready);
        round_trip(&Request::End { session: u64::MAX });
        round_trip(&Request::Start {
            account: "alice",
            session: Session::Exec {
                command: b"uptime",
                pty: None,
            },
        });
        round_trip(&Request::Start {
            account: "alice",
            session: Session::Exec { command: b"", pty },
        });
        round_trip(&Request::Start {
            account: "deploy",
            session: Session::Shell { pty },
        });
        round_trip(&Request::Start {
            account: "deploy",
            session: Session::Shell { pty: None },
        });
        round_trip(&Request::Start {
            account: "svc$",
            session: Session::Sftp,
        });
    }

    #[test]
    fn every_reply_round_trips() {
        for reply in [
            Reply::Listener,
            Reply::Started {
                session: 1,
                uid: 1001,
            },
            Reply::Refused(Refusal::NotListed),
            Reply::Refused(Refusal::Unresolved),
            Reply::Refused(Refusal::Limit),
            Reply::Refused(Refusal::Pty),
            Reply::Refused(Refusal::Helper),
            Reply::Exited {
                session: 7,
                exit: Exit::Code(3),
            },
            Reply::Exited {
                session: 7,
                exit: Exit::Signal {
                    signal: 15,
                    core_dumped: true,
                },
            },
        ] {
            assert_eq!(parse_reply(&encode_reply(&reply)), Ok(reply));
        }
    }

    /// A `start` with every field at its bound, as raw bytes.
    fn largest_start() -> Vec<u8> {
        let account = "a".repeat(MAX_ACCOUNT);
        let command = vec![b'x'; MAX_COMMAND];
        let term = vec![b't'; pty::TERM_BOUND];
        // 0 is TTY_OP_END: a valid modes blob of any length.
        let modes = vec![0u8; pty::MODES_BOUND];
        encode_request(&Request::Start {
            account: &account,
            session: Session::Exec {
                command: &command,
                pty: Some(PtyRequest {
                    term: &term,
                    size: SIZE,
                    modes: &modes,
                }),
            },
        })
    }

    #[test]
    fn a_start_at_every_bound_fits_the_record() {
        let record = largest_start();
        assert!(record.len() <= MAX_RECORD, "{}", record.len());
        assert!(parse_request(&record).is_ok());
    }

    #[test]
    fn a_field_past_its_bound_is_malformed() {
        let start = |account: &str, command: &[u8], term: &[u8], modes: &[u8]| {
            encode_request(&Request::Start {
                account,
                session: Session::Exec {
                    command,
                    pty: Some(PtyRequest {
                        term,
                        size: SIZE,
                        modes,
                    }),
                },
            })
        };
        let long_account = "a".repeat(MAX_ACCOUNT + 1);
        let long_command = vec![b'x'; MAX_COMMAND + 1];
        let long_term = vec![b't'; pty::TERM_BOUND + 1];
        let long_modes = vec![0u8; pty::MODES_BOUND + 1];
        for record in [
            start(&long_account, b"", b"", &[]),
            start("a", &long_command, b"", &[]),
            start("a", b"", &long_term, &[]),
            start("a", b"", b"", &long_modes),
        ] {
            assert_eq!(parse_request(&record), Err(truncated()));
        }
    }

    #[test]
    fn field_rules() {
        let start = |account: &str, term: &[u8], modes: &[u8]| {
            encode_request(&Request::Start {
                account,
                session: Session::Shell {
                    pty: Some(PtyRequest {
                        term,
                        size: SIZE,
                        modes,
                    }),
                },
            })
        };
        assert_eq!(
            parse_request(&start("", b"", &[])),
            Err(Malformed("account name empty or not UTF-8"))
        );
        assert_eq!(
            parse_request(&start("a", b"x/y", &[])),
            Err(Malformed("TERM outside ADR-0038 §2's rule"))
        );
        // Opcode 1 (VINTR) takes a uint32; two bytes are a truncated one.
        assert_eq!(
            parse_request(&start("a", b"", &[1, 0, 0])),
            Err(Malformed("terminal modes truncated"))
        );
        let mut non_utf8 = encode_request(&Request::Start {
            account: "ab",
            session: Session::Sftp,
        });
        non_utf8[6] = 0xff;
        assert_eq!(
            parse_request(&non_utf8),
            Err(Malformed("account name empty or not UTF-8"))
        );
    }

    #[test]
    fn records_that_break_the_framing_are_malformed() {
        assert_eq!(parse_request(&[]), Err(Malformed("empty record")));
        assert_eq!(parse_request(&[0]), Err(Malformed("unknown message type")));
        assert_eq!(
            parse_request(&[LISTENER]),
            Err(Malformed("unknown message type"))
        );
        assert_eq!(parse_request(&[READY, 0]), Err(Malformed("trailing bytes")));
        assert_eq!(parse_request(&[END, 0, 0]), Err(truncated()));
        // A command on a shell: its bytes misparse or trail.
        let mut w = Writer::new();
        w.put_byte(START);
        w.put_string(b"a");
        w.put_byte(SHELL);
        w.put_boolean(false);
        w.put_string(b"uptime");
        assert_eq!(
            parse_request(&w.into_bytes()),
            Err(Malformed("trailing bytes"))
        );
        // A PTY flag on sftp: one byte too many.
        let mut sftp = encode_request(&Request::Start {
            account: "a",
            session: Session::Sftp,
        });
        sftp.push(0);
        assert_eq!(parse_request(&sftp), Err(Malformed("trailing bytes")));
        let mut kind = encode_request(&Request::Start {
            account: "a",
            session: Session::Sftp,
        });
        *kind.last_mut().unwrap() = 9;
        assert_eq!(parse_request(&kind), Err(Malformed("unknown session kind")));
        let mut over = largest_start();
        over.resize(MAX_RECORD + 1, 0);
        assert_eq!(
            parse_request(&over),
            Err(Malformed("record over its bound"))
        );
    }

    /// The fuzz seeds that `scripts/fuzz-seeds.py` writes are what this
    /// parser reads: every one parses, except the empty record.
    #[test]
    fn the_fuzz_seeds_parse() {
        let seeds = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fuzz/seeds/launcher_request"
        );
        let mut seen = 0;
        for entry in std::fs::read_dir(seeds).expect("seed directory") {
            let path = entry.expect("seed").path();
            let record = std::fs::read(&path).expect("seed bytes");
            let parsed = parse_request(&record);
            if record.is_empty() {
                assert_eq!(parsed, Err(Malformed("empty record")));
            } else {
                assert!(parsed.is_ok(), "{}: {parsed:?}", path.display());
            }
            seen += 1;
        }
        assert!(seen >= 7, "{seen} seeds");
    }

    #[test]
    fn replies_that_break_the_protocol_are_malformed() {
        assert_eq!(
            parse_reply(&[REFUSED, 6]),
            Err(Malformed("unknown refusal reason"))
        );
        let mut exited = encode_reply(&Reply::Exited {
            session: 1,
            exit: Exit::Code(0),
        });
        exited[9] = 3;
        assert_eq!(parse_reply(&exited), Err(Malformed("unknown exit kind")));
        // An exit code never dumps core.
        let mut cored = encode_reply(&Reply::Exited {
            session: 1,
            exit: Exit::Code(0),
        });
        *cored.last_mut().unwrap() = 1;
        assert_eq!(parse_reply(&cored), Err(Malformed("unknown exit kind")));
        assert_eq!(
            parse_reply(&[READY]),
            Err(Malformed("unknown message type"))
        );
        assert_eq!(
            parse_reply(&[LISTENER, 0]),
            Err(Malformed("trailing bytes"))
        );
    }
}
