//! Connection admission control (ADR-0028): the four checks the accept
//! loop runs before spawning a connection task, and the RAII guards
//! that release what they took.
//!
//! Check order is load-bearing (ADR-0028): the three non-mutating cap
//! reads first, the state-mutating per-source rate limit last, so a
//! connection refused by a cap never touches or grows the per-source
//! map — the load-shedding order for a rotating-source flood. The
//! first check that fails names the structured `limit` field on the
//! `connection.refused` event.
//!
//! A connection counts as **half-open** from TCP accept until userauth
//! success; [`ConnectionGuard::mark_authenticated`] ends that span
//! while the global slot stays held until the guard drops with the
//! connection task (panic included — the guard is RAII).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The ADR-0028 admission knobs, config-driven (`[limits]`, ADR-0029
/// schema conventions) with the ADR's documented defaults.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Global concurrent-connection cap, any auth state.
    pub max_connections: usize,
    /// Total half-open (pre-auth) cap — OpenSSH `MaxStartups` hard cap.
    pub max_half_open: usize,
    /// Per-source half-open cap.
    pub max_per_source: usize,
    /// Per-source token-bucket refill, tokens per second.
    pub accept_rate: u32,
    /// Per-source token-bucket capacity (burst).
    pub accept_burst: u32,
}

impl Default for Limits {
    /// ADR-0028 defaults: 256 / 100 / 10, burst 10 at 1 token/s —
    /// anchored on OpenSSH prior art, not yet validated under load.
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_half_open: 100,
            max_per_source: 10,
            accept_rate: 1,
            accept_burst: 10,
        }
    }
}

/// Which admission check refused the connection. The wire value of the
/// `limit` field on `connection.refused` — names match the `[limits]`
/// config keys so the event points at the knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Global concurrent-connection cap.
    MaxConnections,
    /// Total half-open cap.
    MaxHalfOpen,
    /// Per-source half-open cap.
    MaxPerSource,
    /// Per-source accept rate limit.
    AcceptRate,
}

impl Refusal {
    /// The structured field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxConnections => "max_connections",
            Self::MaxHalfOpen => "max_half_open",
            Self::MaxPerSource => "max_per_source",
            Self::AcceptRate => "accept_rate",
        }
    }
}

/// Integer token bucket (no floats, no drift): `level` tokens plus the
/// timestamp of the last refill accounting; partial-second remainders
/// are preserved by advancing `refilled_at` only by the time the added
/// tokens represent.
#[derive(Debug)]
struct Bucket {
    level: u32,
    refilled_at: Instant,
}

impl Bucket {
    const fn full(limits: &Limits, now: Instant) -> Self {
        Self {
            level: limits.accept_burst,
            refilled_at: now,
        }
    }

    fn refill(&mut self, limits: &Limits, now: Instant) {
        let elapsed_ms =
            u64::try_from(now.duration_since(self.refilled_at).as_millis()).unwrap_or(u64::MAX);
        let added = elapsed_ms.saturating_mul(u64::from(limits.accept_rate)) / 1000;
        if added == 0 {
            return;
        }
        let capped = u32::try_from(added.min(u64::from(limits.accept_burst))).unwrap_or(u32::MAX);
        self.level = (self.level + capped).min(limits.accept_burst);
        if self.level == limits.accept_burst {
            // Full: the remainder is irrelevant, reset the clock.
            self.refilled_at = now;
        } else {
            // Advance only by the time the added tokens represent, so
            // sub-second remainders keep accruing.
            self.refilled_at += std::time::Duration::from_millis(
                added.saturating_mul(1000) / u64::from(limits.accept_rate),
            );
        }
    }

    fn try_take(&mut self, limits: &Limits, now: Instant) -> bool {
        self.refill(limits, now);
        if self.level == 0 {
            return false;
        }
        self.level -= 1;
        true
    }

    fn is_full(&mut self, limits: &Limits, now: Instant) -> bool {
        self.refill(limits, now);
        self.level == limits.accept_burst
    }
}

/// Per-source accounting: live half-open count plus the rate bucket.
#[derive(Debug)]
struct SourceState {
    half_open: usize,
    bucket: Bucket,
}

/// The shared admission state. One mutex over everything: only the
/// accept loop admits, guards release from connection tasks, and the
/// critical sections are a few integer operations — contention is not
/// a concern at the cap scale (ADR-0028's 256).
#[derive(Debug, Default)]
struct State {
    connections: usize,
    half_open: usize,
    sources: HashMap<IpAddr, SourceState>,
    admissions_since_sweep: u32,
}

/// Amortised map sweep: every this many `try_admit` calls, prunable
/// sources (no connections, full bucket) are dropped even if their
/// last guard fell while the bucket was still refilling.
const SWEEP_INTERVAL: u32 = 64;

/// Admission control for one listener (ADR-0028).
#[derive(Debug)]
pub struct Admission {
    limits: Limits,
    state: Arc<Mutex<State>>,
}

/// The per-source aggregation key: IPv4 by address, IPv6 by /64 — a
/// single IPv6 host trivially holds a /64, so finer granularity would
/// make the caps trivially evadable (ADR-0028). V4-mapped V6 addresses
/// canonicalise to their V4 form first.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            segments[4..].fill(0);
            IpAddr::V6(segments.into())
        }
    }
}

impl Admission {
    /// New admission state for the given limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Runs the four checks in the ADR-0028 order for a connection from
    /// `ip`, taking the slots on success. The guard releases them.
    ///
    /// # Panics
    ///
    /// If the admission mutex is poisoned (a panic while holding it).
    ///
    /// # Errors
    ///
    /// Returns the first check that failed; nothing was taken and the
    /// per-source map was not touched unless all three caps passed.
    pub fn try_admit(&self, ip: IpAddr, now: Instant) -> Result<ConnectionGuard, Refusal> {
        let key = source_key(ip);
        let mut state = self.state.lock().expect("admission mutex poisoned");
        // Amortised prune (ADR-0028): the drop-time prune misses a
        // source whose last guard fell while its bucket was refilling
        // — nothing would ever revisit it. O(sources) every
        // SWEEP_INTERVAL admissions bounds the steady state.
        state.admissions_since_sweep += 1;
        if state.admissions_since_sweep >= SWEEP_INTERVAL {
            state.admissions_since_sweep = 0;
            let limits = self.limits;
            state
                .sources
                .retain(|_, s| s.half_open > 0 || !s.bucket.is_full(&limits, now));
        }
        // 1–3: non-mutating cap reads.
        if state.connections >= self.limits.max_connections {
            return Err(Refusal::MaxConnections);
        }
        if state.half_open >= self.limits.max_half_open {
            return Err(Refusal::MaxHalfOpen);
        }
        if let Some(source) = state.sources.get(&key)
            && source.half_open >= self.limits.max_per_source
        {
            return Err(Refusal::MaxPerSource);
        }
        // 4: the state-mutating rate check, last — a cap refusal never
        // charges the source's bucket or creates its entry.
        let source = state.sources.entry(key).or_insert_with(|| SourceState {
            half_open: 0,
            bucket: Bucket::full(&self.limits, now),
        });
        if !source.bucket.try_take(&self.limits, now) {
            return Err(Refusal::AcceptRate);
        }
        source.half_open += 1;
        state.connections += 1;
        state.half_open += 1;
        drop(state);
        Ok(ConnectionGuard {
            limits: self.limits,
            state: Arc::clone(&self.state),
            source: key,
            authenticated: AtomicBool::new(false),
        })
    }
}

/// RAII for one admitted connection (ADR-0028).
///
/// Holds a global slot for its whole life and a half-open slot until
/// [`Self::mark_authenticated`]. Drop releases whatever is still held,
/// so a panicking handler frees its slots.
#[derive(Debug)]
pub struct ConnectionGuard {
    limits: Limits,
    state: Arc<Mutex<State>>,
    source: IpAddr,
    authenticated: AtomicBool,
}

impl ConnectionGuard {
    /// Ends the half-open span: userauth succeeded. Idempotent.
    ///
    /// # Panics
    ///
    /// If the admission mutex is poisoned (a panic while holding it).
    pub fn mark_authenticated(&self) {
        if self.authenticated.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut state = self.state.lock().expect("admission mutex poisoned");
        state.half_open = state.half_open.saturating_sub(1);
        if let Some(source) = state.sources.get_mut(&self.source) {
            source.half_open = source.half_open.saturating_sub(1);
        }
    }

    /// Whether userauth has succeeded — the shutdown path snapshots
    /// this to pick immediate-disconnect vs drain (ADR-0028).
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated.load(Ordering::SeqCst)
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.state.lock().expect("admission mutex poisoned");
        state.connections = state.connections.saturating_sub(1);
        let ended_half_open = !self.authenticated.load(Ordering::SeqCst);
        if ended_half_open {
            state.half_open = state.half_open.saturating_sub(1);
        }
        // Prune rule (ADR-0028): a source leaves the map when it holds
        // no connections and its bucket is full.
        if let Some(source) = state.sources.get_mut(&self.source) {
            if ended_half_open {
                source.half_open = source.half_open.saturating_sub(1);
            }
            if source.half_open == 0 && source.bucket.is_full(&self.limits, Instant::now()) {
                state.sources.remove(&self.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::*;

    fn limits() -> Limits {
        Limits {
            max_connections: 4,
            max_half_open: 3,
            max_per_source: 2,
            accept_rate: 1,
            accept_burst: 10,
        }
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn admits_up_to_the_per_source_cap_then_refuses() {
        let a = Admission::new(limits());
        let now = Instant::now();
        let _g1 = a.try_admit(v4(1), now).expect("first");
        let _g2 = a.try_admit(v4(1), now).expect("second");
        assert_eq!(a.try_admit(v4(1), now).unwrap_err(), Refusal::MaxPerSource);
        // A different source still gets in.
        let _g3 = a.try_admit(v4(2), now).expect("other source");
    }

    #[test]
    fn total_half_open_cap_refuses_across_sources() {
        let a = Admission::new(limits());
        let now = Instant::now();
        let _g1 = a.try_admit(v4(1), now).expect("1");
        let _g2 = a.try_admit(v4(2), now).expect("2");
        let _g3 = a.try_admit(v4(3), now).expect("3");
        assert_eq!(a.try_admit(v4(4), now).unwrap_err(), Refusal::MaxHalfOpen);
    }

    #[test]
    fn authenticated_connections_leave_half_open_but_hold_the_global_cap() {
        let a = Admission::new(limits());
        let now = Instant::now();
        let g1 = a.try_admit(v4(1), now).expect("1");
        let g2 = a.try_admit(v4(1), now).expect("2");
        g1.mark_authenticated();
        g2.mark_authenticated();
        // Half-open freed: the same source admits again...
        let g3 = a.try_admit(v4(1), now).expect("3");
        let g4 = a.try_admit(v4(1), now).expect("4");
        g3.mark_authenticated();
        g4.mark_authenticated();
        // ...but the global cap (4) still counts them all.
        assert_eq!(
            a.try_admit(v4(9), now).unwrap_err(),
            Refusal::MaxConnections
        );
    }

    #[test]
    fn drop_releases_the_slots() {
        let a = Admission::new(limits());
        let now = Instant::now();
        let g1 = a.try_admit(v4(1), now).expect("1");
        let _g2 = a.try_admit(v4(1), now).expect("2");
        drop(g1);
        let _g3 = a.try_admit(v4(1), now).expect("slot freed by drop");
    }

    #[test]
    fn rate_limit_refuses_after_the_burst_and_refills_over_time() {
        let mut l = limits();
        l.max_connections = 100;
        l.max_half_open = 100;
        l.max_per_source = 100;
        l.accept_burst = 2;
        let a = Admission::new(l);
        let now = Instant::now();
        let g1 = a.try_admit(v4(1), now).expect("burst 1");
        let g2 = a.try_admit(v4(1), now).expect("burst 2");
        drop((g1, g2));
        assert_eq!(a.try_admit(v4(1), now).unwrap_err(), Refusal::AcceptRate);
        // 1 token/s: one second later exactly one more gets in.
        let later = now + Duration::from_secs(1);
        let _g3 = a.try_admit(v4(1), later).expect("refilled");
        assert_eq!(a.try_admit(v4(1), later).unwrap_err(), Refusal::AcceptRate);
    }

    #[test]
    fn sub_second_refill_remainders_accrue() {
        let mut l = limits();
        l.accept_burst = 1;
        let a = Admission::new(l);
        let now = Instant::now();
        drop(a.try_admit(v4(1), now).expect("take the only token"));
        // Two 500 ms waits must add up to the 1 s a token costs.
        let half = now + Duration::from_millis(500);
        assert_eq!(a.try_admit(v4(1), half).unwrap_err(), Refusal::AcceptRate);
        let full = now + Duration::from_secs(1);
        drop(a.try_admit(v4(1), full).expect("remainder accrued"));
    }

    #[test]
    fn cap_refusal_does_not_create_or_charge_the_source() {
        let a = Admission::new(limits());
        let now = Instant::now();
        // Saturate the total half-open cap from three sources.
        let _g1 = a.try_admit(v4(1), now).expect("1");
        let _g2 = a.try_admit(v4(2), now).expect("2");
        let _g3 = a.try_admit(v4(3), now).expect("3");
        // A fourth source is refused by the cap (check 2)...
        assert_eq!(a.try_admit(v4(4), now).unwrap_err(), Refusal::MaxHalfOpen);
        // ...and its entry was never created (check 4 never ran).
        assert!(!a.state.lock().expect("mutex").sources.contains_key(&v4(4)));
    }

    #[test]
    fn idle_source_is_pruned_at_drop_once_its_bucket_refilled() {
        let a = Admission::new(limits());
        // Admitted "30 s ago": by real drop time the bucket has long
        // since refilled, so the drop-path prune fires.
        let past = Instant::now()
            .checked_sub(Duration::from_secs(30))
            .expect("test clock");
        let g = a.try_admit(v4(1), past).expect("admit");
        drop(g);
        assert!(!a.state.lock().expect("mutex").sources.contains_key(&v4(1)));
    }

    #[test]
    fn sweep_prunes_sources_the_drop_path_missed() {
        let mut l = limits();
        l.max_connections = 1000;
        l.max_half_open = 1000;
        l.max_per_source = 1000;
        l.accept_burst = 100;
        let a = Admission::new(l);
        let now = Instant::now();
        // Source 1's guard drops while its bucket is still refilling:
        // the drop-path prune cannot fire and the entry lingers.
        drop(a.try_admit(v4(1), now).expect("admit"));
        assert!(a.state.lock().expect("mutex").sources.contains_key(&v4(1)));
        // SWEEP_INTERVAL admissions later — at a fabricated future
        // instant where source 1's bucket is full again — it is gone.
        let later = now + Duration::from_secs(61);
        for _ in 0..SWEEP_INTERVAL {
            drop(a.try_admit(v4(2), later).expect("sweep traffic"));
        }
        assert!(!a.state.lock().expect("mutex").sources.contains_key(&v4(1)));
    }

    #[test]
    fn ipv6_sources_aggregate_by_slash_64() {
        let a = Admission::new(limits());
        let now = Instant::now();
        let host_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let host_b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0xdead, 0xbeef, 0, 2));
        let other_net = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        let _g1 = a.try_admit(host_a, now).expect("first in /64");
        let _g2 = a.try_admit(host_b, now).expect("second in /64");
        // Same /64: the per-source cap (2) is shared.
        assert_eq!(a.try_admit(host_a, now).unwrap_err(), Refusal::MaxPerSource);
        // A different /64 is a different source.
        let _g3 = a.try_admit(other_net, now).expect("other /64");
    }
}
