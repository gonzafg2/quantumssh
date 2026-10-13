//! #200: running out of descriptors pauses the accept loop instead of
//! ending the server.
//!
//! The test lowers this process's `RLIMIT_NOFILE`, so it lives in its own
//! test binary, alone: no other test shares the process.

mod support;

use support::*;

use quantumssh_core::admission::Limits;
use quantumssh_core::transport::RekeyThresholds;
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use tokio::time::{Duration, sleep, timeout};

#[tokio::test]
async fn running_out_of_descriptors_pauses_accepting_instead_of_ending_the_server() {
    let budget = Duration::from_secs(30);
    let limits = Limits {
        max_connections: 64,
        max_half_open: 64,
        max_per_source: 64,
        accept_rate: 64,
        accept_burst: 64,
    };
    let (addr, _host_key, tx, serve) =
        start_server_full(budget, RekeyThresholds::bsi_defaults(budget), limits).await;

    // Fill the descriptor table to its last free slot. The client socket
    // below takes that slot, so the server's accept() of the connection
    // finds none: EMFILE.
    let saved = getrlimit(Resource::Nofile);
    let open = std::fs::read_dir("/dev/fd").expect("list fds").count() as u64;
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(open + 16),
            maximum: saved.maximum,
        },
    )
    .expect("lower the soft limit");
    let mut filler = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        filler.push(file);
    }
    assert!(!filler.is_empty(), "the lowered limit left no room");
    drop(filler.pop());
    let pending = connect(addr).await;

    // The server tries to accept, fails with EMFILE, and must keep going.
    sleep(Duration::from_millis(300)).await;
    assert!(!serve.is_finished(), "the accept loop ended on EMFILE");

    // Free the descriptors: within the pause, accepting resumes.
    drop(filler);
    drop(pending);
    setrlimit(Resource::Nofile, saved).expect("restore the soft limit");
    let mut fresh = connect(addr).await;
    let id = timeout(Duration::from_secs(5), read_server_id(&mut fresh))
        .await
        .expect("the server accepts again after the pause");
    assert!(id.starts_with(b"SSH-2.0-"), "{id:?}");
    drop(fresh);

    tx.send(tokio::time::Instant::now() + Duration::from_secs(5))
        .expect("send shutdown");
    let result = timeout(Duration::from_secs(10), serve)
        .await
        .expect("serve returns")
        .expect("join serve");
    result.expect("clean shutdown");
}
