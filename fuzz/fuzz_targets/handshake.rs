//! The transport over an in-memory stream: the identification-line
//! reader, plaintext framing, and every stage transition through the
//! peer's `SSH_MSG_NEWKEYS`. Input after that meets the AEAD, which
//! `sealed_frame` covers.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantumssh_core::host_key::HostKey;
use quantumssh_core::transport;
use quantumssh_fuzz::HOST_KEY_SEEDS;
use std::sync::LazyLock;
use tokio::runtime::{Builder, Runtime};

static HOST_KEY: LazyLock<HostKey> = LazyLock::new(|| HostKey::from_seeds(&HOST_KEY_SEEDS));

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
});

fuzz_target!(|data: &[u8]| {
    RUNTIME.block_on(async {
        let stream = tokio::io::join(data, tokio::io::sink());
        let Ok(kexinit) = transport::version_exchange(stream).await else {
            return;
        };
        let Ok(hybrid) = kexinit.exchange_kexinit().await else {
            return;
        };
        let Ok(newkeys) = hybrid.run_hybrid(&HOST_KEY).await else {
            return;
        };
        let _ = newkeys.exchange_newkeys().await;
    });
});
