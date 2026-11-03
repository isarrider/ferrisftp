//! A whole session on arbitrary input: framing, the INIT handshake, every
//! request parser and the extension dispatcher.
//!
//! The server runs in read-only mode so that random requests cannot create,
//! change or delete files on the machine running the fuzzer. Requests that
//! read (stat, opendir, readlink, realpath, statvfs, user lookups, …) still
//! execute for real.

#![no_main]

use std::io::{Cursor, sink};
use std::sync::Once;

use ferrisftp::Server;
use ferrisftp::policy::Policy;
use libfuzzer_sys::fuzz_target;

/// INIT for protocol version 3, so most inputs get past the handshake.
const INIT: [u8; 9] = [0, 0, 0, 5, 1, 0, 0, 0, 3];

fuzz_target!(|data: &[u8]| {
    static CHDIR: Once = Once::new();
    CHDIR.call_once(|| {
        // Relative paths in requests resolve inside an empty scratch dir.
        let dir = std::env::temp_dir().join("ferrisftp-fuzz");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::env::set_current_dir(&dir);
    });

    let mut policy = Policy::default();
    policy.read_only = true;

    // With and without a valid handshake in front.
    for prefix in [&INIT[..], &[][..]] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(data);
        let _ = Server::with_policy(policy.clone()).run(Cursor::new(input), sink());
    }
});
