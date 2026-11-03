//! ferrisftp — an SFTP version 3 server that runs as an SSH subsystem.
//!
//! The SSH server (Dropbear or OpenSSH) handles the network, authentication
//! and encryption, then runs this program as the logged-in user with the
//! SFTP stream on stdin/stdout.

pub mod attrs;
pub mod extensions;
pub mod handles;
pub mod longname;
pub mod pipeline;
pub mod protocol;
pub mod server;
pub mod sys;
pub mod wire;

pub use server::Server;
