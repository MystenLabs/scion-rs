//! Tools to communicate with the local SCION daemon.

mod messages;
pub use messages::{AsInfo, PathRequest};

pub mod client;
pub use client::{get_daemon_address, DaemonClient, DaemonClientError};
