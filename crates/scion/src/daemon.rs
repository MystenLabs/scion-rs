//! Communicate with the local SCION daemon.
//!
//! This module provides a convenient [`DaemonClient`] to communicate with the local [SCION daemon][daemon].
//! It uses the automatically generated gRPC code in the [scion_grpc] crate.
//!
//! The daemon address can be configured using the environment variable specified in the constant
//! [`DAEMON_ADDRESS_ENV_VARIABLE`] if it differs from the default value stored in
//! [`DEFAULT_DAEMON_ADDRESS`].
//!
//! [daemon]: https://docs.scion.org/en/latest/manuals/daemon.html

mod messages;
pub use messages::{AsInfo, PathRequest, PathRequestFlags};

mod client;
pub use client::{
    get_daemon_address,
    DaemonClient,
    DaemonClientError,
    DAEMON_ADDRESS_ENV_VARIABLE,
    DEFAULT_DAEMON_ADDRESS,
};
