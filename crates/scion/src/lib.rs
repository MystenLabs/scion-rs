//! End-host networking stack for the SCION Internet architecture.
//!
//! This crate contains all asynchronous code required to interact with SCION components, instantiate sockets,
//! and send SCION packets.
//!
//! # Organization
//!
//! - [daemon] contains a [`DaemonClient`][daemon::DaemonClient] to interact with the SCION daemon.
//! - [dispatcher] contains a [`DispatcherStream`][dispatcher::DispatcherStream] to send and receive packets
//!   via the SCION dispatcher. It is normally not necessary to use this directly as the [`pan`] and [socket]
//!   modules have tools with more convenient interfaces.
//! - [pan] contains services and strategies to manage paths as well as a datagram socket that includes this
//!   path management.
//! - [socket] contains a simple [UDP socket][socket::UdpSocket] and a [raw socket][socket::RawSocket] that
//!   can be used to send an receive SCMP informational messages (see
//!   [`ScmpMessage`][scion_proto::scmp::ScmpMessage]).

pub mod daemon;
pub mod dispatcher;
pub mod pan;
pub mod socket;
