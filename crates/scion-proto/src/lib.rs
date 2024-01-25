//! Protocol-level types for an endhost in the SCION Internet architecture
//!
//! [SCION][scion-net] is an Internet architecture that provides path-aware, end-to-end
//! communication, with failure isolation and explicit trust information. Within the SCION network,
//! [*autonomous systems* (ASes)](https://docs.scion.org/en/latest/glossary.html#term-AS), in which
//! endhosts reside, are organized into independent routing groups called
//! [*isolation domains* (ISDs)][isd].
//!
//! This crate provides Rust implementations of the core types used by endhosts within the SCION
//! network:
//!
//! - [addresses][address] which identify ISDs, ASes, and endhosts;
//! - [paths][path] which allow a user to choose the route taken by their packets through the
//!   network and provide information about those routes;
//! - [SCION packet][packet] and [UDP datagram][datagram] implementations for encoding packets on
//!   the wire;
//! - [control messages][scmp] for sending informational and error control messages to endhosts and
//!   routers in the network; and
//! - [parsing logic][reliable] for the endhost-to-SCION-dispatcher communication.
//!
//! This crate does not perform any I/O. See the [**scion**](../scion/index.html) crate for
//! (asynchronous) socket implementations that use these types.
//!
//! [scion-net]: https://scion-architecture.net/
//! [scionproto-github]: https://github.com/scionproto/scion
//! [isd]: https://docs.scion.org/en/latest/overview.html#isolation-domains-isds

pub mod address;
pub mod datagram;
pub mod packet;
pub mod path;
pub mod reliable;
pub mod scmp;
pub mod wire_encoding;

pub(crate) mod utils;

#[cfg(test)]
pub(crate) mod test_utils;
