//! SCION addresses for ISDs, ASes, hosts, and sockets.
//!
//! This module provides end-host networking addresses for the SCION Internet architecture.
//!
//! # Organisation
//!
//! - An [`IsdAsn`] globally identifies an AS within the SCION network, and consists of an ISD
//!   identifier ([`Isd`]) and AS number ([`Asn`]).
//! - A [`HostAddr`] represents an AS-specific host addresses of either a IPv4, IPv6, or Service host;
//!   [`std::net::Ipv4Addr`], [`std::net::Ipv6Addr`], and [`ServiceAddr`] are their respective addresses.
//! - The above combined are a [`ScionAddr`], which is the globally-routeable address of IPv4, IPv6, or
//!   Service hosts in the SCION network; [`SocketAddrV4`], [`SocketAddrV6`], and [`ScionAddrSvc`] are the
//!   respective addresses.
//! - [`SocketAddr`] is a [`ScionAddr`] with an associated port, and is used for UDP application
//!   addressing; the respective IPv4, IPv6, and service types are [`SocketAddrV4`], [`SocketAddrV6`],
//!   and [`SocketAddrSvc`].

mod asn;
pub use asn::Asn;

mod isd;
pub use isd::Isd;

mod ia;
pub use ia::IsdAsn;

mod service;
pub use service::ServiceAddr;

mod host;
pub use host::{HostAddr, HostType};

mod socket_address;
pub use socket_address::{SocketAddr, SocketAddrSvc, SocketAddrV4, SocketAddrV6};

mod scion_address;
pub use scion_address::{ScionAddr, ScionAddrSvc, ScionAddrV4, ScionAddrV6};

mod error;
pub use error::AddressParseError;
