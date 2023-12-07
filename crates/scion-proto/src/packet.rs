//! Representation of SCION packet and constituent types.
//!
//! This module contains an implementation of the SCION packet representation, its wire
//! format, and errors encountered while decoding the packet.
//!
//! For paths useable in a SCION packet, see the [path module][`crate::path`].

pub mod error;
pub use error::{DecodeError, EncodeError, InadequateBufferSize};

pub mod headers;
pub use headers::{
    AddressHeader,
    AddressInfo,
    ByEndpoint,
    CommonHeader,
    FlowId,
    RawHostAddress,
    ScionHeaders,
    Version,
};

pub mod raw;
pub use raw::ScionPacketRaw;

pub mod udp;
pub use udp::ScionPacketUdp;

mod checksum;
pub use checksum::ChecksumDigest;
