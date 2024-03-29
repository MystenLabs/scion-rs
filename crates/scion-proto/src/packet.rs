//! Representation of SCION packet and constituent types.
//!
//! This module contains an implementation of the SCION packet representation, its wire
//! format, and errors encountered while decoding the packet.
//!
//! For paths useable in a SCION packet, see the [path module][`crate::path`].
use bytes::Bytes;

mod error;
pub use error::{DecodeError, EncodeError, InadequateBufferSize, ScmpEncodeError};

mod headers;
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

mod raw;
pub use raw::ScionPacketRaw;

mod scmp;
pub use scmp::ScionPacketScmp;

mod udp;
pub use udp::ScionPacketUdp;

mod checksum;
pub use checksum::{ChecksumDigest, MessageChecksum};

use crate::wire_encoding::{WireDecode, WireEncodeVec};

/// All SCION packet types must implement this trait.
pub trait ScionPacket<const N: usize>: WireEncodeVec<N> + WireDecode<Bytes> {}
