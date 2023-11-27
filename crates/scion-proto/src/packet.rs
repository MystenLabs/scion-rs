//! Representation of SCION packet and constituent types.
//!
//! This module contains an implementation of the SCION packet representation, its wire
//! format, and errors encountered while decoding the packet.
//!
//! For paths useable in a SCION packet, see the [path module][`crate::path`].

use bytes::{Buf, Bytes};

use crate::{
    path::DataplanePathErrorKind,
    wire_encoding::{WireDecode, WireDecodeWithContext},
};

mod common_header;
pub use common_header::{AddressInfo, CommonHeader, FlowId, Version};

mod address_header;
pub use address_header::{AddressHeader, RawHostAddress};

mod path_header;
pub use path_header::PathHeader;

/// Instances of an object associated with both a source and destination endpoint.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ByEndpoint<T> {
    pub destination: T,
    pub source: T,
}

/// A SCION network packet.
#[allow(unused)]
pub struct ScionPacket {
    /// Metadata about the remaining headers and payload.
    pub common_header: CommonHeader,
    /// Source and destination addresses.
    pub address_header: AddressHeader,
    /// The path to the destination, when necessary.
    pub path_header: Option<PathHeader>,
    /// The packet payload.
    pub payload: Bytes,
}

impl<T> WireDecode<T> for ScionPacket
where
    T: Buf,
{
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        let common_header = CommonHeader::decode(data)?;

        // Limit the data for headers to the length specified by the common header
        let mut header_data = data.take(common_header.remaining_header_length());

        let address_header =
            AddressHeader::decode_with_context(&mut header_data, common_header.address_info)?;

        let path_context = (common_header.path_type, header_data.remaining());
        let path_header = match PathHeader::decode_with_context(&mut header_data, path_context) {
            Err(DecodeError::EmptyPath) => None,
            other => Some(other?),
        };

        // The path header consumes all the remaining header bytes
        debug_assert_eq!(header_data.remaining(), 0);

        if data.remaining() < common_header.payload_size() {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }

        let payload = data.copy_to_bytes(common_header.payload_size());

        Ok(Self {
            common_header,
            address_header,
            path_header,
            payload,
        })
    }
}

/// Errors raised when failing to decode a [`ScionPacket`] or its constituents.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    #[error("cannot decode packet with unsupported header version {0:?}")]
    UnsupportedVersion(Version),
    #[error("header length factor is inconsistent with the SCION specification: {0}")]
    InvalidHeaderLength(u8),
    #[error("the provided bytes did not include the full packet")]
    PacketEmptyOrTruncated,
    #[error("attempted to decode the empty path type")]
    EmptyPath,
    #[error("invalid path header: {0}")]
    InvalidPath(DataplanePathErrorKind),
}

impl From<DataplanePathErrorKind> for DecodeError {
    fn from(value: DataplanePathErrorKind) -> Self {
        Self::InvalidPath(value)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
#[error("the provided buffer did not have sufficient size")]
pub struct InadequateBufferSize;
