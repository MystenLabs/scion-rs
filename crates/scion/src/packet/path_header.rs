use bytes::{Buf, Bytes};

use super::DecodeError;
use crate::{
    path::standard::StandardPath,
    wire_encoding::{MaybeEncoded, WireDecodeWithContext},
};

/// SCION path types that may be encountered in a packet
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PathType {
    /// The empty path type.
    Empty = 0,
    /// The standard SCION path type.
    Scion,
    /// One-hop paths between neighbouring border routers.
    OneHop,
    /// Experimental Epic path type.
    Epic,
    /// Experimental Colibri path type.
    Colibri,
}

impl From<PathType> for u8 {
    fn from(value: PathType) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for PathType {
    type Error = UnsupportedPathType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Scion),
            2 => Ok(Self::OneHop),
            3 => Ok(Self::Epic),
            4 => Ok(Self::Colibri),
            _ => Err(UnsupportedPathType(value)),
        }
    }
}

impl From<u8> for MaybeEncoded<PathType, u8> {
    fn from(value: u8) -> Self {
        match PathType::try_from(value) {
            Ok(path_type) => MaybeEncoded::Decoded(path_type),
            Err(UnsupportedPathType(raw)) => MaybeEncoded::Encoded(raw),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported path type {0}")]
pub struct UnsupportedPathType(pub u8);

/// Path header found in a SCION packet
pub enum PathHeader {
    /// The standard SCION path header.
    Standard(StandardPath),
    /// The raw bytes of an unsupported path header type.
    Unsupported(Bytes),
}

impl From<StandardPath> for PathHeader {
    fn from(value: StandardPath) -> Self {
        PathHeader::Standard(value)
    }
}

impl<T> WireDecodeWithContext<T> for PathHeader
where
    T: Buf,
{
    type Error = DecodeError;
    type Context = (MaybeEncoded<PathType, u8>, usize);

    fn decode_with_context(
        data: &mut T,
        type_and_length: (MaybeEncoded<PathType, u8>, usize),
    ) -> Result<Self, Self::Error> {
        let (path_type, path_length) = type_and_length;
        if data.remaining() < path_length {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }

        match path_type {
            MaybeEncoded::Decoded(PathType::Empty) => Err(Self::Error::EmptyPath),
            MaybeEncoded::Decoded(PathType::Scion) => {
                Ok(StandardPath::decode_with_context(data, path_length)?.into())
            }
            MaybeEncoded::Decoded(_) | MaybeEncoded::Encoded(_) => {
                Ok(PathHeader::Unsupported(data.copy_to_bytes(path_length)))
            }
        }
    }
}
