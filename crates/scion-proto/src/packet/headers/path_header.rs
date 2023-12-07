use bytes::{Buf, BufMut, Bytes};

use crate::{
    packet::{DecodeError, InadequateBufferSize},
    path::standard::StandardPath,
    wire_encoding::{WireDecode, WireDecodeWithContext, WireEncode},
};

/// SCION path types that may be encountered in a packet
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PathType {
    /// The empty path type.
    Empty,
    /// The standard SCION path type.
    Scion,
    /// One-hop paths between neighbouring border routers.
    OneHop,
    /// Experimental Epic path type.
    Epic,
    /// Experimental Colibri path type.
    Colibri,
    /// Other, unrecognised path types
    Other(u8),
}

impl From<PathType> for u8 {
    fn from(value: PathType) -> Self {
        match value {
            PathType::Empty => 0,
            PathType::Scion => 1,
            PathType::OneHop => 2,
            PathType::Epic => 3,
            PathType::Colibri => 4,
            PathType::Other(value) => value,
        }
    }
}

impl From<u8> for PathType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Empty,
            1 => Self::Scion,
            2 => Self::OneHop,
            3 => Self::Epic,
            4 => Self::Colibri,
            value => Self::Other(value),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported path type {0}")]
pub struct UnsupportedPathType(pub u8);

/// Dataplane path found in a SCION packet
#[derive(Debug, Clone, PartialEq)]
pub enum DataplanePath {
    /// The empty path type, used for intra-AS hops
    EmptyPath,
    /// The standard SCION path header.
    Standard(StandardPath),
    /// The raw bytes of an unsupported path header type.
    Unsupported { path_type: PathType, bytes: Bytes },
}

impl DataplanePath {
    pub fn deep_copy(&self) -> Self {
        match self {
            Self::EmptyPath => Self::EmptyPath,
            Self::Standard(path) => Self::Standard(path.deep_copy()),
            Self::Unsupported { path_type, bytes } => Self::Unsupported {
                path_type: *path_type,
                bytes: Bytes::copy_from_slice(bytes),
            },
        }
    }

    pub fn path_type(&self) -> PathType {
        match self {
            Self::EmptyPath => PathType::Empty,
            Self::Standard(_) => PathType::Scion,
            Self::Unsupported { path_type, .. } => *path_type,
        }
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::EmptyPath
    }
}

impl From<StandardPath> for DataplanePath {
    fn from(value: StandardPath) -> Self {
        Self::Standard(value)
    }
}

impl WireEncode for DataplanePath {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        match self {
            Self::Standard(path) => path.raw().len(),
            Self::EmptyPath => 0,
            Self::Unsupported { bytes, .. } => bytes.len(),
        }
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        match self {
            Self::Standard(path) => buffer.put(path.raw()),
            Self::EmptyPath => (),
            Self::Unsupported { bytes, .. } => buffer.put_slice(bytes),
        }
    }
}

impl WireDecodeWithContext<Bytes> for DataplanePath {
    type Error = DecodeError;
    type Context = (PathType, usize);

    fn decode_with_context(
        data: &mut Bytes,
        (path_type, length_hint): Self::Context,
    ) -> Result<Self, Self::Error> {
        match path_type {
            PathType::Empty => Ok(DataplanePath::EmptyPath),
            PathType::Scion => Ok(StandardPath::decode(data)?.into()),
            other => {
                if data.remaining() < length_hint {
                    Err(Self::Error::PacketEmptyOrTruncated)
                } else {
                    Ok(DataplanePath::Unsupported {
                        path_type: other,
                        bytes: data.split_to(length_hint),
                    })
                }
            }
        }
    }
}
