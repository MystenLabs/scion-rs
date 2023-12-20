//! Types and functions for SCION dataplane paths.

use std::ops::Deref;

use bytes::{Buf, BufMut, Bytes};

use crate::{
    packet::{DecodeError, InadequateBufferSize},
    path::standard::StandardPath,
    wire_encoding::{WireDecode, WireDecodeWithContext, WireEncode},
};

/// SCION path types that may be encountered in a packet.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PathType {
    /// The empty path type.
    Empty,
    /// The standard SCION path type.
    Scion,
    /// One-hop paths between neighboring border routers.
    OneHop,
    /// Experimental Epic path type.
    Epic,
    /// Experimental Colibri path type.
    Colibri,
    /// Other, unrecognized path types.
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

/// Error returned when performing operations on a path of currently unsupported [`PathType`].
#[derive(Debug, thiserror::Error)]
#[error("unsupported path type {0}")]
pub struct UnsupportedPathType(pub u8);

/// Dataplane path found in a SCION packet.
#[derive(Debug, Clone)]
pub enum DataplanePath<T = Bytes> {
    /// The empty path type, used for intra-AS hops.
    EmptyPath,
    /// The standard SCION path header.
    Standard(StandardPath<T>),
    /// The raw bytes of an unsupported path header type.
    Unsupported {
        /// The path's type.
        path_type: PathType,
        /// The raw encoded path.
        bytes: T,
    },
}

impl<T> DataplanePath<T> {
    /// The maximum length of a SCION dataplane path.
    ///
    /// Computed from the max header length (1020) minus the common header length (12)
    /// and the minimum SCION address header length (24).
    pub const MAX_LEN: usize = 984;

    /// Returns the path's type.
    pub fn path_type(&self) -> PathType {
        match self {
            Self::EmptyPath => PathType::Empty,
            Self::Standard(_) => PathType::Scion,
            Self::Unsupported { path_type, .. } => *path_type,
        }
    }

    /// Returns true iff the path is a [`DataplanePath::EmptyPath`].
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::EmptyPath)
    }
}

impl<T> DataplanePath<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns the raw binary of the path.
    pub fn raw(&self) -> &[u8] {
        match self {
            DataplanePath::EmptyPath => &[],
            DataplanePath::Standard(path) => path.raw(),
            DataplanePath::Unsupported { bytes, .. } => bytes.deref(),
        }
    }

    /// Creates a new DataplanePath by copying this one into the provided backing buffer.
    ///
    /// # Panics
    ///
    /// For non-empty paths, this panics if the provided buffer does not have the same
    /// length as self.raw().
    pub fn copy_to_slice<'b>(&self, buffer: &'b mut [u8]) -> DataplanePath<&'b mut [u8]> {
        match self {
            DataplanePath::EmptyPath => DataplanePath::EmptyPath,
            DataplanePath::Standard(path) => DataplanePath::Standard(path.copy_to_slice(buffer)),
            DataplanePath::Unsupported { path_type, bytes } => {
                buffer.copy_from_slice(bytes);
                DataplanePath::Unsupported {
                    path_type: *path_type,
                    bytes: buffer,
                }
            }
        }
    }

    /// Reverse the path to the provided slice.
    ///
    /// Unsupported path types are copied to the slice, as is.
    pub fn reverse_to_slice<'b>(&self, buffer: &'b mut [u8]) -> DataplanePath<&'b mut [u8]> {
        match self {
            DataplanePath::EmptyPath => DataplanePath::EmptyPath,
            DataplanePath::Standard(path) => DataplanePath::Standard(path.reverse_to_slice(buffer)),
            DataplanePath::Unsupported { .. } => self.copy_to_slice(buffer),
        }
    }

    /// Reverses the path.
    pub fn to_reversed(&self) -> Result<DataplanePath, UnsupportedPathType> {
        match self {
            Self::EmptyPath => Ok(DataplanePath::EmptyPath),
            Self::Standard(standard_path) => {
                Ok(DataplanePath::Standard(standard_path.to_reversed()))
            }
            Self::Unsupported { path_type, .. } => Err(UnsupportedPathType(u8::from(*path_type))),
        }
    }
}

impl DataplanePath<Bytes> {
    /// Returns a deep copy of the object.
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

    /// Reverses the path in place.
    pub fn reverse(&mut self) -> Result<&mut Self, UnsupportedPathType> {
        match self {
            Self::EmptyPath => (),
            Self::Standard(standard_path) => *standard_path = standard_path.to_reversed(),
            Self::Unsupported { path_type, .. } => {
                return Err(UnsupportedPathType(u8::from(*path_type)))
            }
        }
        Ok(self)
    }
}

impl From<DataplanePath<&mut [u8]>> for DataplanePath<Bytes> {
    fn from(value: DataplanePath<&mut [u8]>) -> Self {
        match value {
            DataplanePath::EmptyPath => DataplanePath::EmptyPath,
            DataplanePath::Standard(path) => DataplanePath::Standard(path.into()),
            DataplanePath::Unsupported { path_type, bytes } => DataplanePath::Unsupported {
                path_type,
                bytes: Bytes::copy_from_slice(bytes),
            },
        }
    }
}

impl From<StandardPath> for DataplanePath {
    fn from(value: StandardPath) -> Self {
        Self::Standard(value)
    }
}

impl<T, U> PartialEq<DataplanePath<U>> for DataplanePath<T>
where
    T: Deref<Target = [u8]>,
    U: Deref<Target = [u8]>,
{
    fn eq(&self, other: &DataplanePath<U>) -> bool {
        match (self, other) {
            (Self::Standard(lhs), DataplanePath::Standard(rhs)) => lhs.raw() == rhs.raw(),
            (
                Self::Unsupported {
                    path_type: l_path_type,
                    bytes: l_bytes,
                },
                DataplanePath::Unsupported {
                    path_type: r_path_type,
                    bytes: r_bytes,
                },
            ) => l_path_type == r_path_type && l_bytes.deref() == r_bytes.deref(),
            (Self::EmptyPath, DataplanePath::EmptyPath) => true,
            _ => false,
        }
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

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn path_type_consistent() {
        for value in 0..u8::MAX {
            assert_eq!(u8::from(PathType::from(value)), value);
        }
    }

    macro_rules! test_path_create_encode_decode {
        ($name:ident, $dataplane_path:expr, $expected_length:expr) => {
            #[test]
            fn $name() -> Result<(), Box<dyn std::error::Error>> {
                let dataplane_path: DataplanePath = $dataplane_path;
                let mut encoded_path = dataplane_path.encode_to_bytes();

                assert_eq!(dataplane_path.encoded_length(), $expected_length);
                assert_eq!(encoded_path.len(), $expected_length);

                assert_eq!(dataplane_path.deep_copy(), dataplane_path);

                assert_eq!(
                    DataplanePath::decode_with_context(
                        &mut encoded_path,
                        (dataplane_path.path_type(), $expected_length)
                    )?,
                    dataplane_path
                );
                Ok(())
            }
        };
    }

    test_path_create_encode_decode!(empty, DataplanePath::EmptyPath, 0);

    #[test]
    fn reverse_empty() {
        let dataplane_path = DataplanePath::<Bytes>::EmptyPath;
        let reverse_path = dataplane_path.to_reversed().unwrap();
        assert_eq!(dataplane_path, reverse_path);
        assert_eq!(reverse_path.to_reversed().unwrap(), dataplane_path);
    }

    test_path_create_encode_decode!(
        other,
        DataplanePath::Unsupported {
            path_type: PathType::Colibri,
            bytes: Bytes::from_static(&[1, 2, 3, 4])
        },
        4
    );

    fn standard_path() -> DataplanePath {
        let mut path_raw = BytesMut::with_capacity(36);
        path_raw.put_u32(0x0000_2000);
        path_raw.put_slice(&[0_u8; 32]);
        DataplanePath::Standard(StandardPath::decode(&mut path_raw.freeze()).unwrap())
    }

    test_path_create_encode_decode!(standard, standard_path(), 36);

    #[test]
    fn reverse_standard() {
        let dataplane_path = standard_path();
        let reverse_path = dataplane_path.to_reversed().unwrap();
        assert!(dataplane_path != reverse_path);
        assert_eq!(reverse_path.to_reversed().unwrap(), dataplane_path);
    }
}
