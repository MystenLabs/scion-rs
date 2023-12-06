use super::Version;
use crate::path::DataplanePathErrorKind;

/// Errors raised when failing to decode a [`ScionPacket`] or its constituents.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    #[error("cannot decode packet with unsupported header version {0:?}")]
    UnsupportedVersion(Version),
    #[error("header length factor is inconsistent with the SCION specification: {0}")]
    InvalidHeaderLength(u8),
    #[error("the provided bytes did not include the full packet")]
    PacketEmptyOrTruncated,
    #[error("the path type and length do not correspond")]
    InconsistentPathLength,
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

/// Errors raised when failing to encode a [`ScionPacket`].
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum EncodeError {
    #[error("packet payload is too large")]
    PayloadTooLarge,
    #[error("packet header is too large")]
    HeaderTooLarge,
}

/// Raised if the buffer does not have sufficient capacity for encoding the SCION headers.
///
/// As the headers can be a maximum of 1020 bytes in length, it is advisable to have at
/// least that amount of remaining space for encoding a [`ScionPacket`] (the payload is not
/// written to the buffer).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy, Default)]
#[error("the provided buffer did not have sufficient size")]
pub struct InadequateBufferSize;
