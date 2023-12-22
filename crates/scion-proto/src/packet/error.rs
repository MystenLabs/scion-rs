//! Errors raised when encoding or decoding SCION packets.

use super::Version;
use crate::path::DataplanePathErrorKind;

/// Errors raised when failing to decode a [`super::ScionPacketRaw`] or [`super::ScionPacketUdp`]
/// or its constituents.
#[allow(missing_docs)]
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

/// Errors raised when failing to encode a [`super::ScionPacketRaw`], [`super::ScionPacketScmp`], or
/// [`super::ScionPacketUdp`].
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum EncodeError {
    /// The payload is too large to be properly encoded in a SCION packet.
    #[error("packet payload is too large")]
    PayloadTooLarge,
    /// The overall header is too large.
    ///
    /// This is most likely due to a too long path.
    #[error("packet header is too large")]
    HeaderTooLarge,
}

/// Errors raised when creating a [`super::ScionPacketScmp`].
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum ScmpEncodeError {
    /// Some SCMP messages (notably the [`ScmpTracerouteRequest`][crate::scmp::ScmpTracerouteRequest])
    /// require a specific path type.
    #[error("the provided path type is not appropriate for this type of packet")]
    InappropriatePathType,
    /// A provided parameter is out of range.
    #[error("a provided parameter is out of range")]
    ParameterOutOfRange,
    /// A general [`EncodeError`] occurred.
    #[error("encoding error")]
    GeneralEncodeError(#[from] EncodeError),
}

/// Raised if the buffer does not have sufficient capacity for encoding the SCION headers.
///
/// As the headers can be a maximum of 1020 bytes in length, it is advisable to have at
/// least that amount of remaining space for encoding a [`super::ScionPacketRaw`] or
/// [`super::ScionPacketUdp`] (the payload is not written to the buffer).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy, Default)]
#[error("the provided buffer did not have sufficient size")]
pub struct InadequateBufferSize;
