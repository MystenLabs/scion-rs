use std::{fmt::Display, io};

use scion_proto::packet::{self, EncodeError};

use crate::dispatcher;

/// Kinds of path-related failures that may occur when sending a packet.
#[derive(Debug)]
pub enum PathErrorKind {
    /// The provided path has already expired.
    Expired,
    /// No path to the destination is available.
    NoPath,
    /// The path should have provided the next-hop in the underlay but did not.
    ///
    /// Currently, only intra-AS paths do not require a next-hop, all inter-AS paths do.
    NoUnderlayNextHop,
}

impl Display for PathErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            PathErrorKind::Expired => "the provided path has already expired",
            PathErrorKind::NoPath => "no path to the destination available",
            PathErrorKind::NoUnderlayNextHop => "no underlay next hop provided by path",
        };
        f.write_str(description)
    }
}

/// Error returned when attempting to send a datagram on the SCION network.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// An IO error raised from the OS or from the socket.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An issue with the provided or fetched path.
    #[error("issue with the provided path: {0}")]
    PathIssue(PathErrorKind),
    /// The packet is too large to be sent on the network.
    #[error("packet is too large to be sent")]
    PacketTooLarge,
}

impl From<PathErrorKind> for SendError {
    fn from(value: PathErrorKind) -> Self {
        SendError::PathIssue(value)
    }
}

impl From<io::ErrorKind> for SendError {
    fn from(value: io::ErrorKind) -> Self {
        Self::Io(value.into())
    }
}

impl From<dispatcher::SendError> for SendError {
    fn from(value: dispatcher::SendError) -> Self {
        match value {
            dispatcher::SendError::Io(io) => Self::Io(io),
            dispatcher::SendError::PayloadTooLarge(_) => Self::PacketTooLarge,
        }
    }
}

impl From<packet::EncodeError> for SendError {
    fn from(value: packet::EncodeError) -> Self {
        match value {
            EncodeError::PayloadTooLarge | EncodeError::HeaderTooLarge => Self::PacketTooLarge,
        }
    }
}

/// Error messages returned from the UDP socket.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiveError {
    /// A buffer with zero-length was provided to which to be written.
    ///
    /// Retry the operation with a buffer of non-zero length to receive datagrams.
    #[error("attempted to receive with a zero-length buffer")]
    ZeroLengthBuffer,
    /// The provided path buffer does not meet the minimum length requirement.
    #[error("path buffer too short")]
    PathBufferTooShort,
}
