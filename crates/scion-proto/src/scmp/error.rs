//! Errors encountered when handling SCMP messages.

use crate::packet;

/// Error encountered when attempting to decode an SCMP message.
#[derive(Debug, thiserror::Error)]
pub enum ScmpDecodeError {
    /// The data is shorter than the minimum length of the corresponding SCMP message.
    #[error("message is empty or was truncated")]
    MessageEmptyOrTruncated,
    /// When attempting to decode a specific message type and the data contains a different message
    /// type.
    #[error("the type of the message does not match the type being decoded")]
    MessageTypeMismatch,
    /// Informational messages of unknown types need to be dropped.
    #[error("unknown info message type {0}")]
    UnknownInfoMessage(u8),
    /// Depending on the type of SCMP message, only specific values of the `code` field are allowed.
    #[error("invalid code for this message type")]
    InvalidCode,
    /// When decoding a SCION packet presumably containing an SCMP message but the next-header value
    /// of the SCION header doesn't match [`SCMP_PROTOCOL_NUMBER`][super::SCMP_PROTOCOL_NUMBER].
    #[error("next-header value of SCION header is not correct")]
    WrongProtocolNumber(u8),
    /// An error when decoding the SCION packet.
    #[error(transparent)]
    PackedDecodeError(#[from] packet::DecodeError),
}
