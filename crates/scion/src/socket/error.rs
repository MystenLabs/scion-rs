use std::io;

use scion_proto::datagram::UdpEncodeError;

use crate::{dispatcher::RegistrationError, pan::SendError};

/// Errors that may be raised when attempted to bind a [`UdpSocket`][super::UdpSocket].
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// The UdpSocket was unable to connect to the dispatcher at the provided address.
    #[error("failed to connect to the dispatcher, reason: {0}")]
    DispatcherConnectFailed(#[from] io::Error),
    /// An error which occurred during the registration handshake with the SCION dispatcher.
    #[error("failed to bind to the requested port")]
    RegistrationFailed(#[from] RegistrationError),
}

impl From<UdpEncodeError> for SendError {
    fn from(value: UdpEncodeError) -> Self {
        match value {
            UdpEncodeError::PayloadTooLarge => Self::PacketTooLarge,
        }
    }
}
