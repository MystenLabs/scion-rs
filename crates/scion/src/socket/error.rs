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

/// Errors that may occur when accessing socket state.
#[derive(Debug, thiserror::Error)]
pub enum SocketStateError {
    /// Failed to acquire read lock on socket state.
    #[error("failed to acquire read lock on socket state")]
    ReadLockFailed,
    /// Failed to acquire write lock on socket state.
    #[error("failed to acquire write lock on socket state")]
    WriteLockFailed,
}

impl From<UdpEncodeError> for SendError {
    fn from(value: UdpEncodeError) -> Self {
        match value {
            UdpEncodeError::PayloadTooLarge => Self::PacketTooLarge,
        }
    }
}

macro_rules! log_err {
    ($message:expr) => {
        |err| {
            tracing::debug!(?err, $message);
            err
        }
    };
    ($message:expr, $error:expr) => {
        |err| {
            tracing::debug!(?err, $message);
            $error
        }
    };
}

pub(crate) use log_err;
