//! Communication with the SCION dispatcher through a UNIX socket.
//!
//! This module provides a convenient [`DispatcherStream`] to send and receive packets to/from a
//! [SCION dispatcher][dispatcher]. It builds on a [`UnixStream`] and uses the message types defined in the
//! [scion_proto::reliable] module.
//!
//! The path to the dispatcher socket can be configured using the environment variable specified in the
//! constant [`DISPATCHER_PATH_ENV_VARIABLE`] if it differs from the default value stored in
//! [`DEFAULT_DISPATCHER_PATH`].
//!
//! [dispatcher]: https://docs.scion.org/en/latest/manuals/dispatcher.html

use std::{
    io::{self, IoSlice},
    path::Path,
};

use bytes::BytesMut;
use scion_proto::{
    address::SocketAddr,
    reliable::{
        CommonHeader,
        DecodeError,
        InvalidRegistrationAddressError,
        Packet,
        RegistrationError as ProtocolRegistrationError,
        RegistrationExchange,
        StreamParser,
    },
    wire_encoding::{WireEncode, WireEncodeVec},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

/// Underlay port on which the dispatcher receives packets from the network.
pub const UNDERLAY_PORT: u16 = 30041;
/// The default file path of the dispatcher socket.
pub const DEFAULT_DISPATCHER_PATH: &str = "/run/shm/dispatcher/default.sock";
/// The environment variable to configure the path of the dispatcher socket.
pub const DISPATCHER_PATH_ENV_VARIABLE: &str = "SCION_DISPATCHER_PATH";

// TODO(jsmith): Allow the user to set this
const RECV_BUFFER_LEN: usize = 1024 * 1024; // 1 MiB;

// Set the send buffer to 1024 bytes since only single common headers (max ~32 B) are written to it.
// This means that the logic for resetting the BytesMut is triggered only once every ~30 packets.
const SEND_BUFFER_LEN: usize = 1024;

/// Get the dispatcher path.
///
/// Depending on the environment, this is the [`DEFAULT_DISPATCHER_PATH`] or manually configured
pub fn get_dispatcher_path() -> String {
    std::env::var(DISPATCHER_PATH_ENV_VARIABLE).unwrap_or(DEFAULT_DISPATCHER_PATH.to_string())
}

/// Error type returned when attempting to register with a SCION dispatcher.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    /// The provided registration address was invalid.
    #[error("an invalid registration address was provided")]
    InvalidAddress,
    /// An error occurred during the registration protocol.
    #[error(transparent)]
    RegistrationExchangeFailed(#[from] ProtocolRegistrationError),
    /// An invalid response was received from the dispatcher.
    #[error(transparent)]
    InvalidResponse(#[from] DecodeError),
    /// The dispatcher refused to bind to the requested address.
    #[error("the dispatcher refused to bind to the requested address")]
    Refused,
    /// An input/output error occurred.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<InvalidRegistrationAddressError> for RegistrationError {
    fn from(_: InvalidRegistrationAddressError) -> Self {
        Self::InvalidAddress
    }
}

/// Error type returned when attempting to receive packets from a SCION dispatcher.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    /// An input/output error occurred.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The received packet could not be decoded.
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

/// Error type returned when attempting to send packets to a SCION dispatcher.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// An input/output error occurred.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The packet payload is too large to be sent.
    #[error("payload is too large to be sent size={0}, max={}", u32::MAX)]
    PayloadTooLarge(usize),
}

/// Wrapper around a UnixStream for communicating with the dispatcher and parsing packets.
#[derive(Debug)]
pub struct DispatcherStream {
    inner: UnixStream,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    parser: StreamParser,
}

impl DispatcherStream {
    /// Create a new DispatcherStream over an already connected UnixStream.
    pub fn new(stream: UnixStream) -> Self {
        Self {
            inner: stream,
            send_buffer: BytesMut::with_capacity(SEND_BUFFER_LEN),
            recv_buffer: BytesMut::with_capacity(RECV_BUFFER_LEN),
            parser: StreamParser::new(),
        }
    }

    /// Connects to the dispatcher over a Unix socket at the provided path.
    pub async fn connect<P: AsRef<Path> + std::fmt::Debug>(path: P) -> Result<Self, io::Error> {
        tracing::trace!(?path, "connecting to dispatcher");
        let inner = UnixStream::connect(path).await?;
        tracing::trace!("successfully connected");

        Ok(Self::new(inner))
    }

    /// Register to receive SCION packet for the given address and port.
    pub async fn register(&mut self, address: SocketAddr) -> Result<SocketAddr, RegistrationError> {
        tracing::trace!(%address, "registering to receive SCION packets");
        let mut exchange = RegistrationExchange::new();

        debug_assert!(self.send_buffer.is_empty());

        // Known to hold all registration messages.
        let mut buffer = [0u8; 64];
        let message_length = exchange.register(address, &mut buffer.as_mut())?;

        if let Err(err) = self
            .send_via(None, &[IoSlice::new(&buffer[..message_length])])
            .await
        {
            match err {
                SendError::Io(err) => return Err(err.into()),
                SendError::PayloadTooLarge(_) => unreachable!(),
            }
        }

        let packet = self.receive_packet().await.map_err(|err| match err {
            ReceiveError::Decode(err) => RegistrationError::InvalidResponse(err),
            ReceiveError::Io(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                RegistrationError::Refused
            }
            ReceiveError::Io(err) => RegistrationError::Io(err),
        })?;

        Ok(exchange.handle_response(&packet.content)?)
    }

    /// Send a packet through the SCION dispatcher.
    ///
    /// The `relay` specifies the underlay address (UDP/IP) to which the dispatcher sends the packet.
    pub async fn send_packet_via<const N: usize>(
        &mut self,
        relay: Option<std::net::SocketAddr>,
        packet: &impl WireEncodeVec<N>,
    ) -> Result<(), SendError> {
        // We know that the buffer is large enough.
        let bytes = packet.encode_with_unchecked(&mut self.send_buffer);
        let buffers: [IoSlice; N] = core::array::from_fn(|i| IoSlice::new(&bytes[i][..]));
        self.send_via(relay, &buffers).await
    }

    /// Send data contained in a slice of buffers through the SCION dispatcher.
    ///
    /// The `relay` specifies the underlay address (UDP/IP) to which the dispatcher sends the packet.
    pub async fn send_via(
        &mut self,
        relay: Option<std::net::SocketAddr>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Result<(), SendError> {
        let packet_len = buffers.iter().map(|b| b.len()).sum();
        tracing::trace!(?relay, "sending {} bytes", packet_len);

        let header = CommonHeader {
            destination: relay,
            payload_length: u32::try_from(packet_len)
                .map_err(|_| SendError::PayloadTooLarge(packet_len))?,
        };

        // We know that the buffer is large enough.
        header.encode_to_unchecked(&mut self.send_buffer);
        self.inner.write_all_buf(&mut self.send_buffer).await?;
        let _ = self.inner.write_vectored(buffers).await?;

        Ok(())
    }

    /// Receive a packet from the dispatcher stream.
    pub async fn receive_packet(&mut self) -> Result<Packet, ReceiveError> {
        loop {
            // Attempt to decode any data available in the receive buffer.
            if let Some(packet) = self.parser.parse(&mut self.recv_buffer)? {
                return Ok(packet);
            }

            // Read data into the receive buffer.
            // 0 bytes read indicates a EoF which (I think) should never happen for the dispatcher.
            if let 0 = self.inner.read_buf(&mut self.recv_buffer).await? {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        }
    }
}
