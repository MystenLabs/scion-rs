use std::{io, path::Path};

use bytes::{Buf, BytesMut};
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
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

// Recv buffer to 1 MiB
// TODO(jsmith): Allow the user to set this
const RECV_BUFFER_LEN: usize = 1024 * 1024; // 1 MiB;

// Set the send buffer to 1024 bytes since only single common headers (max ~32 B) are written to it.
// This means that the logic for resetting the BytesMut is triggered only once every ~30 packets.
const SEND_BUFFER_LEN: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("an invalid registration address was provided")]
    InvalidAddress,
    #[error(transparent)]
    RegistrationExchangeFailed(#[from] ProtocolRegistrationError),
    #[error(transparent)]
    InvalidResponse(#[from] DecodeError),
    #[error("the dispatcher refused to bind to the requested address")]
    Refused,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<InvalidRegistrationAddressError> for RegistrationError {
    fn from(_: InvalidRegistrationAddressError) -> Self {
        Self::InvalidAddress
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Io(#[from] io::Error),
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
    /// Connects to the dispatcher over a Unix socket at the provided path.
    pub async fn connect<P: AsRef<Path> + std::fmt::Debug>(path: P) -> Result<Self, io::Error> {
        tracing::trace!(?path, "connecting to dispatcher");
        let inner = UnixStream::connect(path).await?;
        tracing::trace!("successfully connected");

        Ok(Self {
            inner,
            send_buffer: BytesMut::with_capacity(SEND_BUFFER_LEN),
            recv_buffer: BytesMut::with_capacity(RECV_BUFFER_LEN),
            parser: StreamParser::new(),
        })
    }

    /// Register to receive SCION packet for the given address and port.
    pub async fn register(&mut self, address: SocketAddr) -> Result<SocketAddr, RegistrationError> {
        tracing::trace!(%address, "registering to receive SCION packets");
        let mut exchange = RegistrationExchange::new();

        debug_assert!(self.send_buffer.is_empty());

        // Known to hold all registration messages
        let mut buffer = [0u8; 64];
        let message_length = exchange.register(address, &mut buffer.as_mut())?;

        if let Err(err) = self.send_via(None, &mut &buffer[..message_length]).await {
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

    pub async fn send_via(
        &mut self,
        relay: Option<std::net::SocketAddr>,
        data: &mut impl Buf,
    ) -> Result<(), SendError> {
        tracing::trace!(?relay, "sending {} bytes", data.remaining());
        let header = CommonHeader {
            destination: relay,
            payload_length: u32::try_from(data.remaining())
                .map_err(|_| SendError::PayloadTooLarge(data.remaining()))?,
        };
        header.encode_to(&mut self.send_buffer);

        self.inner.write_all_buf(&mut self.send_buffer).await?;
        self.inner.write_all_buf(data).await?;

        Ok(())
    }

    /// Receive a packet from the dispatcher stream
    pub async fn receive_packet(&mut self) -> Result<Packet, ReceiveError> {
        loop {
            // Attempt to decode any data available in the receive buffer
            if let Some(packet) = self.parser.parse(&mut self.recv_buffer)? {
                return Ok(packet);
            }

            // Read data into the receive buffer.
            // 0 bytes read indicates a EoF which (I think) should never happen for the dispatcher
            if let 0 = self.inner.read_buf(&mut self.recv_buffer).await? {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        }
    }
}
