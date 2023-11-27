use std::{io, path::Path};

use bytes::{Buf, BufMut, BytesMut};
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

const BUFFER_LENGTH: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    // TODO(jsmith): Write an integration test for address not supported
    #[error(transparent)]
    AddressNotSupported(#[from] InvalidRegistrationAddressError),
    #[error(transparent)]
    RegistrationExchangeFailed(#[from] ProtocolRegistrationError),
    #[error(transparent)]
    InvalidResponse(#[from] DecodeError),
    // TODO(jsmith): Write an integration test for when the address is already in use.
    #[error("the dispatcher refused to bind to the requested address")]
    AddressInUse,
    #[error(transparent)]
    Io(#[from] io::Error),
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
    pub async fn connect<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let inner = UnixStream::connect(path).await?;

        Ok(Self {
            inner,
            send_buffer: BytesMut::with_capacity(BUFFER_LENGTH),
            recv_buffer: BytesMut::with_capacity(BUFFER_LENGTH),
            parser: StreamParser::new(),
        })
    }

    /// Register to receive SCION packet for the given address and port.
    pub async fn register(&mut self, address: SocketAddr) -> Result<SocketAddr, RegistrationError> {
        let mut exchange = RegistrationExchange::new();

        debug_assert!(self.send_buffer.is_empty());

        // Known to hold all registration messages
        let mut registration_message = [0u8; 64];

        // Write the registraton message to the buffer
        let mut buffer = registration_message.as_mut_slice();
        exchange.register(address, &mut buffer)?;
        let bytes_remaining = buffer.remaining_mut();

        let message_length = registration_message.len() - bytes_remaining;
        let mut buffer = &registration_message[..message_length];

        if let Err(err) = self.send_via(None, &mut buffer).await {
            match err {
                SendError::PayloadTooLarge(_) => unreachable!(),
                SendError::Io(err) => return Err(err.into()),
            }
        }

        let packet = match self.receive_packet().await {
            Ok(packet) => packet,
            Err(err) => match err {
                ReceiveError::Io(err) => match err.kind() {
                    // TODO(jsmith): One of these should be mapped to AddressInUse
                    io::ErrorKind::ConnectionReset => todo!(),
                    io::ErrorKind::ConnectionAborted => todo!(),
                    _ => return Err(err.into()),
                },
                ReceiveError::Decode(err) => return Err(err.into()),
            },
        };

        Ok(exchange.handle_response(&packet.content)?)
    }

    pub async fn send_via(
        &mut self,
        relay: Option<std::net::SocketAddr>,
        data: &mut impl Buf,
    ) -> Result<(), SendError> {
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
