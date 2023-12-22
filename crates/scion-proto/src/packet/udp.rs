//! SCION packets containing UDP datagrams.

use bytes::{Buf, Bytes};

use super::{InadequateBufferSize, MessageChecksum, ScionHeaders, ScionPacketRaw};
use crate::{
    address::SocketAddr,
    datagram::{UdpDecodeError, UdpMessage},
    packet::{ByEndpoint, EncodeError},
    path::Path,
    wire_encoding::{WireDecode, WireEncodeVec},
};

/// A SCION packet containing a UDP datagram.
#[derive(Debug, Clone, PartialEq)]
pub struct ScionPacketUdp {
    /// Packet headers
    pub headers: ScionHeaders,
    /// The contained UDP datagram
    pub datagram: UdpMessage,
}

impl ScionPacketUdp {
    /// Returns the source socket address of the UDP packet.
    pub fn source(&self) -> Option<SocketAddr> {
        self.headers
            .address
            .source()
            .map(|scion_addr| SocketAddr::new(scion_addr, self.src_port()))
    }

    /// Returns the destination socket address of the UDP packet.
    pub fn destination(&self) -> Option<SocketAddr> {
        self.headers
            .address
            .destination()
            .map(|scion_addr| SocketAddr::new(scion_addr, self.dst_port()))
    }

    /// Returns the UDP packet payload.
    pub fn payload(&self) -> &Bytes {
        &self.datagram.payload
    }

    /// Returns the UDP source port
    pub fn src_port(&self) -> u16 {
        self.datagram.port.source
    }

    /// Returns the UDP destination port
    pub fn dst_port(&self) -> u16 {
        self.datagram.port.destination
    }
}

impl ScionPacketUdp {
    /// Creates a new SCION UDP packet based on the UDP payload
    pub fn new(
        endhosts: &ByEndpoint<SocketAddr>,
        path: &Path,
        payload: Bytes,
    ) -> Result<Self, EncodeError> {
        let headers = ScionHeaders::new_with_ports(
            endhosts,
            path,
            UdpMessage::PROTOCOL_NUMBER,
            payload.len() + UdpMessage::HEADER_LEN,
        )?;
        let mut datagram =
            UdpMessage::new(endhosts.map(|e| e.port()), payload).map_err(|_| todo!())?;
        datagram.set_checksum(&headers.address);

        Ok(Self { headers, datagram })
    }
}

impl TryFrom<ScionPacketRaw> for ScionPacketUdp {
    type Error = UdpDecodeError;

    fn try_from(mut value: ScionPacketRaw) -> Result<Self, Self::Error> {
        if value.headers.common.next_header != UdpMessage::PROTOCOL_NUMBER {
            return Err(UdpDecodeError::WrongProtocolNumber(
                value.headers.common.next_header,
            ));
        }
        Ok(Self {
            headers: value.headers,
            datagram: UdpMessage::decode(&mut value.payload)?,
        })
    }
}

impl<T: Buf> WireDecode<T> for ScionPacketUdp {
    type Error = UdpDecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        ScionPacketRaw::decode(data)?.try_into()
    }
}

impl WireEncodeVec<3> for ScionPacketUdp {
    type Error = InadequateBufferSize;

    fn encode_with_unchecked(&self, buffer: &mut bytes::BytesMut) -> [Bytes; 3] {
        let encoded_headers = self.headers.encode_with_unchecked(buffer);
        let encoded_datagram = self.datagram.encode_with_unchecked(buffer);
        [
            encoded_headers[0].clone(),
            encoded_datagram[0].clone(),
            encoded_datagram[1].clone(),
        ]
    }

    fn total_length(&self) -> usize {
        self.headers.total_length() + self.datagram.total_length()
    }

    fn required_capacity(&self) -> usize {
        self.headers.required_capacity() + self.datagram.required_capacity()
    }
}
