//! SCION packets containing UDP datagrams.

use bytes::Bytes;

use super::{InadequateBufferSize, ScionHeaders, ScionPacketRaw};
use crate::{
    address::SocketAddr,
    datagram::{UdpDatagram, UdpDecodeError},
    packet::{ByEndpoint, EncodeError},
    path::Path,
    wire_encoding::{WireDecode, WireEncodeVec},
};

/// A SCION packet containing a UDP datagram.
pub struct ScionPacketUdp {
    /// Packet headers
    pub headers: ScionHeaders,
    /// The contained UDP datagram
    pub datagram: UdpDatagram,
}

impl ScionPacketUdp {
    /// Creates a new SCION UDP packet based on the UDP payload
    pub fn new(
        endhosts: &ByEndpoint<SocketAddr>,
        path: &Path,
        payload: Bytes,
    ) -> Result<Self, EncodeError> {
        let headers = ScionHeaders::new(
            endhosts,
            path,
            UdpDatagram::PROTOCOL_NUMBER,
            payload.len() + UdpDatagram::HEADER_LEN,
        )?;
        let mut datagram =
            UdpDatagram::new(endhosts.map(|e| e.port()), payload).map_err(|_| todo!())?;
        datagram.set_checksum(&headers.address);

        Ok(Self { headers, datagram })
    }
}

impl TryFrom<ScionPacketRaw> for ScionPacketUdp {
    type Error = UdpDecodeError;

    fn try_from(mut value: ScionPacketRaw) -> Result<Self, Self::Error> {
        if value.headers.common.next_header != UdpDatagram::PROTOCOL_NUMBER {
            return Err(UdpDecodeError::WrongProtocolNumber(
                value.headers.common.next_header,
            ));
        }
        Ok(Self {
            headers: value.headers,
            datagram: UdpDatagram::decode(&mut value.payload)?,
        })
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
