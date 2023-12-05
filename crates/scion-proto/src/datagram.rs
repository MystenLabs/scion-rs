use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    packet::{AddressHeader, ByEndpoint, ChecksumDigest, InadequateBufferSize},
    wire_encoding::{WireDecode, WireEncodeVec},
};

#[derive(Debug, thiserror::Error)]
pub enum UdpDecodeError {
    #[error("datagram is empty or was truncated")]
    DatagramEmptyOrTruncated,
    #[error("next-header value of SCION header is not correct")]
    WrongProtocolNumber(u8),
}

#[derive(Debug, thiserror::Error)]
pub enum UdpEncodeError {
    #[error("payload length cannot be encoded")]
    PayloadTooLarge,
}

/// Scion UDP datagram
///
/// The SCION UDP datagram format includes a checksum that is calculated based on
/// the [RFC].
///
/// [RFC]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html
#[derive(Debug, Default)]
pub struct UdpDatagram {
    /// The source and destination ports
    pub port: ByEndpoint<u16>,
    /// The length of the header and payload
    pub length: u16,
    /// SCION checksum, computed with a pseudo-header
    pub checksum: u16,
    /// The UDP payload
    pub payload: Bytes,
}

impl UdpDatagram {
    pub const PROTOCOL_NUMBER: u8 = 17;
    pub const HEADER_LEN: usize = 8;

    /// Creates a new datagram setting the length field appropriately
    ///
    /// Returns an error if the payload is too large
    pub fn new(port: ByEndpoint<u16>, payload: Bytes) -> Result<Self, UdpEncodeError> {
        let datagram = Self {
            port,
            length: (payload.len() + Self::HEADER_LEN)
                .try_into()
                .map_err(|_| UdpEncodeError::PayloadTooLarge)?,
            checksum: 0,
            payload,
        };
        Ok(datagram)
    }

    /// Compute the checksum for this datagram using the provided address header.
    pub fn calculate_checksum(&self, address_header: &AddressHeader) -> u16 {
        ChecksumDigest::with_pseudoheader(address_header, Self::PROTOCOL_NUMBER, self.length.into())
            .add_u16(self.port.source)
            .add_u16(self.port.destination)
            .add_u16(self.length)
            .add_u16(self.checksum)
            .add_slice(&self.payload)
            .checksum()
    }

    /// Returns true if the checksum successfully verifies, otherwise false.
    pub fn verify_checksum(&self, address_header: &AddressHeader) -> bool {
        self.calculate_checksum(address_header) == 0
    }

    /// Clears then sets the checksum to the value returned by [`Self::calculate_checksum()`].
    pub fn set_checksum(&mut self, address_header: &AddressHeader) {
        self.checksum = 0;
        self.checksum = self.calculate_checksum(address_header);
    }
}

impl WireEncodeVec<2> for UdpDatagram {
    type Error = InadequateBufferSize;

    fn encode_with_unchecked(&self, buffer: &mut BytesMut) -> [Bytes; 2] {
        buffer.put_u16(self.port.source);
        buffer.put_u16(self.port.destination);
        buffer.put_u16(self.length);
        buffer.put_u16(self.checksum);
        [buffer.split().freeze(), self.payload.clone()]
    }

    #[inline]
    fn total_length(&self) -> usize {
        Self::HEADER_LEN + self.payload.len()
    }

    #[inline]
    fn required_capacity(&self) -> usize {
        Self::HEADER_LEN
    }
}

impl<T> WireDecode<T> for UdpDatagram
where
    T: Buf,
{
    type Error = UdpDecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if data.remaining() < UdpDatagram::HEADER_LEN {
            return Err(Self::Error::DatagramEmptyOrTruncated);
        }

        let source = data.get_u16();
        let destination = data.get_u16();
        let length = data.get_u16();
        let checksum = data.get_u16();

        let payload_length = usize::from(length) - Self::HEADER_LEN;
        if payload_length <= data.remaining() {
            Ok(Self {
                port: ByEndpoint {
                    destination,
                    source,
                },
                length,
                checksum,
                payload: data.copy_to_bytes(payload_length),
            })
        } else {
            Err(Self::Error::DatagramEmptyOrTruncated)
        }
    }
}
