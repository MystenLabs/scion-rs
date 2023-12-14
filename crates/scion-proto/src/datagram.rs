//! Representation, encoding, and decoding of UDP datagrams.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    packet::{AddressHeader, ByEndpoint, ChecksumDigest, InadequateBufferSize},
    wire_encoding::{WireDecode, WireEncodeVec},
};

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum UdpDecodeError {
    #[error("datagram is empty or was truncated")]
    DatagramEmptyOrTruncated,
    #[error("next-header value of SCION header is not correct")]
    WrongProtocolNumber(u8),
}

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum UdpEncodeError {
    #[error("payload length cannot be encoded")]
    PayloadTooLarge,
}

/// SCION UDP datagram.
///
/// The SCION UDP datagram format includes a checksum that is calculated based on
/// the [RFC].
///
/// [RFC]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html
#[derive(Debug, Default, PartialEq)]
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
    /// SCION protocol number for UDP.
    ///
    /// See the [IETF SCION-dataplane RFC draft][rfc] for possible values.
    ///
    ///[rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#protnum
    pub const PROTOCOL_NUMBER: u8 = 17;
    /// Length in bytes of the UDP header.
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

impl<T: Buf> WireDecode<T> for UdpDatagram {
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

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use super::*;
    use crate::{address::IsdAsn, wire_encoding::MaybeEncoded};

    #[test]
    fn create_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
        let payload = Bytes::from_static(&[1, 2, 3, 4]);
        let address_header = AddressHeader {
            ia: ByEndpoint {
                source: IsdAsn::from_str("1-1")?,
                destination: IsdAsn::from_str("1-2")?,
            },
            host: ByEndpoint {
                source: MaybeEncoded::Decoded(Ipv4Addr::from_str("10.0.0.1")?.into()),
                destination: MaybeEncoded::Decoded(Ipv4Addr::from_str("10.0.0.2")?.into()),
            },
        };
        let mut datagram = UdpDatagram::new(
            ByEndpoint {
                source: 10001,
                destination: 10002,
            },
            payload.clone(),
        )?;
        datagram.set_checksum(&address_header);
        let expected_length = 8 + 4;
        let expected_header = [
            (10001 >> 8) as u8,
            (10001 & 0xff) as u8,
            (10002 >> 8) as u8,
            (10002 & 0xff) as u8,
            0,
            expected_length.try_into()?,
            (datagram.checksum >> 8) as u8,
            (datagram.checksum & 0xff) as u8,
        ];

        assert!(datagram.verify_checksum(&address_header));

        let encoded_datagram = datagram.encode_to_bytes_vec();
        assert_eq!(datagram.total_length(), expected_length);
        assert_eq!(
            encoded_datagram,
            [Bytes::copy_from_slice(&expected_header[..]), payload]
        );

        let mut encoded_bytes = BytesMut::new();
        encoded_bytes.put(encoded_datagram[0].clone());
        encoded_bytes.put(encoded_datagram[1].clone());
        assert_eq!(UdpDatagram::decode(&mut encoded_bytes.freeze())?, datagram);

        Ok(())
    }
}
