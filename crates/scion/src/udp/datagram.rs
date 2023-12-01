#![allow(unused)]
use bytes::{Buf, Bytes};
use scion_proto::{
    packet::{AddressHeader, ByEndpoint, ChecksumDigest},
    wire_encoding::WireDecode,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum UdpDecodeError {
    #[error("datagram is empty or was truncated")]
    DatagramEmptyOrTruncated,
}

/// Scion UDP datagram
///
/// The SCION UDP datagram format includes a checksum that is calculated based on
/// the [RFC].
///
/// [RFC]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html
#[derive(Debug, Default)]
pub(super) struct UdpDatagram {
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
    const PROTOCOL_NUMBER: u8 = 17;
    const HEADER_LEN: usize = 8;

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
