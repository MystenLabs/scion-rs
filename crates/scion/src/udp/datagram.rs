#![allow(unused)]
use bytes::{Buf, Bytes};
use scion_proto::{packet::ByEndpoint, wire_encoding::WireDecode};

pub(super) struct UdpDatagram {
    pub port: ByEndpoint<u16>,
    pub length: u16,
    pub checksum: u16,
    pub payload: Bytes,
}

impl UdpDatagram {
    const HEADER_LEN: usize = 16;
}

#[derive(Debug, thiserror::Error)]
pub(super) enum UdpDecodeError {
    #[error("datagram is empty or was truncated")]
    DatagramEmptyOrTruncated,
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
        // TODO(jsmith): Check for additional verifications to be done on these fields
        // TODO(jsmith): Determine whether we should check the checksum

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
