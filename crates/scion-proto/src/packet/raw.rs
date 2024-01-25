//! Raw SCION packets.

use bytes::{Buf, Bytes};

use super::{
    AddressHeader,
    ByEndpoint,
    CommonHeader,
    DecodeError,
    EncodeError,
    FlowId,
    InadequateBufferSize,
    ScionHeaders,
    ScionPacket,
};
use crate::{
    address::ScionAddr,
    path::{DataplanePath, Path},
    wire_encoding::{WireDecode, WireDecodeWithContext, WireEncode, WireEncodeVec},
};

/// A SCION network packet.
#[derive(Debug, Clone, PartialEq)]
pub struct ScionPacketRaw {
    /// Packet headers
    pub headers: ScionHeaders,
    /// The packet payload.
    pub payload: Bytes,
}

impl ScionPacketRaw {
    /// Creates a new SCION raw packet
    pub fn new(
        endhosts: &ByEndpoint<ScionAddr>,
        path: &Path,
        payload: Bytes,
        next_header: u8,
        flow_id: FlowId,
    ) -> Result<Self, EncodeError> {
        let headers = ScionHeaders::new(endhosts, path, next_header, payload.len(), flow_id)?;

        Ok(Self { headers, payload })
    }
}

impl WireEncodeVec<2> for ScionPacketRaw {
    type Error = InadequateBufferSize;

    fn encode_with_unchecked(&self, buffer: &mut bytes::BytesMut) -> [Bytes; 2] {
        self.headers.encode_to_unchecked(buffer);
        [buffer.split().freeze(), self.payload.clone()]
    }

    fn total_length(&self) -> usize {
        self.headers.encoded_length() + self.payload.len()
    }

    fn required_capacity(&self) -> usize {
        self.headers.encoded_length()
    }
}

impl<T: Buf> WireDecode<T> for ScionPacketRaw {
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        let common_header = CommonHeader::decode(data)?;

        // Limit the data for headers to the length specified by the common header
        let mut header_data = data.take(common_header.remaining_header_length());
        let address_header =
            AddressHeader::decode_with_context(&mut header_data, common_header.address_info)?;

        // The path requires a Bytes, if we were already parsing a Bytes, then this is just an
        // Arc increment, otherwise we copy the bytes needed for the path.
        let mut path_bytes = header_data.copy_to_bytes(header_data.remaining());
        let context = (common_header.path_type, path_bytes.len());
        let path_header = DataplanePath::decode_with_context(&mut path_bytes, context)?;

        if path_bytes.has_remaining() {
            Err(DecodeError::InconsistentPathLength)
        } else if data.remaining() < common_header.payload_size() {
            Err(DecodeError::PacketEmptyOrTruncated)
        } else {
            let payload = data.copy_to_bytes(common_header.payload_size());
            Ok(Self {
                headers: ScionHeaders {
                    common: common_header,
                    address: address_header,
                    path: path_header,
                },
                payload,
            })
        }
    }
}

impl ScionPacket<2> for ScionPacketRaw {}
