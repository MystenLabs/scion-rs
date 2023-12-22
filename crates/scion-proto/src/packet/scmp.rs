//! SCION packets containing SCMP messages.

use bytes::{Buf, Bytes};

use super::{error::ScmpEncodeError, FlowId, InadequateBufferSize, ScionHeaders, ScionPacketRaw};
use crate::{
    address::ScionAddr,
    packet::ByEndpoint,
    path::{DataplanePath, Path},
    scmp::{ScmpDecodeError, ScmpMessage, ScmpTracerouteRequest, ScmpType, SCMP_PROTOCOL_NUMBER},
    wire_encoding::{WireDecode, WireEncodeVec},
};

/// A SCION packet containing a SCMP message.
#[derive(Debug, Clone, PartialEq)]
pub struct ScionPacketScmp {
    /// Packet headers
    pub headers: ScionHeaders,
    /// The contained SCMP message
    pub message: ScmpMessage,
}

impl ScionPacketScmp {
    /// Returns the SCMP message type.
    pub fn get_type(&self) -> ScmpType {
        self.message.get_type()
    }
}

impl ScionPacketScmp {
    /// Creates a new SCION SCMP packet based on the SCMP message correctly setting the checksum.
    ///
    /// This does not work for an [`ScmpTracerouteRequest`] message, which requires setting specific
    /// router alert flags. Use [`Self::new_traceroute_request`] for this purpose.
    pub fn new(
        endhosts: &ByEndpoint<ScionAddr>,
        path: &Path,
        mut message: ScmpMessage,
    ) -> Result<Self, ScmpEncodeError> {
        let headers = ScionHeaders::new(
            endhosts,
            path,
            SCMP_PROTOCOL_NUMBER,
            message.total_length(),
            FlowId::default(),
        )?;
        message.set_checksum(&headers.address);

        Ok(Self { headers, message })
    }

    /// Creates a new SCION packet containing an [`ScmpTracerouteRequest`].
    ///
    /// This correctly sets the appropriate router alert flags and checksum.
    ///
    /// The parameter `interface_index` corresponds to the actually traversed AS-level interfaces
    /// on the path following the same conventions as the
    /// [`PathMetadata`][crate::path::PathMetadata] (starting with `0` as the egress interface of
    /// the local AS).
    ///
    /// # Errors
    ///
    /// Returns an [`ScmpEncodeError`] if the encoding of the packet headers fails or the
    /// `interface_index` is out of range.
    pub fn new_traceroute_request(
        endhosts: &ByEndpoint<ScionAddr>,
        path: &Path,
        identifier: u16,
        sequence_number: u16,
        interface_index: usize,
    ) -> Result<Self, ScmpEncodeError> {
        let DataplanePath::Standard(ref standard_path) = path.dataplane_path else {
            return Err(ScmpEncodeError::InappropriatePathType);
        };
        let mut standard_path = standard_path.to_mut();

        let Some(hop_field) = standard_path.hop_field_mut(
            standard_path
                .meta_header()
                .hop_field_index_for_interface(interface_index),
        ) else {
            return Err(ScmpEncodeError::ParameterOutOfRange);
        };
        if interface_index % 2 == 0 {
            hop_field.set_cons_egress_router_alert(true);
        } else {
            hop_field.set_cons_ingress_router_alert(true);
        };

        let path = Path {
            dataplane_path: DataplanePath::Standard(standard_path.freeze()),
            underlay_next_hop: path.underlay_next_hop,
            isd_asn: path.isd_asn,
            metadata: None,
        };
        let packet = Self::new(
            endhosts,
            &path,
            ScmpTracerouteRequest::new(identifier, sequence_number).into(),
        )?;

        Ok(packet)
    }
}

impl TryFrom<ScionPacketRaw> for ScionPacketScmp {
    type Error = ScmpDecodeError;

    fn try_from(mut value: ScionPacketRaw) -> Result<Self, Self::Error> {
        if value.headers.common.next_header != SCMP_PROTOCOL_NUMBER {
            return Err(ScmpDecodeError::WrongProtocolNumber(
                value.headers.common.next_header,
            ));
        }
        Ok(Self {
            headers: value.headers,
            message: ScmpMessage::decode(&mut value.payload)?,
        })
    }
}

impl<T: Buf> WireDecode<T> for ScionPacketScmp {
    type Error = ScmpDecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        ScionPacketRaw::decode(data)?.try_into()
    }
}

impl WireEncodeVec<3> for ScionPacketScmp {
    type Error = InadequateBufferSize;

    fn encode_with_unchecked(&self, buffer: &mut bytes::BytesMut) -> [Bytes; 3] {
        let encoded_headers = self.headers.encode_with_unchecked(buffer);
        let encoded_message = self.message.encode_with_unchecked(buffer);
        [
            encoded_headers[0].clone(),
            encoded_message[0].clone(),
            encoded_message[1].clone(),
        ]
    }

    fn total_length(&self) -> usize {
        self.headers.total_length() + self.message.total_length()
    }

    fn required_capacity(&self) -> usize {
        self.headers.required_capacity() + self.message.required_capacity()
    }
}
