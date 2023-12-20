//! Format, decoding, and encoding of general (raw) SCMP messages.

use bytes::{Buf, BufMut, Bytes};

use super::{
    ScmpDecodeError,
    ScmpMessageBase,
    ScmpMessageChecksum,
    ScmpType,
    SCMP_PROTOCOL_NUMBER,
};
use crate::{
    packet::{AddressHeader, ChecksumDigest, InadequateBufferSize},
    wire_encoding::{WireDecode, WireEncodeVec},
};

/// Format of an SCMP message.
///
/// See the [SCION documentation page][scion-doc-scmp] for further details.
///
/// The optional and variable-length `InfoBlock` and `DataBlock` are here represented by a single
/// field [`Self::payload`].
///
/// [scion-doc-scmp]: https://docs.scion.org/en/latest/protocols/scmp.html
#[derive(Debug, Clone, PartialEq)]
pub struct ScmpMessageRaw {
    /// The type of the SCMP message.
    ///
    /// This determines the format and content of the [`Self::payload`].
    pub message_type: ScmpType,
    /// Additional granularity to the [`Self::message_type`].
    pub code: u8,
    /// Checksum to detect accidental data corruption.
    pub checksum: u16,
    /// Optional field of variable length combining the `InfoBlock` and `DataBlock`.
    ///
    /// The format depends on [`Self::message_type`].
    pub payload: Bytes,
}

impl ScmpMessageRaw {
    /// The length of the fixed fields in every SCMP message in bytes.
    pub const FIELD_LENGTH: usize = 4;
}

impl ScmpMessageBase for ScmpMessageRaw {
    fn get_type(&self) -> ScmpType {
        self.message_type
    }

    fn code(&self) -> u8 {
        self.code
    }
}

impl ScmpMessageChecksum for ScmpMessageRaw {
    fn checksum(&self) -> u16 {
        self.checksum
    }

    fn set_checksum(&mut self, address_header: &AddressHeader) {
        self.checksum = 0;
        self.checksum = self.calculate_checksum(address_header);
    }

    fn calculate_checksum(&self, address_header: &AddressHeader) -> u16 {
        ChecksumDigest::with_pseudoheader(
            address_header,
            SCMP_PROTOCOL_NUMBER,
            self.total_length()
                .try_into()
                .expect("this never returns anything above `u32::MAX`"),
        )
        .add_u16((u8::from(self.message_type) as u16) << 8 | self.code as u16)
        .add_u16(self.checksum)
        .add_slice(self.payload.as_ref())
        .checksum()
    }
}

impl WireEncodeVec<2> for ScmpMessageRaw {
    type Error = InadequateBufferSize;

    fn encode_with_unchecked(&self, buffer: &mut bytes::BytesMut) -> [Bytes; 2] {
        buffer.put_u8(self.message_type.into());
        buffer.put_u8(self.code);
        buffer.put_u16(self.checksum);
        [buffer.split().freeze(), self.payload.clone()]
    }

    #[inline]
    fn total_length(&self) -> usize {
        Self::FIELD_LENGTH + self.payload.len()
    }

    #[inline]
    fn required_capacity(&self) -> usize {
        Self::FIELD_LENGTH
    }
}

impl<T: Buf> WireDecode<T> for ScmpMessageRaw {
    type Error = ScmpDecodeError;

    /// Interpret all data beyond the fixed fields as the message payload. Length and format checks
    /// are only applied when converting to an [`ScmpMessage`][super::ScmpMessage].
    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if data.remaining() < Self::FIELD_LENGTH {
            return Err(ScmpDecodeError::MessageEmptyOrTruncated);
        }

        let message_type = data.get_u8().into();
        let code = data.get_u8();
        let checksum = data.get_u16();
        let payload = data.copy_to_bytes(data.remaining());

        Ok(Self {
            message_type,
            code,
            checksum,
            payload,
        })
    }
}
