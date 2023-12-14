//! A standard SCION path.

use std::mem;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::DataplanePathErrorKind;
use crate::{
    packet::{DecodeError, InadequateBufferSize},
    wire_encoding::{self, WireDecode, WireEncode},
};

wire_encoding::bounded_uint! {
    /// A 2-bit index into the info fields.
    #[derive(Default)]
    pub struct InfoFieldIndex(u8 : 2);
}

wire_encoding::bounded_uint! {
    /// A 6-bit index into the hop fields.
    #[derive(Default)]
    pub struct HopFieldIndex(u8 : 6);
}

wire_encoding::bounded_uint! {
    /// A 6-bit count of the number of hop fields in a path segment.
    #[derive(Default)]
    pub struct SegmentLength(u8 : 6);
}

impl SegmentLength {
    /// Gets the indicated length of the segment as a usize.
    pub const fn length(&self) -> usize {
        self.0 as usize
    }
}

wire_encoding::bounded_uint! {
    /// A 6-bit reserved field within the [`PathMetaHeader`].
    #[derive(Default)]
    pub struct PathMetaReserved(u8 : 6);
}

/// Meta information about the SCION path contained in a [`StandardPath`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PathMetaHeader {
    /// An index to the current info field for the packet on its way through the network.
    ///
    /// This must be smaller than [`Self::info_fields_count`].
    pub current_info_field: InfoFieldIndex,

    /// An index to the current hop field within the segment pointed to by the info field.
    ///
    /// For valid SCION packets, this should point at a hop field associated with the
    /// current info field.
    ///
    /// This must be smaller than [`Self::hop_fields_count`].
    pub current_hop_field: HopFieldIndex,

    /// Unused bits in the path path meta header.
    pub reserved: PathMetaReserved,

    /// The number of hop fields in a given segment.
    ///
    /// For valid SCION packets, the SegmentLengths at indices 1 and 2 should be non-zero
    /// only if all the preceding SegmentLengths are non-zero.
    pub segment_lengths: [SegmentLength; 3],
}

impl PathMetaHeader {
    /// The length of a path meta header in bytes.
    pub const LENGTH: usize = 4;
    /// The length of an info field in bytes.
    pub const INFO_FIELD_LENGTH: usize = 8;
    /// The length of a hop field in bytes.
    pub const HOP_FIELD_LENGTH: usize = 12;

    /// The number of info fields.
    pub const fn info_fields_count(&self) -> usize {
        match &self.segment_lengths {
            [SegmentLength(0), ..] => 0,
            [_, SegmentLength(0), _] => 1,
            [.., SegmentLength(0)] => 2,
            _ => 3,
        }
    }

    /// Returns the index of the current info field.
    pub fn info_field_index(&self) -> usize {
        self.current_info_field.get().into()
    }

    /// The number of hop fields.
    pub const fn hop_fields_count(&self) -> usize {
        self.segment_lengths[0].length()
            + self.segment_lengths[1].length()
            + self.segment_lengths[2].length()
    }

    /// Returns the index of the current hop field.
    pub fn hop_field_index(&self) -> usize {
        self.current_hop_field.get().into()
    }

    /// Returns the offset in bytes of the given info field.
    pub fn info_field_offset(info_field_index: usize) -> usize {
        Self::LENGTH + Self::INFO_FIELD_LENGTH * info_field_index
    }

    /// Returns the offset in bytes of the given hop field.
    pub fn hop_field_offset(&self, hop_field_index: usize) -> usize {
        Self::LENGTH
            + Self::INFO_FIELD_LENGTH * self.info_fields_count()
            + Self::HOP_FIELD_LENGTH * hop_field_index
    }

    /// Encodes the header as a `u32`.
    pub fn as_u32(&self) -> u32 {
        (u32::from(self.current_info_field.get()) << 30)
            | (u32::from(self.current_hop_field.get()) << 24)
            | (u32::from(self.reserved.get()) << 18)
            | (u32::from(self.segment_lengths[0].get()) << 12)
            | (u32::from(self.segment_lengths[1].get()) << 6)
            | (u32::from(self.segment_lengths[2].get()))
    }

    const fn encoded_path_length(&self) -> usize {
        Self::LENGTH
            + self.info_fields_count() * Self::INFO_FIELD_LENGTH
            + self.hop_fields_count() * Self::HOP_FIELD_LENGTH
    }

    fn computed_info_field_index(&self) -> usize {
        self.segment_lengths
            .iter()
            .enumerate()
            .scan(0usize, |total, (i, segment)| {
                if self.hop_field_index() >= *total {
                    *total += segment.length();
                    Some(i)
                } else {
                    None
                }
            })
            .last()
            .unwrap()
    }
}

impl WireEncode for PathMetaHeader {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        Self::LENGTH
    }

    #[inline]
    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_u32(self.as_u32());
    }
}

impl<T: Buf> WireDecode<T> for PathMetaHeader {
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if data.remaining() < mem::size_of::<u32>() {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }
        let fields = data.get_u32();

        let meta = Self {
            current_info_field: InfoFieldIndex(nth_field::<0>(fields)),
            current_hop_field: HopFieldIndex(nth_field::<1>(fields)),
            reserved: PathMetaReserved(nth_field::<2>(fields)),
            segment_lengths: [
                SegmentLength(nth_field::<3>(fields)),
                SegmentLength(nth_field::<4>(fields)),
                SegmentLength(nth_field::<5>(fields)),
            ],
        };

        if meta.segment_lengths[2].get() > 0 && meta.segment_lengths[1].get() == 0
            || meta.segment_lengths[1].get() > 0 && meta.segment_lengths[0].get() == 0
            || meta.segment_lengths[0].get() == 0
        {
            return Err(DataplanePathErrorKind::InvalidSegmentLengths.into());
        }

        if meta.info_field_index() >= meta.info_fields_count() {
            return Err(DataplanePathErrorKind::InfoFieldOutOfRange.into());
        }
        // Above errs also when info_fields_index() is 4, since info_fields_count() is at most 3
        debug_assert!(meta.info_field_index() <= 3);

        if meta.hop_field_index() >= meta.hop_fields_count()
            || meta.computed_info_field_index() != meta.info_field_index()
        {
            return Err(DataplanePathErrorKind::HopFieldOutOfRange.into());
        }

        Ok(meta)
    }
}

/// Return the n-th 2 or 6-bit field from a u32 value, as indexed below.
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | 0 |     1     |     2     |     3     |     4     |     5     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[inline]
const fn nth_field<const N: usize>(fields: u32) -> u8 {
    const FIELD_BITS: usize = 6;
    const MASK: u32 = 0b11_1111;

    ((fields >> ((5 - N) * FIELD_BITS)) & MASK) as u8
}

/// The standard SCION path header.
///
/// Consists of a [`PathMetaHeader`] along with one or more info fields and hop fields.
#[derive(Debug, Clone, PartialEq)]
pub struct StandardPath {
    /// The meta information about the stored path.
    meta_header: PathMetaHeader,
    /// The raw data containing the meta_header, info, and hop fields.
    encoded_path: Bytes,
}

impl StandardPath {
    /// Returns the metadata about the stored path.
    pub fn meta_header(&self) -> &PathMetaHeader {
        &self.meta_header
    }

    /// Creates a deep copy of this path.
    pub fn deep_copy(&self) -> Self {
        Self {
            meta_header: self.meta_header.clone(),
            encoded_path: Bytes::copy_from_slice(&self.encoded_path),
        }
    }

    /// Returns the encoded raw path.
    pub fn raw(&self) -> Bytes {
        self.encoded_path.clone()
    }

    /// Reverses both the raw path and the metadata in the [`Self::meta_header`].
    ///
    /// Can panic if the meta header is inconsistent with the encoded path or the encoded path
    /// itself is inconsistent (e.g., the `current_info_field` points to an empty segment).
    pub fn to_reversed(&self) -> Self {
        let meta_header = PathMetaHeader {
            current_info_field: (self.meta_header.info_fields_count() as u8
                - self.meta_header.current_info_field.get()
                - 1)
            .into(),
            current_hop_field: (self.meta_header.hop_fields_count() as u8
                - self.meta_header.current_hop_field.get()
                - 1)
            .into(),
            reserved: PathMetaReserved::default(),
            segment_lengths: match self.meta_header.segment_lengths {
                [SegmentLength(0), ..] => [SegmentLength(0); 3],
                [s1, SegmentLength(0), ..] => [s1, SegmentLength(0), SegmentLength(0)],
                [s1, s2, SegmentLength(0)] => [s2, s1, SegmentLength(0)],
                [s1, s2, s3] => [s3, s2, s1],
            },
        };

        let mut encoded_path = BytesMut::with_capacity(self.encoded_path.len());
        meta_header.encode_to_unchecked(&mut encoded_path);
        self.write_reversed_info_fields_to(&mut encoded_path);
        self.write_reversed_hop_fields_to(&mut encoded_path);

        Self {
            meta_header,
            encoded_path: encoded_path.freeze(),
        }
    }

    /// Writes the info fields to the provided buffer in reversed order.
    ///
    /// This also flips the "construction direction flag" for all info fields.
    fn write_reversed_info_fields_to(&self, buffer: &mut BytesMut) {
        for info_field in (0..self.meta_header.info_fields_count()).rev() {
            let offset = PathMetaHeader::info_field_offset(info_field);
            let slice = &self
                .encoded_path
                .slice(offset..offset + PathMetaHeader::INFO_FIELD_LENGTH);

            buffer.put_u8(slice[0] ^ 0b1); // Flip construction direction flag
            buffer.put_slice(&slice[1..]);
        }
    }

    /// Writes the hop fields to the provided buffer in reversed order.
    fn write_reversed_hop_fields_to(&self, buffer: &mut BytesMut) {
        for hop_field in (0..self.meta_header.hop_fields_count()).rev() {
            let offset = self.meta_header().hop_field_offset(hop_field);
            buffer.put_slice(
                &self
                    .encoded_path
                    .slice(offset..offset + PathMetaHeader::HOP_FIELD_LENGTH),
            )
        }
    }
}

impl WireDecode<Bytes> for StandardPath {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        let mut view: &[u8] = data.as_ref();
        let meta_header = PathMetaHeader::decode(&mut view)?;

        if data.remaining() < meta_header.encoded_path_length() {
            Err(Self::Error::PacketEmptyOrTruncated)
        } else {
            let encoded_path = data.split_to(meta_header.encoded_path_length());
            Ok(Self {
                meta_header,
                encoded_path,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    use super::*;

    macro_rules! path_bytes {
        (info: $info:expr, hop: $hop:expr, seg_lengths: $segs:expr, field_len: $field_len:expr) => {{
            const MASK: u32 = 0b11_1111;
            let meta_bytes = ($info << 30)
                | (($hop & MASK) << 24)
                | (($segs[0] & MASK) << 12)
                | (($segs[1] & MASK) << 6)
                | ($segs[2] & MASK);

            let mut data = vec![7u8; $field_len + PathMetaHeader::LENGTH];
            data.as_mut_slice().put_u32(meta_bytes);
            Bytes::from(data)
        }};
        (info: $info:expr, hop: $hop:expr, seg_lengths: $segs:expr) => {
            path_bytes! {
                info: $info, hop: $hop, seg_lengths: $segs,
                field_len: (
                    ($segs[0] + $segs[1] + $segs[2]) * 12
                    + $segs.iter().filter(|x| **x != 0).count() * 8
                )
            }
        };
    }

    macro_rules! test_valid_decode_encode_reverse {
        ($name:ident, $encoded_path:expr, $decoded_header:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn decode() {
                    let mut data = $encoded_path;
                    let header = StandardPath::decode(&mut data).expect("valid decode");

                    assert_eq!(*header.meta_header(), $decoded_header);
                }

                #[test]
                fn encode() {
                    let encoded_header = $decoded_header.encode_to_bytes();

                    assert_eq!(
                        encoded_header.slice(..),
                        $encoded_path[..PathMetaHeader::LENGTH]
                    );
                }

                #[test]
                fn reverse_twice_identity() {
                    let mut data = $encoded_path;
                    let header = StandardPath::decode(&mut data).expect("valid decode");

                    let reverse_path = header.to_reversed();
                    assert!(header != reverse_path);
                    assert_eq!(header, reverse_path.to_reversed());
                }
            }
        };
    }

    test_valid_decode_encode_reverse!(
        valid_no_zero_index,
        path_bytes! {info: 0, hop: 0, seg_lengths: [3, 0, 0], field_len: 44},
        PathMetaHeader {
            current_info_field: InfoFieldIndex(0),
            current_hop_field: HopFieldIndex(0),
            reserved: PathMetaReserved(0),
            segment_lengths: [SegmentLength(3), SegmentLength(0), SegmentLength(0)]
        }
    );

    test_valid_decode_encode_reverse!(
        valid_minimal,
        path_bytes! {info: 0, hop: 0, seg_lengths: [1, 0, 0]},
        PathMetaHeader {
            current_info_field: InfoFieldIndex(0),
            current_hop_field: HopFieldIndex(0),
            reserved: PathMetaReserved(0),
            segment_lengths: [SegmentLength(1), SegmentLength(0), SegmentLength(0)]
        }
    );

    test_valid_decode_encode_reverse!(
        valid_with_index,
        path_bytes! {info: 1, hop: 8, seg_lengths: [5, 4, 0], field_len: 124},
        PathMetaHeader {
            current_info_field: InfoFieldIndex(1),
            current_hop_field: HopFieldIndex(8),
            reserved: PathMetaReserved(0),
            segment_lengths: [SegmentLength(5), SegmentLength(4), SegmentLength(0)]
        }
    );

    macro_rules! decode_errs {
        ($name:ident, $path:expr, $err:expr) => {
            #[test]
            fn $name() {
                let mut data = $path;
                let expected_err: DecodeError = $err.into();
                let err = StandardPath::decode(&mut data).expect_err("should fail");
                assert_eq!(expected_err, err);
            }
        };
    }

    decode_errs!(
        fields_truncated,
        path_bytes! {info: 1, hop: 8, seg_lengths: [5, 4, 0], field_len: 8},
        DecodeError::PacketEmptyOrTruncated
    );
    decode_errs!(
        invalid_segment_len,
        path_bytes! {info: 0, hop: 0, seg_lengths: [0, 1, 1]},
        DataplanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        invalid_segment_len2,
        path_bytes! {info: 0, hop: 0, seg_lengths: [1, 0, 1]},
        DataplanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        invalid_segment_len3,
        path_bytes! {info: 0, hop: 0, seg_lengths: [0, 1, 0]},
        DataplanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        no_segment_len,
        path_bytes! {info: 0, hop: 0, seg_lengths: [0, 0, 0]},
        DataplanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        info_index_too_large,
        path_bytes! {info: 3, hop: 0, seg_lengths: [5, 4, 3]},
        DataplanePathErrorKind::InfoFieldOutOfRange
    );
    decode_errs!(
        info_index_out_of_range,
        path_bytes! {info: 2, hop: 0, seg_lengths: [5, 4, 0]},
        DataplanePathErrorKind::InfoFieldOutOfRange
    );
    decode_errs!(
        hop_field_out_of_range,
        path_bytes! {info: 0, hop: 10, seg_lengths: [9, 0, 0]},
        DataplanePathErrorKind::HopFieldOutOfRange
    );
    decode_errs!(
        hop_field_points_to_wrong_info,
        path_bytes! {info: 0, hop: 6, seg_lengths: [3, 7, 0]},
        DataplanePathErrorKind::HopFieldOutOfRange
    );
    decode_errs!(
        hop_field_points_to_wrong_info2,
        path_bytes! {info: 0, hop: 3, seg_lengths: [3, 7, 0]},
        DataplanePathErrorKind::HopFieldOutOfRange
    );
}
