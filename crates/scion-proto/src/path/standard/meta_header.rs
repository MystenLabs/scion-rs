use std::mem;

use bytes::{Buf, BufMut};

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

/// Meta information about the SCION path contained in a [`StandardPath`][super::StandardPath].
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

    pub(super) const fn encoded_path_length(&self) -> usize {
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

    pub(super) fn to_reversed(&self) -> Self {
        Self {
            current_info_field: InfoFieldIndex(0),
            current_hop_field: HopFieldIndex(0),
            reserved: PathMetaReserved::default(),
            segment_lengths: match self.segment_lengths {
                [SegmentLength(0), ..] => [SegmentLength(0); 3],
                [s1, SegmentLength(0), ..] => [s1, SegmentLength(0), SegmentLength(0)],
                [s1, s2, SegmentLength(0)] => [s2, s1, SegmentLength(0)],
                [s1, s2, s3] => [s3, s2, s1],
            },
        }
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
