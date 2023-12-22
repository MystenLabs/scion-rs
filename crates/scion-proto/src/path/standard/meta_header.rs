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

    /// The number of interfaces on the path.
    ///
    /// This starts counting at 0 with the egress interface of the first AS and only counts actually
    /// traversed interfaces. In particular, crossover ASes are only counted as 2 interfaces even
    /// though they are represented by two hop fields.
    pub fn interfaces_count(&self) -> usize {
        2 * (self.hop_fields_count() - self.info_fields_count())
    }

    /// Returns the index of the hop field including the given interface.
    ///
    /// This does *not* check that the `interface_index` is in range and provides meaningless
    /// results if the [`Self::segment_lengths`] are invalid but does not panic in those cases.
    pub fn hop_field_index_for_interface(&self, interface_index: usize) -> usize {
        let actual_hop_index = (interface_index + 1) / 2;
        match interface_index / 2 + 1 {
            // The interface is in the first segment
            x if x < self.segment_lengths[0].length() => actual_hop_index,
            // The interface is in the second segment; add 1 for the additional crossover hop field
            x if x + 1 < self.segment_lengths[0].length() + self.segment_lengths[1].length() => {
                actual_hop_index + 1
            }
            // The interface is in the third segment; add 2 for the additional crossover hop fields
            _ => actual_hop_index + 2,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! new_path_meta_header {
        [$seg1:expr, $seg2:expr, $seg3:expr] => {
            PathMetaHeader {
                current_info_field: InfoFieldIndex(0),
                current_hop_field: HopFieldIndex(0),
                reserved: PathMetaReserved(0),
                segment_lengths: [
                    SegmentLength($seg1),
                    SegmentLength($seg2),
                    SegmentLength($seg3),
                ],
            }
        };
    }

    mod interfaces_count {
        use super::*;

        macro_rules! test_interfaces_count {
            ($name:ident, [$seg1:expr, $seg2:expr, $seg3:expr], $count:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        new_path_meta_header![$seg1, $seg2, $seg3].interfaces_count(),
                        $count
                    )
                }
            };
        }

        test_interfaces_count!(no_segment, [0, 0, 0], 0);
        test_interfaces_count!(single_segment1, [2, 0, 0], 2);
        test_interfaces_count!(single_segment2, [4, 0, 0], 6);
        test_interfaces_count!(two_segments, [4, 3, 0], 10);
        test_interfaces_count!(three_segments, [4, 3, 2], 12);
    }

    mod hop_index_for_interface {
        use super::*;

        macro_rules! test_hop_index_for_interface {
            ($name:ident, [$seg1:expr, $seg2:expr, $seg3:expr], $interface_index:expr, $hop_index:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        new_path_meta_header![$seg1, $seg2, $seg3]
                            .hop_field_index_for_interface($interface_index),
                        $hop_index
                    )
                }
            };
        }
        test_hop_index_for_interface!(single_segment1, [4, 0, 0], 0, 0);
        test_hop_index_for_interface!(single_segment2, [4, 0, 0], 1, 1);
        test_hop_index_for_interface!(single_segment3, [4, 0, 0], 4, 2);
        test_hop_index_for_interface!(single_segment4, [4, 0, 0], 5, 3);
        test_hop_index_for_interface!(two_segments1, [4, 3, 0], 5, 3);
        test_hop_index_for_interface!(two_segments2, [4, 3, 0], 6, 4);
        test_hop_index_for_interface!(two_segments3, [4, 3, 0], 9, 6);
        test_hop_index_for_interface!(three_segments1, [4, 3, 2], 9, 6);
        test_hop_index_for_interface!(three_segments2, [4, 3, 2], 10, 7);
        test_hop_index_for_interface!(three_segments3, [4, 3, 2], 11, 8);

        macro_rules! test_no_panic {
            ($name:ident, [$seg1:expr, $seg2:expr, $seg3:expr]) => {
                #[test]
                fn $name() {
                    let header = new_path_meta_header![$seg1, $seg2, $seg3];
                    header.hop_field_index_for_interface(0);
                    header.hop_field_index_for_interface(4);
                }
            };
        }

        test_no_panic!(no_segment, [0, 0, 0]);
        test_no_panic!(invalid_segments1, [0, 0, 4]);
        test_no_panic!(invalid_segments2, [2, 0, 4]);
        test_no_panic!(invalid_segments3, [0, 3, 0]);
    }
}
