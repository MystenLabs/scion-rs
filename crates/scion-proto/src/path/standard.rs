//! A standard SCION path.
use std::ops::Deref;

use bytes::{Buf, BufMut, Bytes};
use chrono::{DateTime, Utc};

use super::DataplanePathErrorKind;
use crate::{
    packet::DecodeError,
    wire_encoding::{WireDecode, WireEncode},
};

mod fields;
pub use fields::{HopField, HopFields, InfoField, InfoFields};

mod segment;
pub use segment::{Segment, Segments};

mod meta_header;
pub use meta_header::{
    HopFieldIndex,
    InfoFieldIndex,
    PathMetaHeader,
    PathMetaReserved,
    SegmentLength,
};

/// The standard SCION path header.
///
/// Consists of a [`PathMetaHeader`] along with one or more info fields and hop fields.
#[derive(Debug, Clone, PartialEq)]
pub struct StandardPath<T = Bytes> {
    /// The meta information about the stored path.
    meta_header: PathMetaHeader,
    /// The raw data containing the meta_header, info, and hop fields.
    encoded_path: T,
}

impl<T> StandardPath<T> {
    /// Returns the metadata about the stored path.
    pub fn meta_header(&self) -> &PathMetaHeader {
        &self.meta_header
    }
}

impl<T> StandardPath<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns the encoded raw path.
    pub fn raw(&self) -> &[u8] {
        &self.encoded_path
    }

    /// Creates new StandardPath, backed by the provided buffer, by copying this one.
    ///
    /// # Panics
    ///
    /// Panics if the provided buffer does not have the same length as self.raw().
    pub fn copy_to_slice<'b>(&self, buffer: &'b mut [u8]) -> StandardPath<&'b mut [u8]> {
        buffer.copy_from_slice(&self.encoded_path);
        StandardPath {
            meta_header: self.meta_header.clone(),
            encoded_path: buffer,
        }
    }

    /// Creates new StandardPath, backed by the provided buffer, by copying and reversing this one.
    ///
    /// The reversed path is suitable for use from an end-host: its current hop and info field
    /// indices are set to 0.
    ///
    /// # Panics
    ///
    /// Panics if the provided buffer does not have the same length as self.raw().
    pub fn reverse_to_slice<'b>(&self, buffer: &'b mut [u8]) -> StandardPath<&'b mut [u8]> {
        assert_eq!(
            buffer.len(),
            self.encoded_path.len(),
            "destination buffer length is not the same as this path's"
        );

        let mut buf_mut: &mut [u8] = buffer;
        let meta_header = self.meta_header.to_reversed();
        meta_header.encode_to_unchecked(&mut buf_mut);
        self.write_reversed_info_fields_to(&mut buf_mut);
        self.write_reversed_hop_fields_to(&mut buf_mut);

        StandardPath {
            meta_header,
            encoded_path: buffer,
        }
    }

    /// Reverses both the raw path and the metadata in the [`Self::meta_header`].
    ///
    /// The reversed path is suitable for use from an end-host: its current hop and info field
    /// indices are set to 0.
    pub fn to_reversed(&self) -> StandardPath<Bytes> {
        let mut encoded_path = vec![0u8; self.encoded_path.len()];
        let StandardPath { meta_header, .. } = self.reverse_to_slice(&mut encoded_path);

        StandardPath {
            meta_header,
            encoded_path: encoded_path.into(),
        }
    }

    /// Returns the [`InfoField`] at the specified index, if within range.
    ///
    /// The index is the index into the path's info fields, and can be at most 3.
    pub fn info_field(&self, index: usize) -> Option<&InfoField> {
        if index < self.meta_header.info_fields_count() {
            let start = PathMetaHeader::info_field_offset(index);
            let slice = &self.encoded_path[start..(start + InfoField::LENGTH)];
            Some(InfoField::new(slice))
        } else {
            None
        }
    }

    /// Returns the segment at the specified index, if any.
    ///
    /// There are always at most 3 segments.
    pub fn segment(&self, segment_index: usize) -> Option<Segment> {
        let Some(info_field) = self.info_field(segment_index) else {
            return None;
        };

        // Get the index of the first hop field in the segment.
        // This is equivalent to the index after all preceding hop fields.
        let hop_index = self.meta_header.segment_lengths[..segment_index]
            .iter()
            .fold(0usize, |sum, seglen| sum + usize::from(seglen.get()));

        let n_hop_fields: usize = self.meta_header.segment_lengths[segment_index].get().into();
        debug_assert_ne!(n_hop_fields, 0);

        Some(Segment::new(
            info_field,
            self.hop_fields_subset(hop_index, n_hop_fields),
        ))
    }

    /// Returns an iterator over the segments of this path.
    pub fn segments(&self) -> Segments {
        Segments::new([self.segment(0), self.segment(1), self.segment(2)])
    }

    /// Returns the expiry time of the path.
    ///
    /// This is the minimum expiry time of each of its segments.
    pub fn expiry_time(&self) -> DateTime<Utc> {
        self.segments()
            .map(|seg| seg.expiry_time())
            .min()
            .expect("at least 1 segment")
    }

    fn hop_fields_subset(&self, hop_index: usize, n_hop_fields: usize) -> HopFields {
        let start = self.meta_header.hop_field_offset(hop_index);
        let stop = start + n_hop_fields * HopField::LENGTH;

        HopFields::new(&self.encoded_path[start..stop])
    }

    /// Returns an iterator over all the [`InfoField`]s in the SCION path.
    pub fn info_fields(&self) -> InfoFields {
        let start = PathMetaHeader::info_field_offset(0);
        let stop = start + self.meta_header.info_fields_count() * InfoField::LENGTH;

        InfoFields::new(&self.encoded_path[start..stop])
    }

    /// Returns an iterator over all of the [`HopField`]s in the SCION path.
    fn hop_fields(&self) -> HopFields {
        self.hop_fields_subset(0, self.meta_header.hop_fields_count())
    }

    /// Writes the info fields to the provided buffer in reversed order.
    ///
    /// This also flips the "construction direction flag" for all info fields.
    fn write_reversed_info_fields_to(&self, buffer: &mut &mut [u8]) {
        for info_field in self.info_fields().rev() {
            let data = info_field.as_ref();
            buffer.put_u8(data[0] ^ InfoField::CONSTRUCTION_DIRECTION_FLAG);
            buffer.put_slice(&data[1..]);
        }
    }

    /// Writes the hop fields to the provided buffer in reversed order.
    fn write_reversed_hop_fields_to(&self, buffer: &mut &mut [u8]) {
        for hop_field in self.hop_fields().rev() {
            buffer.put_slice(hop_field.as_ref())
        }
    }
}

impl<'b> StandardPath<&'b mut [u8]> {
    /// Converts a standard path over a mutable reference to one over an immutable reference.
    pub fn freeze(self) -> StandardPath<&'b [u8]> {
        StandardPath {
            meta_header: self.meta_header,
            encoded_path: &*self.encoded_path,
        }
    }
}

impl StandardPath<Bytes> {
    /// Creates a deep copy of this path.
    pub fn deep_copy(&self) -> Self {
        Self {
            meta_header: self.meta_header.clone(),
            encoded_path: Bytes::copy_from_slice(&self.encoded_path),
        }
    }
}

impl From<StandardPath<&mut [u8]>> for StandardPath<Bytes> {
    fn from(value: StandardPath<&mut [u8]>) -> Self {
        StandardPath {
            meta_header: value.meta_header,
            encoded_path: Bytes::copy_from_slice(value.encoded_path),
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
    use std::num::NonZeroU16;

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
                fn reverse_twice_field_identity() {
                    let mut data = $encoded_path;
                    let path = StandardPath::decode(&mut data).expect("valid decode");

                    let twice_reversed = path.to_reversed().to_reversed();
                    assert!(path.hop_fields().eq(twice_reversed.hop_fields()));
                    assert!(path.info_fields().eq(twice_reversed.info_fields()));
                    assert_eq!(
                        path.meta_header.segment_lengths,
                        twice_reversed.meta_header.segment_lengths
                    );
                }
            }
        };
    }

    test_valid_decode_encode_reverse!(
        valid_no_zero_index,
        path_bytes! {info: 0, hop: 0, seg_lengths: [3, 0, 0], field_len: 44},
        PathMetaHeader {
            current_info_field: InfoFieldIndex::new_unchecked(0),
            current_hop_field: HopFieldIndex::new_unchecked(0),
            reserved: PathMetaReserved::new_unchecked(0),
            segment_lengths: [
                SegmentLength::new_unchecked(3),
                SegmentLength::new_unchecked(0),
                SegmentLength::new_unchecked(0)
            ]
        }
    );

    test_valid_decode_encode_reverse!(
        valid_minimal,
        path_bytes! {info: 0, hop: 0, seg_lengths: [1, 0, 0]},
        PathMetaHeader {
            current_info_field: InfoFieldIndex::new_unchecked(0),
            current_hop_field: HopFieldIndex::new_unchecked(0),
            reserved: PathMetaReserved::new_unchecked(0),
            segment_lengths: [
                SegmentLength::new_unchecked(1),
                SegmentLength::new_unchecked(0),
                SegmentLength::new_unchecked(0)
            ]
        }
    );

    test_valid_decode_encode_reverse!(
        valid_with_index,
        path_bytes! {info: 1, hop: 8, seg_lengths: [5, 4, 0], field_len: 124},
        PathMetaHeader {
            current_info_field: InfoFieldIndex::new_unchecked(1),
            current_hop_field: HopFieldIndex::new_unchecked(8),
            reserved: PathMetaReserved::new_unchecked(0),
            segment_lengths: [
                SegmentLength::new_unchecked(5),
                SegmentLength::new_unchecked(4),
                SegmentLength::new_unchecked(0)
            ]
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

    fn assert_ifaces_eq(hop_fields: HopFields<'_>, interfaces: &[(u16, u16)]) {
        fn interface_or_zero(iface: Option<NonZeroU16>) -> u16 {
            iface.map(NonZeroU16::get).unwrap_or_default()
        }

        let hop_interfaces: Vec<_> = hop_fields
            .map(|hop| {
                (
                    interface_or_zero(hop.cons_ingress_interface()),
                    interface_or_zero(hop.cons_egress_interface()),
                )
            })
            .collect();
        assert_eq!(hop_interfaces, interfaces);
    }

    macro_rules! test_iterators {
        ($name:ident: { path: $path_bytes:expr, times: $times:expr, interfaces: $interfaces:expr }) => {
            mod $name {
                use super::*;

                type TestResult = Result<(), Box<dyn std::error::Error>>;

                #[test]
                fn info_fields() -> TestResult {
                    let path_bytes: Vec<&[u8]> = $path_bytes;
                    let path = StandardPath::decode(&mut Bytes::from(path_bytes.concat()))?;
                    let times: &[i64] = &$times;

                    let info_field_times: Vec<_> = path
                        .info_fields()
                        .map(|info| info.timestamp().timestamp())
                        .collect();
                    assert_eq!(times, info_field_times);

                    Ok(())
                }

                #[test]
                fn hop_fields() -> TestResult {
                    let path_bytes: Vec<&[u8]> = $path_bytes;
                    let path = StandardPath::decode(&mut Bytes::from(path_bytes.concat()))?;

                    let interfaces: &[&[(u16, u16)]] = &$interfaces;
                    let interfaces: Vec<(u16, u16)> = interfaces
                        .iter()
                        .map(|l| l.iter())
                        .flatten()
                        .cloned()
                        .collect();

                    assert_ifaces_eq(path.hop_fields(), &interfaces);

                    Ok(())
                }

                #[test]
                fn segments() -> TestResult {
                    let path_bytes: Vec<&[u8]> = $path_bytes;
                    let path = StandardPath::decode(&mut Bytes::from(path_bytes.concat()))?;
                    let times: &[i64] = &$times;
                    let interfaces: &[&[(u16, u16)]] = &$interfaces;

                    assert_eq!(path.segments().len(), times.len());
                    for (i, segment) in path.segments().enumerate() {
                        assert_eq!(segment.info_field().timestamp().timestamp(), times[i]);
                        assert_ifaces_eq(segment.hop_fields(), interfaces[i]);
                    }

                    Ok(())
                }
            }
        };
    }

    test_iterators! {
        one_segment_path: {
            path: vec![
                b"\x00\x00\x10\x00",
                // Info
                b"\x3c\x84\x86\x84",
                b"\xa9\xf0\x7c\xce",
                // Hop
                b"\x13\xf7\xb4\x8a",
                b"\xc4\x8a\xc6\x3c",
                b"\xb7\xb1\x94\x9c",
            ],
            times: [0xa9f07cce],
            interfaces: [&[(0xb48a, 0xc48a)]]
        }
    }

    test_iterators! {
        two_segment_path: {
            path: vec![
                b"\x00\x00\x10\x80",
                // Info-1
                b"\x07\x2d\x19\xcd",
                b"\x76\x5d\xd0\xdf",
                // Info-2
                b"\xfb\xc7\xe6\xbd",
                b"\x2a\xb4\x7c\x18",
                // Hop-1-1
                b"\x0f\xb8\x40\x22\x19\x90\xb7\x06\xb3\xe1\x97\x66",
                // Hop-2-1, Hop-2-2
                b"\x66\xba\x03\x8d\xdd\x4e\xd0\x7f\xda\xce\xfe\x81",
                b"\xce\x4e\x99\x9e\x52\x74\xc1\x52\xfc\x72\x0c\x35",
            ],
            times: [0x765dd0df, 0x2ab47c18],
            interfaces: [&[(0x4022, 0x1990)], &[(0x038d, 0xdd4e), (0x999e, 0x5274)]]
        }
    }

    test_iterators! {
        three_segment_path: {
            path: vec![
                b"\x00\x00\x10\x83",
                // Info-1
                b"\x2e\x48\x83\xd9",
                b"\xa3\x1a\xb4\x21",
                // Info-2
                b"\x81\xbc\xbe\xfd",
                b"\xd7\x76\x72\xf2",
                // Info-3
                b"\x1c\x40\x75\xf3",
                b"\xd3\x48\x21\x61",
                // Hop-1-1
                b"\x6b\x80\xa9\xb7\x25\x58\xbe\xa8\x7c\x1e\x93\x71",
                // Hop-2-1, Hop-2-2
                b"\x97\xca\xc2\xb6\x91\x99\x75\x2d\x7a\x6a\xa4\x9f",
                b"\x67\x83\xea\x67\x39\x02\x05\x49\xe6\x0a\xe7\x36",
                // Hop-3-1, Hop-3-2, Hop-3-3
                b"\xb5\x83\xd1\xf7\x27\xbf\xc2\x95\x1a\xdc\x05\x5f",
                b"\xcb\x66\x78\xca\xa6\xb0\x8e\x1b\x92\x4c\x79\xa5",
                b"\xf9\x77\x08\xde\xdf\x39\xef\xa9\x10\x40\x23\xca",
            ],
            times: [0xa31ab421, 0xd77672f2, 0xd3482161],
            interfaces: [
                &[(0xa9b7, 0x2558)],
                &[(0xc2b6, 0x9199), (0xea67, 0x3902)],
                &[(0xd1f7, 0x27bf), (0x78ca, 0xa6b0), (0x08de, 0xdf39)]
            ]
        }
    }
}
