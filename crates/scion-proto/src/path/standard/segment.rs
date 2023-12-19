use std::{iter::FusedIterator, ops::Range};

use chrono::{DateTime, Utc};

use super::{HopFields, InfoField};

/// A segment of a SCION [`StandardPath`][super::StandardPath].
///
/// Allows retrieving the info and hop fields associated with the path segment,
/// as well as the overall expiry time of the segment.
#[derive(Debug, Clone)]
pub struct Segment<'a> {
    info_field: &'a InfoField,
    hop_fields: HopFields<'a>,
}

impl<'a> Segment<'a> {
    /// Creates a new view of a non-empty segment.
    ///
    /// # Panics
    ///
    /// If hop_fields is empty.
    pub(super) fn new(info_field: &'a InfoField, hop_fields: HopFields<'a>) -> Self {
        assert_ne!(hop_fields.len(), 0);
        Self {
            info_field,
            hop_fields,
        }
    }

    /// Returns the [`InfoField`] associated with this path segment.
    pub fn info_field(&self) -> &InfoField {
        self.info_field
    }

    /// Returns an iterator over the [`HopField`][super::HopField]s associated with this segment.
    pub fn hop_fields(&self) -> HopFields<'a> {
        self.hop_fields.clone()
    }

    /// Returns the expiry time of the segment as the minimum expiry time of all of its hop fields.
    pub fn expiry_time(&self) -> DateTime<Utc> {
        self.hop_fields()
            .map(|hop_field| hop_field.expiry_time(self.info_field()))
            .min()
            .expect("always at least 1 hop field")
    }
}

/// An iterator over the [`Segment`]s in a SCION [`StandardPath`][super::StandardPath].
///
/// This `struct` is created by the [`segments`][super::StandardPath::segments] method on
/// [`StandardPath`][super::StandardPath]. See its documentation for more information.
pub struct Segments<'a> {
    inner: [Option<Segment<'a>>; 3],
    valid_range: Range<usize>,
}

impl<'a> Segments<'a> {
    pub(super) fn new(segments: [Option<Segment<'a>>; 3]) -> Self {
        let end = segments.iter().position(Option::is_none).unwrap_or(3);
        Self {
            inner: segments,
            valid_range: 0..end,
        }
    }
}

impl<'a> Iterator for Segments<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.valid_range.next().map(|idx| {
            self.inner[idx]
                .clone()
                .expect("segment in iterated position is not None")
        })
    }
}

impl DoubleEndedIterator for Segments<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.valid_range.next_back().map(|idx| {
            self.inner[idx]
                .clone()
                .expect("segment in iterated position is not None")
        })
    }
}

impl ExactSizeIterator for Segments<'_> {
    fn len(&self) -> usize {
        self.valid_range.len()
    }
}

impl FusedIterator for Segments<'_> {}
