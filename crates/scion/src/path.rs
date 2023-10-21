use std::fmt::Display;

pub mod standard;

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum PathErrorKind {
    InvalidSegmentLengths,
    InfoFieldOutOfRange,
    HopFieldOutOfRange,
}

impl Display for PathErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            PathErrorKind::InvalidSegmentLengths => {
                f.write_str("the sequence of segment lengths are invalid")
            }
            PathErrorKind::InfoFieldOutOfRange => {
                f.write_str("the current info field index is too large")
            }
            PathErrorKind::HopFieldOutOfRange => f.write_str(
                "the current hop field index is outside the range of the current info field",
            ),
        }
    }
}
