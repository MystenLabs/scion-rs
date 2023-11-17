use std::fmt::Display;

pub mod standard;

pub mod error;
pub use error::{PathParseError, PathParseErrorKind};

mod cp_path;
pub use cp_path::{GeoCoordinates, Path, PathMetadata};

pub mod epic;
pub use epic::EpicAuths;

pub mod linktype;
pub use linktype::LinkType;

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum PathErrorKind {
    InvalidSegmentLengths,
    InfoFieldOutOfRange,
    HopFieldOutOfRange,
}

impl Display for PathErrorKind {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            PathErrorKind::InvalidSegmentLengths => "the sequence of segment lengths are invalid",
            PathErrorKind::InfoFieldOutOfRange => "the current info field index is too large",
            PathErrorKind::HopFieldOutOfRange => {
                "the current hop field index is outside the range of the current info field"
            }
        };
        fmt.write_str(description)
    }
}
