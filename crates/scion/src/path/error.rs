use std::fmt::Display;

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
/// Error kinds for dataplane paths.
pub enum DataplanePathErrorKind {
    InvalidSegmentLengths,
    InfoFieldOutOfRange,
    HopFieldOutOfRange,
}

impl Display for DataplanePathErrorKind {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            DataplanePathErrorKind::InvalidSegmentLengths => {
                "the sequence of segment lengths are invalid"
            }
            DataplanePathErrorKind::InfoFieldOutOfRange => {
                "the current info field index is too large"
            }
            DataplanePathErrorKind::HopFieldOutOfRange => {
                "the current hop field index is outside the range of the current info field"
            }
        };
        fmt.write_str(description)
    }
}

/// An error which can be returned when parsing a SCION path with metadata.
#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
pub struct PathParseError(PathParseErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathParseErrorKind {
    EmptyRaw,
    NoInterface,
    InvalidInterface,
    InvalidPathInterface,
    InvalidExpiration,
    NegativeLatency,
    InvalidLatency,
    InvalidLinkType,
    InvalidMtu,
}

impl Display for PathParseError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self.0 {
            PathParseErrorKind::EmptyRaw => "Empty raw path",
            PathParseErrorKind::NoInterface => "No underlay address for local border router",
            PathParseErrorKind::InvalidInterface => {
                "Invalid underlay address for local border router"
            }
            PathParseErrorKind::InvalidPathInterface => "Invalid interface for on-path AS",
            PathParseErrorKind::InvalidExpiration => "Invalid expiration timestamp",
            PathParseErrorKind::NegativeLatency => "Negative on-path latency",
            PathParseErrorKind::InvalidLatency => "Invalid on-path latency",
            PathParseErrorKind::InvalidLinkType => "Invalid link type",
            PathParseErrorKind::InvalidMtu => "Invalid MTU",
        };

        fmt.write_str(description)
    }
}

impl From<PathParseErrorKind> for PathParseError {
    fn from(value: PathParseErrorKind) -> Self {
        Self(value)
    }
}
