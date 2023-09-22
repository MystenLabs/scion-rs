use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use super::AddressParseError;

/// Identifier of a SCION Isolation Domain
///
/// See formatting and allocations here:
/// https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#isd-numbers
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Isd(u16);

impl Isd {
    /// The SCION ISD number representing the wildcard ISD.
    pub const WILDCARD: Self = Self(0);
    /// The number of bits in a SCION ISD number
    pub const BITS: u32 = u16::BITS;

    /// Create a new ISD from a 16-bit value.
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Return the identifier as a 16-bit value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    // Return true for the special 'wildcard' AS number
    pub fn is_wildcard(&self) -> bool {
        self == &Self::WILDCARD
    }
}

impl Display for Isd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Isd {
    type Err = AddressParseError;

    /// Parses an ISD from a decimal string.
    ///
    /// ISD 0 is parsed without any errors.
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if let Ok(value) = u16::from_str(string) {
            Ok(Isd::new(value))
        } else {
            Err(Self::Err::InvalidIsdString(string.into()))
        }
    }
}
