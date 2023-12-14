use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use super::{error::AddressKind, AddressParseError};

/// Identifier of a SCION Isolation Domain.
///
/// See formatting and allocations [here][isd-and-as-numbering].
///
/// [isd-and-as-numbering]: https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#isd-numbers
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Isd(u16);

impl Isd {
    /// The SCION ISD number representing the wildcard ISD.
    pub const WILDCARD: Self = Self(0);
    /// The number of bits in a SCION ISD number
    pub const BITS: u32 = u16::BITS;

    /// Create a new ISD from a 16-bit value.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Return the identifier as a 16-bit value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// Return true for the special 'wildcard' AS number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Isd;
    /// assert!(Isd::WILDCARD.is_wildcard());
    /// assert!(!Isd::new(1).is_wildcard());
    /// ```
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
        u16::from_str(string)
            .map(Isd::new)
            .or(Err(AddressKind::Isd.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod display {
        use super::*;

        #[test]
        fn wildcard() {
            assert_eq!(Isd::WILDCARD.to_string(), "0");
        }
    }
}
