use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use super::{error::AddressKind, AddressParseError};

/// A 16-bit identifier of a SCION Isolation Domain.
///
/// See [this table][anapaya-assignments] for current ISD network assignments.
///
/// [anapaya-assignments]: https://docs.anapaya.net/en/latest/resources/isd-as-assignments/
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Isd(pub u16);

impl Isd {
    /// The SCION ISD number representing the wildcard ISD.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Isd;
    /// assert_eq!(Isd::WILDCARD, Isd::new(0));
    /// ```
    pub const WILDCARD: Self = Self(0);

    /// Maximum valid ISD identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Isd;
    /// assert_eq!(Isd::MAX, Isd::new(u16::MAX));
    /// ```
    pub const MAX: Self = Self::new(u16::MAX);

    /// The number of bits in a SCION ISD number.
    pub const BITS: u32 = u16::BITS;

    /// Creates a new ISD from a 16-bit value.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Return the identifier as a 16-bit value.
    pub const fn to_u16(&self) -> u16 {
        self.0
    }

    /// Return true for the special 'wildcard' AS number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Isd;
    /// assert!(Isd::WILDCARD.is_wildcard());
    /// assert!(Isd::new(0).is_wildcard());
    /// assert!(!Isd::new(1).is_wildcard());
    /// ```
    pub const fn is_wildcard(&self) -> bool {
        self.0 == Self::WILDCARD.0
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
