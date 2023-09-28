use std::{
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

use serde::Deserialize;

use super::{AddressParseError, Asn, Isd};

/// The combined ISD and AS identifier of a SCION AS (sometimes abbreviated as IA).
#[derive(Copy, Clone, Eq, PartialEq, Deserialize, Hash)]
#[serde(try_from = "String")]
pub struct IsdAsn(u64);

impl IsdAsn {
    /// A SCION IA of the special wildcard IA, 0-0.
    pub const WILDCARD: Self = Self(0);

    /// Construct a new identifier from ISD and AS identifiers.
    pub fn new(isd: Isd, asn: Asn) -> Self {
        Self(u64::from(isd.as_u16()) << Asn::BITS | asn.as_u64())
    }

    /// Return the ISD associated with this identifier.
    pub fn isd(&self) -> Isd {
        Isd::new(u16::try_from(self.0 >> Asn::BITS).expect("only the 16 high-order bits"))
    }

    /// Return the AS number associated with this identifier.
    pub fn asn(&self) -> Asn {
        Asn::new(self.0 & 0xffff_ffff_ffff)
    }

    /// Return true if either the ISD or AS numbers are wildcards
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion::address::{Asn,IsdAsn,Isd};
    /// assert!(IsdAsn::new(Isd::WILDCARD,Asn::new(1)).is_wildcard());
    /// assert!(IsdAsn::new(Isd::new(1),Asn::WILDCARD).is_wildcard());
    /// assert!(!IsdAsn::new(Isd::new(1),Asn::new(1)).is_wildcard());
    /// ```
    pub fn is_wildcard(&self) -> bool {
        self.isd().is_wildcard() || self.asn().is_wildcard()
    }

    /// Return the IA as a 64-bit integer.
    ///
    /// The highest 16 bits constitute the ISD number, and the lower 48 bits form the
    /// AS number.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Debug for IsdAsn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("IA({:#018x})", self.0))
    }
}

impl Display for IsdAsn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.isd(), self.asn())
    }
}

impl FromStr for IsdAsn {
    type Err = AddressParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let n_separators = string.chars().filter(|c| *c == '-').take(2).count();
        if n_separators != 1 {
            return Err(Self::Err::InvalidIaString(string.into()));
        }

        let (isd_str, asn_str) = string
            .split_once('-')
            .expect("already checked that the string contains exactly one '-'");
        Ok(IsdAsn::new(
            Isd::from_str(isd_str)?,
            Asn::from_str(asn_str)?,
        ))
    }
}

impl TryFrom<String> for IsdAsn {
    type Error = AddressParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl From<IsdAsn> for u64 {
    fn from(value: IsdAsn) -> Self {
        value.as_u64()
    }
}

impl From<u64> for IsdAsn {
    fn from(value: u64) -> Self {
        IsdAsn(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Asn, Isd};

    macro_rules! test_new_and_get {
        ($name:ident, $ia:expr, $isd:expr, $asn:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn construct() {
                    assert_eq!($ia, IsdAsn::new($isd, $asn));
                }

                #[test]
                fn get_isd() {
                    assert_eq!($isd, $ia.isd());
                }

                #[test]
                fn get_asn() {
                    assert_eq!($asn, $ia.asn());
                }
            }
        };
    }

    test_new_and_get!(wildcard, IsdAsn(0), Isd::new(0), Asn::new(0));
    test_new_and_get!(
        long,
        IsdAsn(0x0001_ff00_0000_00ab),
        Isd::new(1),
        Asn::new(0xff00_0000_00ab)
    );
    test_new_and_get!(
        max_and_min,
        IsdAsn(0xffff_0000_0000_0000),
        Isd::new(0xffff),
        Asn::new(0)
    );
    test_new_and_get!(
        min_and_max,
        IsdAsn(0x0000_ffff_ffff_ffff),
        Isd::new(0),
        Asn::new(0xffff_ffff_ffff)
    );

    mod conversion {
        use super::*;

        #[test]
        fn as_u64() {
            assert_eq!(
                IsdAsn::new(Isd::new(0x0123), Asn::new(0x4567_89ab_cdef)).as_u64(),
                0x0123_4567_89ab_cdef
            )
        }

        macro_rules! test_success {
            ($name:ident, $number:expr, $ia:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(IsdAsn::from($number), $ia);
                    assert_eq!(u64::from($ia), $number);
                }
            };
        }

        test_success!(wildcard, 0, IsdAsn::new(Isd::WILDCARD, Asn::WILDCARD));
        test_success!(max_value, -1_i64 as u64, IsdAsn(0xffff_ffff_ffff_ffff));
    }

    mod display {
        use super::*;

        #[test]
        fn debug() {
            assert_eq!(
                format!("{:?}", IsdAsn(0x0001_ff00_0000_00ab)),
                "IA(0x0001ff00000000ab)"
            );
        }

        #[test]
        fn simple() {
            assert_eq!(IsdAsn(0x0001_ff00_0000_00ab).to_string(), "1-ff00:0:ab");
        }

        #[test]
        fn wildcard() {
            assert_eq!(IsdAsn(0).to_string(), "0-0");
        }

        #[test]
        fn max_ia() {
            assert_eq!(
                IsdAsn(0xffff_ffff_ffff_ffff).to_string(),
                "65535-ffff:ffff:ffff"
            );
        }
    }

    mod parse {
        use super::*;

        macro_rules! test_success {
            ($name:ident, $input:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(IsdAsn::from_str($input).unwrap(), $expected);
                    assert_eq!(IsdAsn::try_from($input.to_string()).unwrap(), $expected);
                }
            };
        }

        test_success!(max, "65535-ffff:ffff:ffff", IsdAsn(0xffff_ffff_ffff_ffff));
        test_success!(wildcard, "0-0", IsdAsn::WILDCARD);
        test_success!(min_non_wildcard, "1-0:0:1", IsdAsn(0x0001_0000_0000_0001));

        #[test]
        fn invalid() {
            assert_eq!(
                IsdAsn::from_str("a-0:0:1").unwrap_err(),
                AddressParseError::InvalidIsdString("a".into())
            );
        }

        #[test]
        fn invalid_parts() {
            assert_eq!(
                IsdAsn::from_str("1-1-0:0:1").unwrap_err(),
                AddressParseError::InvalidIaString("1-1-0:0:1".into())
            );
        }
    }
}
