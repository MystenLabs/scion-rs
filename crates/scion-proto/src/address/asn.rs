use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use super::{error::AddressKind, AddressParseError};

/// A SCION autonomous system (AS) number
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Asn(u64);

impl Asn {
    /// A SCION AS number representing the wildcard AS.
    pub const WILDCARD: Self = Self(0);
    /// The number of bits in a SCION AS number
    pub const BITS: u32 = 48;

    const BITS_PER_PART: u32 = 16;
    const NUMBER_PARTS: u32 = 3;
    const MAX_VALUE: u64 = (1 << Self::BITS) - 1;

    /// Creates a new AS from a u64 value.
    ///
    /// # Panics
    ///
    /// This function panics if the provided id is greater than the maximum AS number, 2^48 - 1.
    pub fn new(id: u64) -> Self {
        Asn::try_from(id).expect("value within AS number range")
    }

    /// Returns the AS number as a u64 integer.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Return true for the special 'wildcard' AS number, 0.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Asn;
    /// assert!(Asn::WILDCARD.is_wildcard());
    /// assert!(!Asn::new(1).is_wildcard());
    /// ```
    pub fn is_wildcard(&self) -> bool {
        self == &Self::WILDCARD
    }
}

impl Display for Asn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        const BGP_ASN_FORMAT_BOUNDARY: u64 = u16::MAX as u64;

        if self.as_u64() <= BGP_ASN_FORMAT_BOUNDARY {
            return write!(f, "{}", self.as_u64());
        }

        for i in (0..Asn::NUMBER_PARTS).rev() {
            let asn_part = self.as_u64() >> (Asn::BITS_PER_PART * i) & u64::from(u16::MAX);
            let separator = if i != 0 { ":" } else { "" };

            write!(f, "{:x}{}", asn_part, separator)?;
        }

        Ok(())
    }
}

impl From<Asn> for u64 {
    fn from(value: Asn) -> Self {
        value.as_u64()
    }
}

impl TryFrom<u64> for Asn {
    type Error = AddressParseError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > Asn::MAX_VALUE {
            Err(AddressKind::Asn.into())
        } else {
            Ok(Asn(value))
        }
    }
}

impl FromStr for Asn {
    type Err = AddressParseError;

    fn from_str(asn_string: &str) -> Result<Self, Self::Err> {
        // AS numbers less than 2^16 can be provided as decimal
        if let Ok(bgp_asn) = u64::from_str(asn_string) {
            return if bgp_asn <= u16::MAX.into() {
                Ok(Self(bgp_asn))
            } else {
                Err(AddressKind::Asn.into())
            };
        }

        let max_splits = usize::try_from(Asn::NUMBER_PARTS).expect("few parts");
        let result = asn_string.splitn(max_splits, ':').try_fold(
            (0u64, 0u32),
            |(asn_value, n_parts), asn_part| {
                u16::from_str_radix(asn_part, 16).map(|value| {
                    (
                        (asn_value << Asn::BITS_PER_PART) | u64::from(value),
                        n_parts + 1,
                    )
                })
            },
        );

        if let Ok((value, Asn::NUMBER_PARTS)) = result {
            // Can not panic as the result is at most 48 bits (exactly 3 parts, 16 bits each)
            Ok(Asn::new(value))
        } else {
            Err(AddressKind::Asn.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod conversion {
        use super::*;

        macro_rules! test_success {
            ($name:ident, $number:expr, $asn:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(Asn::try_from($number).unwrap(), $asn);
                    assert_eq!(u64::from($asn), $number);
                }
            };
        }

        test_success!(wildcard, 0, Asn::WILDCARD);
        test_success!(max_value, Asn::MAX_VALUE, Asn(0xffff_ffff_ffff));

        #[test]
        fn out_of_range() {
            assert_eq!(
                Asn::try_from(Asn::MAX_VALUE + 1).unwrap_err(),
                AddressParseError(AddressKind::Asn)
            );
        }
    }

    mod parse {
        use super::*;

        macro_rules! test_success {
            ($name:ident, $input:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(Asn::from_str($input).unwrap(), $expected);
                }
            };
        }

        test_success!(zero, "0", Asn::WILDCARD);
        test_success!(zero_with_colon, "0:0:0", Asn::WILDCARD);
        test_success!(low_bit, "0:0:1", Asn(1));
        test_success!(high_bit, "1:0:0", Asn(0x000100000000));
        test_success!(max, "ffff:ffff:ffff", Asn(Asn::MAX_VALUE));
        test_success!(bgp_asn, "65535", Asn(65535));

        macro_rules! test_error {
            ($name:ident, $input:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        Asn::from_str($input).unwrap_err(),
                        AddressParseError(AddressKind::Asn)
                    );
                }
            };
        }

        test_error!(errs_large_decimal_format, "65536");
        test_error!(errs_on_only_colon, ":");
        test_error!(errs_extra_colon, "0:0:0:");
        test_error!(errs_too_few, "0:0");
        test_error!(errs_invalid_part, ":0:0");
        test_error!(errs_out_of_range, "10000:0:0");
        test_error!(errs_out_of_range2, "0:0:10000");
        test_error!(errs_invalid_format, "0:0x0:0");
    }

    mod display {
        use super::*;

        macro_rules! test_display {
            ($name:ident, $asn:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    assert_eq!($asn.to_string(), $expected);
                }
            };
        }

        test_display!(large, Asn(0xff00000000ab), "ff00:0:ab");
        test_display!(large_symmetric, Asn(0x0001fcd10001), "1:fcd1:1");
        test_display!(max, Asn(Asn::MAX_VALUE), "ffff:ffff:ffff");
        test_display!(wildcard, Asn(0), "0");
        test_display!(bgp_asn, Asn(1), "1");
        test_display!(bgp_asn_max, Asn(65535), "65535");
        test_display!(outside_bgp_asn, Asn(65536), "0:1:0");
    }
}
