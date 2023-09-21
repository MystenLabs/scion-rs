use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use thiserror;

use super::{HostAddress, HostType};

/// A SCION service address.
///
/// A service address is a short identifier used to send anycast or multicast
/// messages to SCION services.
///
/// # Textual Representation
///
/// Service addresses can also be represented as strings, for example CS and CS_A
/// both represent the anycast service address ServiceAddress::CONTROL. The
/// corresponding multicast service address would be CS_M.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct ServiceAddress(u16);

impl ServiceAddress {
    /// SCION daemon anycast service address (DS_A)
    pub const DAEMON: Self = Self(0x0001);
    /// SCION control-service anycast address (CS_A)
    pub const CONTROL: Self = Self(0x0002);
    /// Wildcard service address (Wildcard_A)
    pub const WILDCARD: Self = Self(0x0010);

    #[allow(unused)]
    /// Special none service address value.
    const NONE: Self = Self(0xffff);
    /// Flag bit indicating whether the address includes multicast
    const MULTICAST_FLAG: u16 = 0x8000;

    /// Returns true if the service address is multicast, false otherwise.
    pub fn is_multicast(&self) -> bool {
        (self.0 & Self::MULTICAST_FLAG) == Self::MULTICAST_FLAG
    }

    /// Sets the service address to be multicast.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion::address::ServiceAddress;
    /// assert!(!ServiceAddress::DAEMON.is_multicast());
    /// assert!(ServiceAddress::DAEMON.multicast().is_multicast());
    /// ```
    pub fn multicast(self) -> Self {
        Self(self.0 | Self::MULTICAST_FLAG)
    }

    /// Sets the service address to be anycast, disabling multicast
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion::address::ServiceAddress;
    /// assert!(ServiceAddress::DAEMON.multicast().anycast().is_anycast());
    /// assert!(!ServiceAddress::DAEMON.multicast().anycast().is_multicast());
    /// ```
    pub fn anycast(self) -> Self {
        Self(self.0 & !Self::MULTICAST_FLAG)
    }

    /// Returns true if the service address is anycast, false otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion::address::ServiceAddress;
    /// assert!(ServiceAddress::DAEMON.is_anycast());
    /// assert!(!ServiceAddress::DAEMON.multicast().is_anycast());
    /// ```
    pub fn is_anycast(&self) -> bool {
        (self.0 & Self::MULTICAST_FLAG) == 0
    }
}

#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
#[error("invalid service address string: {0}")]
pub struct ParseServiceAddressError(String);

impl FromStr for ServiceAddress {
    type Err = ParseServiceAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (service, suffix) = s.split_once('_').unwrap_or((s, "A"));

        let address = match service {
            "CS" => ServiceAddress::CONTROL,
            "DS" => ServiceAddress::DAEMON,
            "Wildcard" => ServiceAddress::WILDCARD,
            _ => return Err(ParseServiceAddressError(s.into())),
        };
        match suffix {
            "A" => Ok(address),
            "M" => Ok(address.multicast()),
            _ => Err(ParseServiceAddressError(s.into())),
        }
    }
}

impl Display for ServiceAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.anycast() {
            ServiceAddress::DAEMON => write!(f, "DS")?,
            ServiceAddress::CONTROL => write!(f, "CS")?,
            ServiceAddress::WILDCARD => write!(f, "Wildcard")?,
            ServiceAddress(value) => write!(f, "<SVC:{:#06x}>", value)?,
        }

        if self.is_multicast() {
            write!(f, "_M")?;
        }

        Ok(())
    }
}

impl HostAddress for ServiceAddress {
    fn host_address_type(&self) -> HostType {
        HostType::Svc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_multicast() {
        assert!(!ServiceAddress::DAEMON.is_multicast());
        assert!(ServiceAddress::DAEMON.multicast().is_multicast());
    }

    mod parse {
        use super::*;

        macro_rules! test_success {
            ($name:ident, $str:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(ServiceAddress::from_str($str).unwrap(), $expected);
                }
            };
        }

        test_success!(control, "CS_A", ServiceAddress::CONTROL);
        test_success!(control_shorthand, "CS", ServiceAddress::CONTROL);
        test_success!(daemon, "DS_A", ServiceAddress::DAEMON);
        test_success!(daemon_shorthand, "DS", ServiceAddress::DAEMON);
        test_success!(wildcard, "Wildcard_A", ServiceAddress::WILDCARD);
        test_success!(wildcard_shorthand, "Wildcard", ServiceAddress::WILDCARD);
        test_success!(
            control_multicast,
            "CS_M",
            ServiceAddress::CONTROL.multicast()
        );
        test_success!(daemon_multicast, "DS_M", ServiceAddress::DAEMON.multicast());
        test_success!(
            wildcard_multicast,
            "Wildcard_M",
            ServiceAddress::WILDCARD.multicast()
        );

        macro_rules! test_error {
            ($name:ident, $str:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        ServiceAddress::from_str($str).unwrap_err(),
                        ParseServiceAddressError($str.into())
                    );
                }
            };
        }

        test_error!(empty, "");
        test_error!(bad_value, "garbage");
        test_error!(invalid_suffix, "CS_Y");
        test_error!(lowercase_anycast, "cs_a");
        test_error!(lowercase_multicast, "cs_m");
        test_error!(trailing_space, "CS ");
        test_error!(leading_space, " CS ");
    }

    mod display {
        use super::*;

        macro_rules! test_display {
            ($name:ident, $addr:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    assert_eq!($addr.to_string(), $expected);
                }
            };
        }

        test_display!(unknown, ServiceAddress(0xABC), "<SVC:0x0abc>");
        test_display!(control, ServiceAddress::CONTROL, "CS");
        test_display!(
            control_multicast,
            ServiceAddress::CONTROL.multicast(),
            "CS_M"
        );
        test_display!(daemon, ServiceAddress::DAEMON, "DS");
        test_display!(daemon_multicast, ServiceAddress::DAEMON.multicast(), "DS_M");
        test_display!(wildcard, ServiceAddress::WILDCARD, "Wildcard");
        test_display!(
            wildcard_multicast,
            ServiceAddress::WILDCARD.multicast(),
            "Wildcard_M"
        );
    }
}
