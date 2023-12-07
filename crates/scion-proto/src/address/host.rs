use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ServiceAddr;

/// The AS-local host identifier of a SCION address.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HostAddr {
    /// An IPv4 host address
    V4(Ipv4Addr),
    /// An IPv6 host address
    V6(Ipv6Addr),
    /// A SCION-service host address
    Svc(ServiceAddr),
}

impl From<Ipv4Addr> for HostAddr {
    fn from(value: Ipv4Addr) -> Self {
        HostAddr::V4(value)
    }
}

impl From<Ipv6Addr> for HostAddr {
    fn from(value: Ipv6Addr) -> Self {
        HostAddr::V6(value)
    }
}

impl From<IpAddr> for HostAddr {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => HostAddr::V4(addr),
            IpAddr::V6(addr) => HostAddr::V6(addr),
        }
    }
}

/// Enum to discriminate among different types of Host addresses.
#[repr(u8)]
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum HostType {
    None = 0,
    Ipv4,
    Ipv6,
    Svc,
}

impl HostType {
    /// Convert a byte host-address type to its enum variant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::HostType;
    /// assert_eq!(HostType::from_byte(0), Some(HostType::None));
    /// assert_eq!(HostType::from_byte(1), Some(HostType::Ipv4));
    /// assert_eq!(HostType::from_byte(2), Some(HostType::Ipv6));
    /// assert_eq!(HostType::from_byte(3), Some(HostType::Svc));
    /// assert_eq!(HostType::from_byte(4), None);
    /// ```
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(HostType::None),
            1 => Some(HostType::Ipv4),
            2 => Some(HostType::Ipv6),
            3 => Some(HostType::Svc),
            _ => None,
        }
    }
}

impl From<HostType> for u8 {
    fn from(value: HostType) -> Self {
        value as u8
    }
}

impl From<IpAddr> for HostType {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => HostType::Ipv4,
            IpAddr::V6(_) => HostType::Ipv6,
        }
    }
}

impl From<Ipv4Addr> for HostType {
    fn from(_: Ipv4Addr) -> Self {
        HostType::Ipv4
    }
}

impl From<Ipv6Addr> for HostType {
    fn from(_: Ipv6Addr) -> Self {
        HostType::Ipv6
    }
}

impl<T: Into<HostType>> From<Option<T>> for HostType {
    fn from(value: Option<T>) -> Self {
        value.map(Into::into).unwrap_or(HostType::None)
    }
}
