use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::ServiceAddress;

/// The AS-local host identifier of a SCION address.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Host {
    /// An IPv4 or IPv6 host address
    Ip(IpAddr),
    /// A SCION-service host address
    Svc(ServiceAddress),
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

/// Trait to be implemented by address types that are supported by SCION
/// as valid AS-host addresses.
pub trait HostAddress {
    /// Return the HostType associated with the host address
    fn host_address_type(&self) -> HostType;
}

impl HostAddress for SocketAddr {
    fn host_address_type(&self) -> HostType {
        self.ip().host_address_type()
    }
}

impl HostAddress for IpAddr {
    fn host_address_type(&self) -> HostType {
        match self {
            IpAddr::V4(_) => HostType::Ipv4,
            IpAddr::V6(_) => HostType::Ipv6,
        }
    }
}

impl HostAddress for Host {
    fn host_address_type(&self) -> HostType {
        match self {
            Host::Ip(ip_address) => ip_address.host_address_type(),
            Host::Svc(service_address) => service_address.host_address_type(),
        }
    }
}

impl<T> HostAddress for Option<T>
where
    T: HostAddress,
{
    fn host_address_type(&self) -> HostType {
        self.as_ref()
            .map(HostAddress::host_address_type)
            .unwrap_or(HostType::None)
    }
}

impl From<IpAddr> for Host {
    fn from(value: IpAddr) -> Self {
        Host::Ip(value)
    }
}

impl From<Ipv4Addr> for Host {
    fn from(value: Ipv4Addr) -> Self {
        Host::Ip(value.into())
    }
}

impl From<Ipv6Addr> for Host {
    fn from(value: Ipv6Addr) -> Self {
        Host::Ip(value.into())
    }
}
