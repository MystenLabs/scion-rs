use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use super::{error::AddressKind, AddressParseError, Host, IsdAsn, ServiceAddress};

/// A SCION socket address.
///
/// SCION socket addresses consist of an ISD-AS number, a 16-bit port identifier, and either an
/// [IPv4 address][`Ipv4Addr`], an [IPv6 address][`Ipv6Addr`], or a
/// [SCION service address][`ServiceAddress`].
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum SocketAddr {
    /// An IPv4 socket address.
    V4(SocketAddrV4),
    /// An IPv6 socket address.
    V6(SocketAddrV6),
    /// A SCION service socket address.
    Svc(SocketAddrSvc),
}

impl SocketAddr {
    /// Returns the host address associated with this socket address.
    pub const fn host(&self) -> Host {
        match self {
            SocketAddr::V4(addr) => Host::Ip(IpAddr::V4(*addr.ip())),
            SocketAddr::V6(addr) => Host::Ip(IpAddr::V6(*addr.ip())),
            SocketAddr::Svc(addr) => Host::Svc(*addr.service()),
        }
    }

    /// Returns true if this socket address stores an IPv4 or IPv6 address, and false otherwise.
    pub const fn is_ip(&self) -> bool {
        !matches!(*self, Self::Svc(_))
    }

    /// Returns true if this socket address stores a SCION service address, and false otherwise.
    pub const fn is_service(&self) -> bool {
        matches!(*self, Self::Svc(_))
    }

    /// Returns the port number associated with this socket address.
    pub const fn port(&self) -> u16 {
        match self {
            Self::V4(addr) => addr.port(),
            Self::V6(addr) => addr.port(),
            Self::Svc(addr) => addr.port(),
        }
    }

    /// Changes the port number associated with this socket address.
    pub fn set_port(&mut self, new_port: u16) {
        match self {
            Self::V4(addr) => addr.set_port(new_port),
            Self::V6(addr) => addr.set_port(new_port),
            Self::Svc(addr) => addr.set_port(new_port),
        }
    }
}

impl From<SocketAddrV4> for SocketAddr {
    /// Converts a [`SocketAddrV4`] into a [`SocketAddr::V4`].
    #[inline]
    fn from(value: SocketAddrV4) -> Self {
        SocketAddr::V4(value)
    }
}

impl From<SocketAddrV6> for SocketAddr {
    /// Converts a [`SocketAddrV6`] into a [`SocketAddr::V6`].
    #[inline]
    fn from(value: SocketAddrV6) -> Self {
        SocketAddr::V6(value)
    }
}

impl From<SocketAddrSvc> for SocketAddr {
    /// Converts a [`SocketAddrSvc`] into a [`SocketAddr::Svc`].
    #[inline]
    fn from(value: SocketAddrSvc) -> Self {
        SocketAddr::Svc(value)
    }
}

impl FromStr for SocketAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddrSvc::from_str(s)
            .map(SocketAddr::Svc)
            .or_else(|_| SocketAddrV4::from_str(s).map(SocketAddr::V4))
            .or_else(|_| SocketAddrV6::from_str(s).map(SocketAddr::V6))
            .or(Err(AddressKind::Socket.into()))
    }
}

impl Display for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketAddr::V4(addr) => addr.fmt(f),
            SocketAddr::V6(addr) => addr.fmt(f),
            SocketAddr::Svc(addr) => addr.fmt(f),
        }
    }
}

macro_rules! impl_socket_address {
    () => {
        /// Returns the ISD-AS number associated with this socket address.
        pub const fn isd_asn(&self) -> IsdAsn {
            self.isd_asn
        }

        /// Returns the port number associated with this socket address.
        pub const fn port(&self) -> u16 {
            self.port
        }

        /// Changes the ISD-AS number associated with this socket address.
        pub fn set_isd_asn(&mut self, new_isd_asn: IsdAsn) {
            self.isd_asn = new_isd_asn;
        }

        /// Changes the port associated with this socket address.
        pub fn set_port(&mut self, new_port: u16) {
            self.port = new_port;
        }
    };
}

/// A SCION IPv4 socket address.
///
/// SCION IPv4 socket addresses consist of a SCION ISD-AS number, an IPv4 address,
/// and a 16-bit port number.
///
/// See [`SocketAddr`] for a type encompassing IPv4, IPv6, and Service socket addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketAddrV4 {
    isd_asn: IsdAsn,
    ip: Ipv4Addr,
    port: u16,
}

impl SocketAddrV4 {
    /// Creates a new SCION socket address from an [ISD-AS number][`IsdAsn`],
    /// [IPv4 address][`Ipv4Addr`], and port number.
    pub const fn new(isd_asn: IsdAsn, ip: Ipv4Addr, port: u16) -> Self {
        Self { isd_asn, ip, port }
    }

    /// Returns the IP address associated with this socket address.
    pub const fn ip(&self) -> &Ipv4Addr {
        &self.ip
    }

    /// Changes the IP address associated with this socket address.
    pub fn set_ip(&mut self, new_ip: Ipv4Addr) {
        self.ip = new_ip;
    }

    impl_socket_address!();
}

impl Display for SocketAddrV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{},{}]:{}", self.isd_asn(), self.ip(), self.port())
    }
}

impl FromStr for SocketAddrV4 {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((isd_asn, host, port)) = parse_ia_and_port(s) {
            let ip = host
                .parse()
                .or(Err(AddressParseError(AddressKind::SocketV4)))?;

            Ok(Self { isd_asn, port, ip })
        } else {
            Err(AddressKind::SocketV4.into())
        }
    }
}

/// A SCION IPv6 socket address.
///
/// SCION IPv6 socket addresses consist of a SCION ISD-AS number, an IPv6 address,
/// and a 16-bit port number.
///
/// See [`SocketAddr`] for a type encompassing IPv6, IPv6, and Service socket addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketAddrV6 {
    isd_asn: IsdAsn,
    ip: Ipv6Addr,
    port: u16,
}

impl SocketAddrV6 {
    /// Creates a new SCION socket address from an [ISD-AS number][`IsdAsn`],
    /// [IPv6 address][`Ipv6Addr`], and port number.
    pub const fn new(isd_asn: IsdAsn, ip: Ipv6Addr, port: u16) -> Self {
        Self { isd_asn, ip, port }
    }

    /// Returns the IP address associated with this socket address.
    pub const fn ip(&self) -> &Ipv6Addr {
        &self.ip
    }

    /// Changes the IP address associated with this socket address.
    pub fn set_ip(&mut self, new_ip: Ipv6Addr) {
        self.ip = new_ip;
    }

    impl_socket_address!();
}

impl Display for SocketAddrV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{},{}]:{}", self.isd_asn(), self.ip(), self.port())
    }
}

impl FromStr for SocketAddrV6 {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((isd_asn, host, port)) = parse_ia_and_port(s) {
            let ip = host
                .parse()
                .or(Err(AddressParseError(AddressKind::SocketV6)))?;

            Ok(Self { isd_asn, port, ip })
        } else {
            Err(AddressKind::SocketV6.into())
        }
    }
}

/// A SCION service socket address.
///
/// SCION service socket addresses consist of a SCION ISD-AS number, an SCION service address
/// and a 16-bit port number.
///
/// See [`SocketAddr`] for a type encompassing IPv6, IPv6, and Service socket addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketAddrSvc {
    isd_asn: IsdAsn,
    service: ServiceAddress,
    port: u16,
}

impl SocketAddrSvc {
    /// Creates a new SCION socket address from an [ISD-AS number][`IsdAsn`],
    /// [service address][`ServiceAddress`], and port number.
    pub const fn new(isd_asn: IsdAsn, service: ServiceAddress, port: u16) -> Self {
        Self {
            isd_asn,
            service,
            port,
        }
    }

    /// Returns the service address associated with this socket address.
    pub const fn service(&self) -> &ServiceAddress {
        &self.service
    }

    /// Changes the service address associated with this socket address.
    pub fn set_service(&mut self, new_service: ServiceAddress) {
        self.service = new_service;
    }

    impl_socket_address!();
}

impl Display for SocketAddrSvc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{},{}]:{}", self.isd_asn(), self.service(), self.port())
    }
}

impl FromStr for SocketAddrSvc {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((isd_asn, host, port)) = parse_ia_and_port(s) {
            let service = host
                .parse()
                .or(Err(AddressParseError(AddressKind::SocketSvc)))?;

            Ok(Self {
                isd_asn,
                port,
                service,
            })
        } else {
            Err(AddressKind::SocketSvc.into())
        }
    }
}

fn parse_ia_and_port(s: &str) -> Option<(IsdAsn, &str, u16)> {
    let (bracketed_ia_ip, port) = s.rsplit_once(':')?;

    let port: u16 = port.parse().ok()?;

    if bracketed_ia_ip.starts_with('[') && bracketed_ia_ip.ends_with(']') {
        let (isd_asn, host) = bracketed_ia_ip[1..bracketed_ia_ip.len() - 1].split_once(',')?;
        Some((isd_asn.parse().ok()?, host, port))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod from_str {
        use super::*;

        macro_rules! parse_ok {
            ($addr_type:ty, $name:ident, $string:literal, $expected:expr) => {
                #[test]
                fn $name() {
                    let parsed: $addr_type = $string.parse().expect("should succeed");
                    assert_eq!(parsed, $expected);
                }
            };
        }

        macro_rules! parse_errs {
            ($name:ident, $socket_type:ident, $string:literal, $err_kind:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        $socket_type::from_str($string),
                        Err(AddressParseError($err_kind))
                    );
                }
            };
            (IPv4 $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddrV4, $string, AddressKind::SocketV4);
            };
            (IPv6 $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddrV6, $string, AddressKind::SocketV6);
            };
            (Svc $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddrSvc, $string, AddressKind::SocketSvc);
            };
            (Enum $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddr, $string, AddressKind::Socket);
            };
        }

        mod v4 {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddrV4,
                valid,
                "[1-ff00:0:110,10.0.0.1]:8080",
                SocketAddrV4::new(parse!("1-ff00:0:110"), Ipv4Addr::new(10, 0, 0, 1), 8080)
            );

            parse_errs!(IPv4 invalid_ia, "[xxx,192.168.0.1]:80");
            parse_errs!(IPv4 invalid_address, "[1-ff00:0:110,CS_M]:80");
            parse_errs!(IPv4 port_too_large, "[1-ff00:0:110,192.168.0.1]:65536");
        }

        mod v6 {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddrV6,
                valid,
                "[1-ff00:0:110,2001:db8::ff00:42:8329]:443",
                SocketAddrV6::new(
                    parse!("1-ff00:0:110"),
                    parse!("2001:db8::ff00:42:8329"),
                    443
                )
            );

            parse_errs!(IPv6 invalid_ia, "[xxx,2001:db8::ff00:42:8329]:80");
            parse_errs!(IPv6 invalid_address, "[1-ff00:0:110,10.0.0.1]:80");
            parse_errs!(IPv6 port_too_large, "[1-ff00:0:110,2001:db8::ff00:42:8329]:65536");
        }

        mod service {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddrSvc,
                valid,
                "[1-ff00:0:110,CS_M]:443",
                SocketAddrSvc::new(
                    parse!("1-ff00:0:110"),
                    ServiceAddress::CONTROL.multicast(),
                    443
                )
            );

            parse_errs!(Svc invalid_ia, "[xxx,CS_M]:80");
            parse_errs!(Svc invalid_address, "[1-ff00:0:110,2001:db8::ff00:42:8329]:80");
            parse_errs!(Svc port_too_large, "[1-ff00:0:110,DS_A]:65536");
        }

        mod general {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddr,
                valid_service,
                "[1-ff00:0:110,CS_M]:443",
                SocketAddr::Svc(SocketAddrSvc::new(
                    parse!("1-ff00:0:110"),
                    ServiceAddress::CONTROL.multicast(),
                    443
                ))
            );
            parse_ok!(
                SocketAddr,
                valid_v6,
                "[1-ff00:0:110,2001:db8::ff00:42:8329]:443",
                SocketAddr::V6(SocketAddrV6::new(
                    parse!("1-ff00:0:110"),
                    parse!("2001:db8::ff00:42:8329"),
                    443
                ))
            );
            parse_ok!(
                SocketAddr,
                valid_v4,
                "[1-ff00:0:110,10.0.0.1]:8080",
                SocketAddr::V4(SocketAddrV4::new(
                    parse!("1-ff00:0:110"),
                    Ipv4Addr::new(10, 0, 0, 1),
                    8080
                ))
            );

            parse_errs!(Enum invalid_ia, "[xxx,CS_M]:80");
            parse_errs!(Enum invalid_address, "[1-ff00:0:110,xxx]:80");
            parse_errs!(Enum port_too_large, "[1-ff00:0:110,DS_A]:65536");
        }
    }
}
