//! SCION endhost addresses.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{error::AddressKind, AddressParseError, HostAddr, IsdAsn, ServiceAddr};

/// A SCION network address.
///
/// SCION network addresses consist of an ISD-AS number, and either an [IPv4 address][`Ipv4Addr`],
/// an [IPv6 address][`Ipv6Addr`], or a [SCION service address][`ServiceAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScionAddr {
    /// An IPv4 network address
    V4(ScionAddrV4),
    /// An IPv6 network address
    V6(ScionAddrV6),
    /// An SCION service network address
    Svc(ScionAddrSvc),
}

impl ScionAddr {
    /// Creates a new SCION address based on the [`IsdAsn`] of the AS and the endhost's
    /// [`HostAddr`].
    pub const fn new(isd_asn: IsdAsn, host: HostAddr) -> Self {
        match host {
            HostAddr::V4(host) => Self::V4(ScionAddrV4::new(isd_asn, host)),
            HostAddr::V6(host) => Self::V6(ScionAddrV6::new(isd_asn, host)),
            HostAddr::Svc(host) => Self::Svc(ScionAddrSvc::new(isd_asn, host)),
        }
    }

    /// Returns the host associated with this socket address.
    pub const fn host(&self) -> HostAddr {
        match self {
            ScionAddr::V4(addr) => HostAddr::V4(*addr.host()),
            ScionAddr::V6(addr) => HostAddr::V6(*addr.host()),
            ScionAddr::Svc(addr) => HostAddr::Svc(*addr.host()),
        }
    }

    /// Changes the host address associated with this SCION address.
    pub fn set_host(&mut self, host: HostAddr) {
        *self = Self::new(self.isd_asn(), host);
    }

    /// Returns the ISD-AS number associated with this SCION address.
    pub const fn isd_asn(&self) -> IsdAsn {
        match self {
            ScionAddr::V4(addr) => addr.isd_asn(),
            ScionAddr::V6(addr) => addr.isd_asn(),
            ScionAddr::Svc(addr) => addr.isd_asn(),
        }
    }

    /// Changes the ISD-AS number associated with this SCION address.
    pub fn set_isd_asn(&mut self, new_isd_asn: IsdAsn) {
        match self {
            ScionAddr::V4(addr) => addr.set_isd_asn(new_isd_asn),
            ScionAddr::V6(addr) => addr.set_isd_asn(new_isd_asn),
            ScionAddr::Svc(addr) => addr.set_isd_asn(new_isd_asn),
        }
    }
}

macro_rules! impl_from {
    ($base:ty, $variant:expr) => {
        impl From<$base> for ScionAddr {
            #[inline]
            fn from(value: $base) -> Self {
                $variant(value)
            }
        }
    };
}

impl_from!(ScionAddrV4, ScionAddr::V4);
impl_from!(ScionAddrV6, ScionAddr::V6);
impl_from!(ScionAddrSvc, ScionAddr::Svc);

impl From<(IsdAsn, HostAddr)> for ScionAddr {
    #[inline]
    fn from((isd_asn, host): (IsdAsn, HostAddr)) -> Self {
        Self::new(isd_asn, host)
    }
}

impl core::fmt::Display for ScionAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScionAddr::V4(addr) => addr.fmt(f),
            ScionAddr::V6(addr) => addr.fmt(f),
            ScionAddr::Svc(addr) => addr.fmt(f),
        }
    }
}

impl core::str::FromStr for ScionAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = ScionAddrSvc::from_str(s) {
            Ok(ScionAddr::Svc(addr))
        } else if let Ok(addr) = ScionAddrV4::from_str(s) {
            Ok(ScionAddr::V4(addr))
        } else if let Ok(addr) = ScionAddrV6::from_str(s) {
            Ok(ScionAddr::V6(addr))
        } else {
            Err(AddressKind::Scion.into())
        }
    }
}

macro_rules! scion_address {
    (
        $(#[$outer:meta])*
        pub struct $name:ident{host: $host_type:ty, kind: $kind:path};
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
        pub struct $name {
            isd_asn: IsdAsn,
            host: $host_type,
        }

        impl $name {
            /// Creates a new SCION address from an [ISD-AS number][`IsdAsn`] and host.
            pub const fn new(isd_asn: IsdAsn, host: $host_type) -> Self {
                Self { isd_asn, host }
            }

            /// Returns the host associated with this socket address.
            pub const fn host(&self) -> &$host_type {
                &self.host
            }

            /// Changes the host address associated with this SCION address.
            pub fn set_host(&mut self, host: $host_type) {
                self.host = host;
            }

            /// Returns the ISD-AS number associated with this SCION address.
            pub const fn isd_asn(&self) -> IsdAsn {
                self.isd_asn
            }

            /// Changes the ISD-AS number associated with this SCION address.
            pub fn set_isd_asn(&mut self, new_isd_asn: IsdAsn) {
                self.isd_asn = new_isd_asn;
            }
        }

        impl From<(IsdAsn, $host_type)> for $name {
            fn from((isd_asn, host): (IsdAsn, $host_type)) -> Self {
                Self { isd_asn, host }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{},{}", self.isd_asn(), self.host())
            }
        }

        impl core::str::FromStr for $name {
            type Err = AddressParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                s.split_once(',')
                    .and_then(|(ia_str, host_str)| {
                        ia_str.parse().ok().zip(host_str.parse().ok())
                    })
                    .map(|(isd_asn, host)| Self {isd_asn, host})
                    .ok_or(AddressParseError($kind))
            }
        }
    };
}

scion_address! {
    /// A SCION IPv4 address.
    ///
    /// SCION IPv4 addresses consist of a SCION ISD-AS number and an IPv4 address.
    ///
    /// See [`ScionAddr`] for a type encompassing SCION IPv4, IPv6, and Service addresses.
    pub struct ScionAddrV4 {host: Ipv4Addr, kind: AddressKind::ScionV4};
}

scion_address! {
    /// A SCION IPv6 address.
    ///
    /// SCION IPv6 addresses consist of a SCION ISD-AS number and an IPv6 address.
    ///
    /// See [`ScionAddr`] for a type encompassing SCION IPv4, IPv6, and Service addresses.
    pub struct ScionAddrV6 {host: Ipv6Addr, kind: AddressKind::ScionV6};
}

scion_address! {
    /// A SCION service address.
    ///
    /// SCION service addresses consist of a SCION ISD-AS number and a service address.
    ///
    /// See [`ScionAddr`] for a type encompassing SCION IPv4, IPv6, and Service addresses.
    pub struct ScionAddrSvc {host: ServiceAddr, kind: AddressKind::ScionSvc};
}
