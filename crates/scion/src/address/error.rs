use std::fmt::Display;

/// An error which can be returned when parsing a SCION socket address, host address, or
/// ISD identifier, AS number, or ISD-AS number.
#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
pub struct AddressParseError(pub(super) AddressKind);

impl Display for AddressParseError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self.0 {
            AddressKind::Isd => "invalid ISD number syntax",
            AddressKind::Asn => "invalid AS number syntax",
            AddressKind::IsdAsn => "invalid ISD-AS number syntax",
            AddressKind::Service => "invalid service address syntax",
            AddressKind::SocketV4 => "invalid SCION-IPv4 socket address syntax",
            AddressKind::SocketV6 => "invalid SCION-IPv6 socket address syntax",
            AddressKind::SocketSvc => "invalid service socket address syntax",
            AddressKind::Socket => "invalid socket address syntax",
        };

        fmt.write_str(description)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AddressKind {
    Isd,
    Asn,
    IsdAsn,
    Service,
    Socket,
    SocketV4,
    SocketV6,
    SocketSvc,
}

impl From<AddressKind> for AddressParseError {
    fn from(value: AddressKind) -> Self {
        Self(value)
    }
}
