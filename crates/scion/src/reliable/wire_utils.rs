use crate::address::{HostType, ServiceAddress};

pub(super) const IPV4_OCTETS: usize = 4;
pub(super) const IPV6_OCTETS: usize = 16;
pub(super) const LAYER4_PORT_OCTETS: usize = 2;

pub(super) fn encoded_address_length(host_type: HostType) -> usize {
    match host_type {
        HostType::Svc => ServiceAddress::ENCODED_LENGTH,
        HostType::Ipv4 => IPV4_OCTETS,
        HostType::Ipv6 => IPV6_OCTETS,
        HostType::None => 0,
    }
}

pub(super) fn encoded_port_length(host_type: HostType) -> usize {
    match host_type {
        HostType::None | HostType::Svc => 0,
        HostType::Ipv4 | HostType::Ipv6 => LAYER4_PORT_OCTETS,
    }
}

pub(super) fn encoded_address_and_port_length(host_type: HostType) -> usize {
    encoded_address_length(host_type) + encoded_port_length(host_type)
}
