use std::collections::VecDeque;

use bytes::{Buf, Bytes};

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

/// A queue of Bytes objects implementing the [`bytes::Buf`] trait.
#[derive(Default, Debug)]
pub(super) struct BytesQueue {
    // INV: byte objects are always non-empty
    queue: VecDeque<Bytes>,
    bytes_remaining: usize,
}

impl BytesQueue {
    pub fn pop_front(&mut self) -> Option<Bytes> {
        if let Some(bytes) = self.queue.pop_front() {
            self.bytes_remaining -= bytes.len();
            Some(bytes)
        } else {
            None
        }
    }

    /// Prepend a Bytes to the queue, discarding it if it is empty.
    pub fn push_front(&mut self, value: Bytes) {
        if !value.is_empty() {
            self.increase_remaining(value.len());
            self.queue.push_front(value)
        }
    }

    /// Append a Bytes to the queue, discarding it if it is empty.
    pub fn push_back(&mut self, value: Bytes) {
        if !value.is_empty() {
            self.increase_remaining(value.len());
            self.queue.push_back(value)
        }
    }

    fn increase_remaining(&mut self, value: usize) {
        self.bytes_remaining = self
            .bytes_remaining
            .checked_add(value)
            .expect("never more than usize bytes in total");
    }

    pub(super) fn take_bytes(&mut self, count: usize) -> TakeBytes<'_> {
        assert!(self.remaining() >= count);
        TakeBytes { bytes: self, count }
    }
}

impl Buf for BytesQueue {
    fn remaining(&self) -> usize {
        self.bytes_remaining
    }

    fn chunk(&self) -> &[u8] {
        self.queue.front().map_or(&[], |data| data)
    }

    fn advance(&mut self, cnt: usize) {
        if cnt == 0 {
            return;
        }
        if cnt > self.bytes_remaining {
            panic!(
                "cnt > self.remaining() ({} > {})",
                cnt, self.bytes_remaining
            );
        }

        self.take_bytes(cnt).for_each(drop);
    }
}

pub(super) struct TakeBytes<'a> {
    bytes: &'a mut BytesQueue,
    count: usize,
}

impl<'a> Iterator for TakeBytes<'a> {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }

        let mut data = self.bytes.pop_front().expect("there must be data");

        if data.len() > self.count {
            self.bytes.push_front(data.split_off(self.count));
        }
        assert!(data.len() <= self.count);

        self.count -= data.len();

        Some(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_empty_bytes() {
        let mut bytes_queue = BytesQueue::default();

        bytes_queue.push_back(Bytes::new());
        bytes_queue.push_back(Bytes::from_static(&[0, 1, 2]));
        bytes_queue.push_back(Bytes::new());
        bytes_queue.push_back(Bytes::from_static(&[4, 5, 6]));

        assert!(bytes_queue.queue.iter().all(|data| !data.is_empty()));
    }

    #[test]
    fn has_available_multiple() {
        let mut bytes_queue = BytesQueue::default();

        bytes_queue.push_back(Bytes::from_static(&[0, 1, 2]));
        bytes_queue.push_back(Bytes::from_static(&[4, 5, 6]));

        let mut buffer = [0u8; 6];
        bytes_queue.copy_to_slice(&mut buffer);

        assert_eq!(buffer, [0, 1, 2, 4, 5, 6]);
    }
}
