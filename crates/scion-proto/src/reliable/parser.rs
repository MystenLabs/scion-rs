use bytes::{Buf, Bytes};

use super::{
    common_header::{CommonHeader, DecodeError, DecodedHeader},
    wire_utils::BytesQueue,
    Packet,
};

#[derive(Debug)]
enum State {
    Good(StreamParserInner),
    Bad(DecodeError),
}

impl State {
    #[must_use]
    fn to_bad(&self, error: DecodeError) -> Self {
        match self {
            Self::Good(_) => Self::Bad(error),
            Self::Bad(_) => panic!("should not be called in the bad state"),
        }
    }
}

#[derive(Default, Debug)]
struct StreamParserInner {
    byte_queue: BytesQueue,
    next_header: Option<DecodedHeader>,
}

impl StreamParserInner {
    fn remaining(&self) -> usize {
        self.byte_queue.remaining()
    }

    /// Decode and store the next partial or common header available from the data.
    ///
    /// Does nothing if a full common header is already decoded, or if there is insufficient data.
    fn decode_next_header(&mut self) -> Result<(), DecodeError> {
        match &mut self.next_header {
            None if self.byte_queue.remaining() >= CommonHeader::MIN_LENGTH => {
                self.next_header = Some(CommonHeader::decode(&mut self.byte_queue)?);
            }
            Some(DecodedHeader::Partial(header))
                if self.byte_queue.remaining() >= header.required_bytes() =>
            {
                self.next_header = Some(DecodedHeader::Full(
                    header.finish_decoding(&mut self.byte_queue),
                ));
            }
            _ => (),
        }

        Ok(())
    }

    /// Remove and return the next header and payload.
    ///
    /// Must only be called when [`Self::is_packet_available()`] is true.
    fn take_packet(&mut self) -> Packet {
        let Some(DecodedHeader::Full(header)) = self.next_header.take() else {
            panic!("must only be called if a packet is available.");
        };

        Packet {
            last_host: header.destination,
            content: self.byte_queue.take_bytes(header.payload_size()).collect(),
        }
    }

    /// Returns true if a packet is available to be retrieved.
    pub fn is_packet_available(&self) -> bool {
        if let Some(DecodedHeader::Full(header)) = &self.next_header {
            self.remaining() >= header.payload_size()
        } else {
            false
        }
    }
}

/// A parser to decode [`CommonHeader`]s and payloads from a sequence of [`Bytes`]
/// with arbitrary boundaries.
#[derive(Debug)]
pub(super) struct StreamParser {
    state: State,
}

impl StreamParser {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub fn remaining(&self) -> usize {
        match &self.state {
            State::Good(inner) => inner.remaining(),
            State::Bad(_) => 0,
        }
    }

    /// Returns the StreamParserInner if in a good state, otherwise returns the error
    /// that moved the parser to a bad state.
    fn inner_mut(&mut self) -> Result<&mut StreamParserInner, DecodeError> {
        match &mut self.state {
            State::Good(inner) => Ok(inner),
            State::Bad(err) => Err(*err),
        }
    }

    /// Adds the data to the queue, and attempts to decode the next packet.
    ///
    /// Appending data to a stream in a bad state results in the data being discarded.
    /// Returns true if the addition of the data resulted in a packet being available.
    pub fn append_data(&mut self, data: Bytes) -> bool {
        if data.is_empty() {
            return false;
        }
        let Ok(inner) = self.inner_mut() else {
            return false;
        };

        let packet_already_available = inner.is_packet_available();

        inner.byte_queue.push_back(data);

        if !packet_already_available {
            match inner.decode_next_header() {
                Ok(()) => self.is_packet_available(),
                Err(err) => {
                    self.state = self.state.to_bad(err);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Returns the next available packet if any.
    ///
    /// # Errors
    ///
    /// Returns a DecodeError if decoding the next packet failed.
    pub fn next_packet(&mut self) -> Result<Option<Packet>, DecodeError> {
        match &mut self.state {
            State::Good(inner) if inner.is_packet_available() => {
                let packet = inner.take_packet();

                if let Err(error) = inner.decode_next_header() {
                    // Decoding the subsequent packet failed, move to a bad state with an
                    // error that will be returned on all subsequent calls.
                    self.state = self.state.to_bad(error);
                }

                Ok(Some(packet))
            }
            State::Good(..) => Ok(None),
            State::Bad(error) => Err(*error),
        }
    }

    /// Returns true if a packet is available to be retrieved.
    pub fn is_packet_available(&self) -> bool {
        match &self.state {
            State::Good(inner) => inner.is_packet_available(),
            State::Bad(_) => false,
        }
    }
}

impl Default for StreamParser {
    fn default() -> Self {
        Self {
            state: State::Good(StreamParserInner::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKET: [u8; 35] = [
        0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 80, b'R', b'U', b'S', b'T',
    ];
    const BAD_PACKET: [u8; 35] = [
        0xbe, 2, 0xef, 3, 0xde, 0, 0xad, 1, 2, 0, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 80, b'R', b'U', b'S', b'T',
    ];

    mod append_data {
        use super::*;

        #[test]
        fn from_empty() {
            let mut parser = StreamParser::new();

            const MIN_LENGTH: usize = CommonHeader::MIN_LENGTH;
            const AVAILABLE: bool = true;

            let mut range_lower: usize = 0;
            for (range_upper, expected_remaining, expected_available) in [
                (MIN_LENGTH - 1, MIN_LENGTH - 1, !AVAILABLE),
                (MIN_LENGTH + 2, 2, !AVAILABLE),
                (PACKET.len() - 1, 3, !AVAILABLE),
                (PACKET.len(), 4, AVAILABLE),
            ] {
                let is_available = parser.append_data(PACKET[range_lower..range_upper].into());

                let context = format!("at append_data(PACKET[{}..{}])", range_lower, range_upper);

                assert_eq!(is_available, expected_available, "{}", context);
                assert_eq!(parser.is_packet_available(), is_available, "{}", context);
                assert_eq!(parser.remaining(), expected_remaining, "{}", context);

                range_lower = range_upper;
            }
        }

        #[test]
        fn packet_already_available() {
            let mut parser = StreamParser::new();

            let newly_available = parser.append_data(PACKET.as_slice().into());
            assert!(newly_available);
            assert_eq!(newly_available, parser.is_packet_available());

            let newly_available = parser.append_data(PACKET.as_slice().into());
            assert!(!newly_available);
            assert_ne!(newly_available, parser.is_packet_available());
        }

        #[test]
        fn bad_packet() {
            let mut parser = StreamParser::new();
            parser.append_data(BAD_PACKET.as_slice().into());

            assert!(!parser.is_packet_available());
        }

        #[test]
        fn bad_packet_when_already_available() {
            let mut parser = StreamParser::new();

            parser.append_data(PACKET.as_slice().into());
            assert!(parser.is_packet_available());

            parser.append_data(BAD_PACKET.as_slice().into());
            assert!(parser.is_packet_available());
        }

        #[test]
        fn append_good_packet_to_bad_state() {
            let mut parser = StreamParser::new();

            parser.append_data(BAD_PACKET.as_slice().into());
            assert!(!parser.is_packet_available());

            parser.append_data(PACKET.as_slice().into());
            assert!(!parser.is_packet_available());
        }
    }

    mod next_packet {
        use super::*;
        use crate::test_utils::parse;

        #[test]
        fn available() {
            let mut parser = StreamParser::new();

            assert!(!parser.is_packet_available());
            assert!(matches!(parser.next_packet(), Ok(None)));

            parser.append_data(PACKET.as_slice().into());

            assert!(parser.is_packet_available());

            let packet = parser.next_packet().unwrap().unwrap();

            assert_eq!(packet.last_host, Some(parse!("[2001:db8::1]:80")));
            assert_eq!(packet.content, vec![Bytes::from_static(b"RUST")]);
            assert!(!parser.is_packet_available());
        }

        #[test]
        fn multiple_available() {
            let mut parser = StreamParser::new();

            assert!(!parser.is_packet_available());
            assert!(matches!(parser.next_packet(), Ok(None)));

            const NUMBER_PACKETS: usize = 3;

            for _ in 0..NUMBER_PACKETS {
                parser.append_data(PACKET.as_slice().into());
            }

            for _ in 0..NUMBER_PACKETS {
                assert!(parser.is_packet_available());
                let _ = parser.next_packet().unwrap();
            }
            assert!(!parser.is_packet_available());
        }

        #[test]
        fn packet_with_error() {
            let mut parser = StreamParser::new();
            parser.append_data(PACKET.as_slice().into());
            parser.append_data(BAD_PACKET.as_slice().into());

            assert!(matches!(parser.next_packet(), Ok(Some(Packet { .. }))));
            assert!(matches!(
                parser.next_packet(),
                Err(DecodeError::InvalidCookie(..))
            ));
        }

        #[test]
        fn only_header_available() {
            let mut parser = StreamParser::new();

            assert!(!parser.is_packet_available());
            assert!(matches!(parser.next_packet(), Ok(None)));

            parser.append_data(PACKET[..32].into());

            assert!(!parser.is_packet_available());

            assert!(matches!(parser.next_packet(), Ok(None)));
        }
    }
}
