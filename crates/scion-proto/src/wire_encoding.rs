/// A trait for types decodable from a wire format, without any additional information.
pub trait WireDecode<T>: Sized {
    /// The error type returned on a failed decode.
    type Error;

    /// Decodes an object from the provided data, such as a [`bytes::Buf`].
    ///
    /// The buffer is advanced by as many bytes as necessary to decode the object.
    /// Bytes are consumed regardless of whether or not decoding fails.
    fn decode(data: &mut T) -> Result<Self, Self::Error>;
}

/// A trait for types decodable from a wire format, *with* additional information.
///
/// In contrast to [`WireDecode`], this trait allows the implementing type to specify
/// additional data that should be passed to the decode calls, by means of the
/// associated type [`Self::Context`].
pub trait WireDecodeWithContext<T>: Sized {
    /// The error type returned on a failed decode.
    type Error;
    /// Data that should be provided to calls to decode.
    type Context;

    /// Decodes an object from the provided data, such as a [`bytes::Buf`], with additional context.
    ///
    /// Callers must provide the required contextual information, as specified by [`Self::Context`],
    /// to decode the object. This may be, for example, the length of the amount of data comprising
    /// the object or the type of the object signalled elsewhere.
    ///
    /// The buffer is advanced by as many bytes as necessary to decode the object.
    /// Bytes are consumed regardless of whether or not decoding fails.
    fn decode_with_context(data: &mut T, context: Self::Context) -> Result<Self, Self::Error>;
}

pub trait WireEncode {
    /// The error type returned on a failed encode.
    type Error: std::fmt::Debug;

    fn encode_to<T: BufMut>(&self, buffer: &mut T) -> Result<(), Self::Error>;

    fn encode_to_bytes(&self) -> Bytes {
        let mut buffer = BytesMut::new();
        self.encode_to(&mut buffer).unwrap(); // BytesMut will grow as needed
        buffer.freeze()
    }
}

/// An enum that stores the undecoded bytes of a field.
///
/// When presented with a typed, encoded, representation of a header field, this library may
/// not currently support decoding the type. In this case, it may return a MaybeEncoded
/// object in the case that the input may be valid but cannot be decoded.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MaybeEncoded<T, U> {
    /// The successfully decoded variant.
    Decoded(T),
    /// The data associated with an instance that cannot currently be decoded by the library.
    Encoded(U),
}

impl<T, U> MaybeEncoded<T, U>
where
    T: Into<U>,
{
    pub fn into_encoded(self) -> U {
        match self {
            MaybeEncoded::Decoded(decoded) => decoded.into(),
            MaybeEncoded::Encoded(encoded) => encoded,
        }
    }
}

macro_rules! bounded_uint {
    (
        $(#[$outer:meta])*
        pub struct $name:ident($type:ty : $bits:literal);
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
        pub struct $name($type);

        impl $name {
            /// The number of bits useable for an instance of this type.
            pub const BITS: u32 = $bits;

            /// The maximum possible value for an instance of this type.
            pub const MAX: Self = Self((1 << $bits) - 1);

            /// Create a new instance if the value is at most `Self::MAX.value()`.
            pub const fn new(value: $type) -> Option<Self> {
                if value <= Self::MAX.0 {
                    Some(Self(value))
                } else {
                    None
                }
            }

            /// Create a new instance with the provided value.
            ///
            /// # Safety
            ///
            /// The value should be at most `Self::MAX.value()`.
            pub const fn new_unchecked(value: $type) -> Self {
                debug_assert!(value <= Self::MAX.0);
                Self(value)
            }

            /// Get the value of this instance as its underlying type.
            #[inline]
            pub const fn get(&self) -> $type {
                self.0
            }
        }
    };
}
pub(crate) use bounded_uint;
use bytes::{BufMut, Bytes, BytesMut};
