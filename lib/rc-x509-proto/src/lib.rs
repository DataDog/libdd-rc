// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Remote Config protocol message definitions.

#![allow(missing_docs)]

pub(crate) mod rc {
    pub(crate) mod x509 {
        pub mod protocol {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/rc.x509.protocol.v1.rs"));
            }
        }
    }
}

use prost::{Message, bytes::Buf};

// Re-exports for callers to import, instead of having to depend on `prost`
// directly.
pub use crate::rc::x509::protocol;
pub use prost::DecodeError;

/// Encode an instance of `T` into a byte array that can be decoded with
/// [`decode()`].
pub fn encode<T>(value: &T) -> Vec<u8>
where
    T: Message + Default,
{
    T::encode_length_delimited_to_vec(value)
}

/// Decode a `T` from `buf`, previously encoded with [`encode()`].
pub fn decode<T>(buf: impl Buf) -> Result<T, DecodeError>
where
    T: Message + Default,
{
    T::decode_length_delimited(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use proptest_derive::Arbitrary;

    /// A struct that contains all primitive protobuf types.
    #[derive(prost::Message, PartialEq, Arbitrary)]
    struct Thing {
        #[prost(string, tag = "1")]
        string: String,

        #[prost(float, tag = "3")]
        i_float: f32,
        #[prost(double, tag = "2")]
        i_double: f64,
        #[prost(int32, tag = "4")]
        i_i32: i32,
        #[prost(sint32, tag = "5")]
        i_si32: i32,
        #[prost(sint64, tag = "6")]
        i_si64: i64,
        #[prost(int64, tag = "7")]
        i_i64: i64,
        #[prost(uint32, tag = "8")]
        i_u32: u32,
        #[prost(fixed32, tag = "9")]
        i_fixed32: u32,
        #[prost(fixed64, tag = "10")]
        i_fixed64: u64,
        #[prost(sfixed32, tag = "11")]
        i_sfixed32: i32,
        #[prost(sfixed64, tag = "12")]
        i_sfixed64: i64,
        #[prost(uint64, tag = "13")]
        i_u64: u64,

        #[prost(bool, tag = "14")]
        boolean: bool,

        #[prost(bytes, tag = "15")]
        bytes: Vec<u8>,

        #[prost(enumeration = "Enum", tag = "16")]
        other: i32,

        #[prost(message, repeated, tag = "17")]
        nested: Vec<Nested>,
    }

    #[derive(prost::Message, PartialEq, Arbitrary)]
    struct Nested {
        #[prost(string, tag = "1")]
        string: String,
    }

    #[derive(Debug, prost::Enumeration, PartialEq)]
    #[repr(i32)]
    enum Enum {
        A = 0,
        B = 1,
    }

    proptest! {
        #[test]
        fn prop_round_trip(
            value in any::<Thing>(),
        ) {
            let encoded = encode(&value);
            assert_eq!(value, decode(encoded.as_slice()).unwrap())
        }
    }
}
