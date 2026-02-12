//! Hex string rendering helper.

use std::fmt::Write;

/// Render the input `bytes` as a lowercase hex string delimited by colons in
/// the style of OpenSSL.
///
/// Example: `cc:cb:0f:63:f1:63:5e:f1:0e:26:e8:82:f7:7a:6e:f9`
pub(super) fn colon_string(bytes: &[u8]) -> String {
    // Pre-allocate a string for the hex string.
    //
    //  * Each byte is rendered using 2 hex chars
    //  * Rendered byte sequences are delimited by a colon
    //
    let cap = bytes.len() * 2; // Hex chars
    let cap = cap + (cap / 2) - 1; // Delimiters
    let mut s = String::with_capacity(cap);

    // Write all except the last byte, rendering a pair of lower-case
    // hex characters followed by a delimiting colon.
    for v in &bytes[..bytes.len() - 1] {
        write!(&mut s, "{v:02x}:").expect("infallible append");
    }

    // Write the last byte without adding a delimiter.
    write!(&mut s, "{:02x}", bytes.last().unwrap()).expect("infallible append");

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn test_fixture() {
        let hex_str = colon_string(&[42, 13, 00, 0xCA, 0xFE]);
        assert_eq!(hex_str, "2a:0d:00:ca:fe");
    }

    proptest! {
        #[test]
        fn prop_render(
            value in prop::collection::vec(any::<u8>(), 1..129), // Arbitrary range
        ) {
            // Render the input as a colon string.
            let hex_str = colon_string(&value);

            // Reverse the rendering back into a raw byte array.
            let raw = hex::decode(hex_str.replace(':', "")).expect("valid hex");

            // The recovered bytes must match the input bytes.
            assert_eq!(raw, value);
        }
    }
}
