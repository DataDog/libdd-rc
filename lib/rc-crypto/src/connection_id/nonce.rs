use aws_lc_rs::rand;

/// A "number used once" for ID generation.
///
/// Specifically a 16 byte / 128 bit, cryptographically random value, used at
/// most once per connection.
#[derive(Debug)]
pub struct IdNonce([u8; 16]);

impl Default for IdNonce {
    fn default() -> Self {
        let mut buf = [0u8; 16];
        rand::fill(&mut buf).unwrap();

        assert_ne!(buf, [0u8; 16]);

        Self(buf)
    }
}

impl IdNonce {
    /// Expose the inner bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use static_assertions::assert_not_impl_any;

    // A nonce should not be cloned, so that it can be consumed after one
    // verification attempt by moving ownership into the verification fn.
    assert_not_impl_any!(IdNonce: Clone);

    #[test]
    fn test_nonce_generation() {
        assert_eq!(IdNonce::default().as_bytes().len(), 16);

        // Rand is random:
        assert_ne!(IdNonce::default().as_bytes(), IdNonce::default().as_bytes());
    }
}
