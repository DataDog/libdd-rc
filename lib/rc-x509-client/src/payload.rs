use tokio_util::bytes::Bytes;

/// An opaque serialised [`v1::DispatchRequestPayload`] byte payload from the
/// Datadog backend, to be delivered to the host application.
///
/// [`v1::DispatchRequestPayload`]:
///     rc_x509_proto::protocol::v1::DispatchRequestPayload
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct Payload(
    #[cfg_attr(feature = "fuzzing", arbitrary(with = crate::fuzzing::arbitrary_bytes))] Bytes,
);

impl Payload {
    /// Copy the payload from `src`.
    ///
    /// # Performance Penalty
    ///
    /// Copying data is inefficient - prefer moving ownership using a `From`
    /// impl instead.
    pub fn copy_from_slice(src: &[u8]) -> Self {
        Self(Bytes::copy_from_slice(src))
    }

    /// Return a raw pointer to this buffer.
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    /// The byte length of this payload.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when len == 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the raw [`Byte`] buffer containing the serialised bytes.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Convert this wrapper into the raw [`Byte`] buffer containing the
    /// serialised bytes.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl From<Bytes> for Payload {
    fn from(value: Bytes) -> Self {
        Self(value)
    }
}

impl From<Vec<u8>> for Payload {
    fn from(value: Vec<u8>) -> Self {
        Self(Bytes::from_owner(value))
    }
}

impl From<&'static [u8]> for Payload {
    fn from(value: &'static [u8]) -> Self {
        Self(Bytes::from_static(value))
    }
}

impl<const N: usize> From<&'static [u8; N]> for Payload {
    fn from(value: &'static [u8; N]) -> Self {
        Self(Bytes::from_static(value.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;

    use super::*;

    // Allows the payload signature verifier to consume the payload, "taking" it
    // from the caller if verification fails - a "nice to have" that is not
    // critical to security, however.
    assert_not_impl_any!(Payload: Clone);

    #[test]
    fn test_ok() {
        let a = Payload::from(&[1, 2, 3, 4]);
        assert_eq!(a.len(), 4);
        assert!(!a.is_empty());
        assert_eq!(*a.as_bytes(), Bytes::from_static(&[1, 2, 3, 4]));
        assert_eq!(a.as_ptr(), a.0.as_ptr());
        assert_eq!(a.into_bytes(), Bytes::from_static(&[1, 2, 3, 4]));
    }
}
