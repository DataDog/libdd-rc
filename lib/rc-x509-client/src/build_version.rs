use tokio_util::bytes::Bytes;

/// Client build version information for the currently running instance.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct BuildVersion {
    // TODO(dom): implement version info
    #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_bytes()"))]
    commit: Bytes,
}

impl BuildVersion {
    /// Return the major semver value.
    pub(crate) fn major(&self) -> u32 {
        0
    }

    /// Return the minor semver value.
    pub(crate) fn minor(&self) -> u32 {
        0
    }

    /// Return the patch semver value.
    pub(crate) fn patch(&self) -> u32 {
        0
    }

    /// Return the Git commit hash of the build as the, unencoded hash raw
    /// bytes.
    pub(crate) fn commit(&self) -> &Bytes {
        &self.commit
    }
}
