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

pub use crate::rc::x509::protocol;
