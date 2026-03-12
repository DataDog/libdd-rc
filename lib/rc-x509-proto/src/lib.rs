// Copyright 2026 Datadog, Inc
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

pub use crate::rc::x509::protocol;
