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

use std::fmt::{Debug, Display};

use rustls_pki_types::ServerName;
use thiserror::Error;

/// The Remote Config endpoint the client is connected to, used to validate the
/// DNS name / DC pins of any certificates presented with a chain containing
/// name constraints.
///
/// This is typically the RC domain for the respective region, such as:
///
///   * `config.datadoqhq.com`
///   * `config.datadoghq.eu`
///   * `config.us3.datadoghq.com`
///   * etc
///
/// This value also supports IP addresses, but RC certificates are not typically
/// issued with IP SANs, making IP addresses unsuitable for prod usage.
#[derive(Debug)]
pub struct EndpointHostname(ServerName<'static>);

impl EndpointHostname {
    pub(crate) fn as_server_name(&self) -> &ServerName<'static> {
        &self.0
    }
}

/// The [`EndpointHostname`] is an invalid DNS domain.
#[derive(Debug, Error)]
#[error("invalid endpoint hostname: {0}")]
pub struct InvalidEndpointHostname(rustls_pki_types::InvalidDnsNameError);

impl TryFrom<String> for EndpointHostname {
    type Error = InvalidEndpointHostname;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ServerName::try_from(value)
            .map_err(InvalidEndpointHostname)
            .map(Self)
    }
}

impl Display for EndpointHostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.to_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns() {
        let got = EndpointHostname::try_from("us1.datadoqhq.com".to_string()).unwrap();
        assert_eq!(got.to_string(), "us1.datadoqhq.com");
    }

    #[test]
    fn test_reject_http() {
        let _err = EndpointHostname::try_from("https://us1.datadoqhq.com".to_string())
            .expect_err("protocol in URI");
    }

    #[test]
    fn test_parse_ip() {
        let got = EndpointHostname::try_from("192.168.42.42".to_string()).unwrap();
        assert_eq!(got.to_string(), "192.168.42.42");
    }
}
