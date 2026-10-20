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

use proptest::prelude::*;

use super::LEAF_ENDPOINT_HOSTNAME;
use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// The leaf dNSName SAN configurations under test.
///
/// All scenarios are described relative to the endpoint hostname the client
/// connects to ([`LEAF_ENDPOINT_HOSTNAME`]); no name constraints are placed on
/// the intermediates.
#[derive(Debug, Clone)]
pub(crate) enum LeafSanScenario {
    /// The leaf has a single dNSName SAN matching the connected endpoint.
    Matching,
    /// The leaf has a single dNSName SAN that does NOT match the connected
    /// endpoint.
    Mismatching,
    /// The leaf has multiple dNSName SANs, one of which matches the connected
    /// endpoint.
    MultipleWithMatch,
    /// The leaf has multiple dNSName SANs, none of which match the connected
    /// endpoint.
    MultipleWithoutMatch,
}

impl LeafSanScenario {
    /// The dNSName SAN values applied to the leaf certificate for this
    /// scenario.
    pub(crate) fn sans(&self) -> Vec<&str> {
        match self {
            LeafSanScenario::Matching => vec![LEAF_ENDPOINT_HOSTNAME],
            LeafSanScenario::Mismatching => vec!["eu1.datadoghq.com"],
            LeafSanScenario::MultipleWithMatch => vec![
                "eu1.datadoghq.com",
                LEAF_ENDPOINT_HOSTNAME,
                "ap1.datadoghq.com",
            ],
            LeafSanScenario::MultipleWithoutMatch => vec!["eu1.datadoghq.com", "ap1.datadoghq.com"],
        }
    }
}

/// Produces a [`TestChain`] with the leaf dNSName SANs specified by the
/// [`LeafSanScenario`].
#[derive(Debug, Clone)]
pub(crate) struct SetLeafSans {
    scenario: LeafSanScenario,
}

impl SetLeafSans {
    pub(crate) fn new(scenario: LeafSanScenario) -> Self {
        Self { scenario }
    }
}

impl ChainMutator for SetLeafSans {
    fn intermediate<'a>(
        &self,
        builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
        // Leave the intermediates unconstrained so the leaf SANs are the only
        // variable under test.
        builder.set_allowed_domains(vec![]);
    }

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        builder.with_sans(self.scenario.sans());
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}

/// Generate an arbitrary [`LeafSanScenario`] value.
pub(crate) fn arbitrary_leaf_san_scenario() -> impl Strategy<Value = LeafSanScenario> {
    prop_oneof![
        Just(LeafSanScenario::Matching),
        Just(LeafSanScenario::Mismatching),
        Just(LeafSanScenario::MultipleWithMatch),
        Just(LeafSanScenario::MultipleWithoutMatch),
    ]
}
