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

use super::{LeafSanScenario, SetLeafSans};
use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

pub(crate) static LEAF_ENDPOINT_HOSTNAME: &str = "us1.datadoghq.com";

/// The name constraint configurations under test.
#[derive(Debug, Clone)]
pub(crate) enum NameConstraintScenario {
    /// Intermediate permitted dNSName constraint matches the leaf SAN.
    Matching,
    /// Intermediate permitted dNSName constraint does NOT match the leaf SAN.
    Mismatching,
    /// Intermediates have no name constraints, leaf has a DNS SAN.
    Unconstrained,
    /// Intermediates have multiple permitted dNSName constraints, and the leaf
    /// has a matching DNS SANs entry.
    MultipleWithMatch,
    /// Intermediate permitted dNSName constraint covers the subdomain used by
    /// the leaf DNS SAN.
    MatchingSubdomain,
}

impl NameConstraintScenario {
    /// The permitted dNSName constraints applied to each intermediate.
    ///
    /// An empty set means the intermediates are unconstrained.
    pub(crate) fn permitted_domains(&self) -> Vec<String> {
        match self {
            NameConstraintScenario::Matching => vec![LEAF_ENDPOINT_HOSTNAME.to_string()],
            NameConstraintScenario::Mismatching => vec!["eu1.datadoghq.com".to_string()],
            NameConstraintScenario::Unconstrained => vec![],
            NameConstraintScenario::MultipleWithMatch => vec![
                "eu1.datadoghq.com".to_string(),
                LEAF_ENDPOINT_HOSTNAME.to_string(),
            ],
            NameConstraintScenario::MatchingSubdomain => vec!["datadoghq.com".to_string()], // Parent domain
        }
    }

    /// Returns true if `dns_name` is permitted by the constraints of this
    /// scenario.
    ///
    /// A permitted dNSName constraint matches the name itself, and all
    /// subdomains of it.
    pub(crate) fn permits(&self, dns_name: &str) -> bool {
        let permitted = self.permitted_domains();
        if permitted.is_empty() {
            return true; // Unconstrained.
        }

        permitted
            .iter()
            .any(|v| dns_name == v || dns_name.ends_with(&format!(".{v}")))
    }
}

/// Produces a [`TestChain`] with overridden name constraints on intermediates
/// as specified by the [`NameConstraintScenario`], and the leaf SANs specified
/// by the [`LeafSanScenario`].
#[derive(Debug, Clone)]
pub(crate) struct SetNameConstraints {
    scenario: NameConstraintScenario,
    leaf_sans: SetLeafSans,
}

impl SetNameConstraints {
    pub(crate) fn new(scenario: NameConstraintScenario) -> Self {
        Self {
            scenario,
            leaf_sans: SetLeafSans::new(LeafSanScenario::Matching),
        }
    }

    /// Override the leaf dNSName SANs issued for this chain.
    pub(crate) fn with_leaf_sans(mut self, scenario: LeafSanScenario) -> Self {
        self.leaf_sans = SetLeafSans::new(scenario);
        self
    }
}

impl ChainMutator for SetNameConstraints {
    fn intermediate<'a>(
        &self,
        builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
        builder.set_allowed_domains(self.scenario.permitted_domains());
    }

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        self.leaf_sans.leaf(builder);
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}

/// Generate an arbitrary [`NameConstraintScenario`] value.
pub(crate) fn arbitrary_name_constraint_scenario() -> impl Strategy<Value = NameConstraintScenario>
{
    prop_oneof![
        Just(NameConstraintScenario::Matching),
        Just(NameConstraintScenario::Mismatching),
        Just(NameConstraintScenario::Unconstrained),
        Just(NameConstraintScenario::MultipleWithMatch),
        Just(NameConstraintScenario::MatchingSubdomain),
    ]
}
