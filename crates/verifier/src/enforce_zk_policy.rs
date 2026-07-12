// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_zk_api::{circuit_capabilities, ZkCircuitId, ZkSemanticGuarantee};

use crate::{VerifierError, VerifierErrorReason};

/// Verifier policy for accepting ZK presentations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkPolicyRequirements {
    /// Whether ZK presentations are accepted at all.
    pub allow_zk_presentations: bool,
    /// Registered circuits accepted by this verifier.
    pub allowed_circuits: &'static [ZkCircuitId],
    /// Require the circuit registry to assert session binding.
    pub require_session_binding: bool,
    /// Require the circuit registry to assert verifier/audience binding.
    pub require_audience_binding: bool,
    /// Require the circuit registry to assert transaction-data binding.
    pub require_transaction_data_binding: bool,
}

impl Default for ZkPolicyRequirements {
    fn default() -> Self {
        Self {
            allow_zk_presentations: true,
            allowed_circuits: ZkCircuitId::ALL,
            require_session_binding: true,
            require_audience_binding: true,
            require_transaction_data_binding: false,
        }
    }
}

/// Enforce verifier-side ZK policy using the shared circuit capability registry.
pub fn enforce_zk_policy(
    circuit_id: ZkCircuitId,
    requirements: ZkPolicyRequirements,
) -> Result<(), VerifierError> {
    if !requirements.allow_zk_presentations {
        return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
    }

    if !requirements.allowed_circuits.contains(&circuit_id) {
        return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
    }

    let capabilities = circuit_capabilities(circuit_id);
    if requirements.require_session_binding
        && !capabilities
            .semantic_guarantees
            .contains(&ZkSemanticGuarantee::SessionBound)
    {
        return Err(VerifierError::new(
            VerifierErrorReason::InvalidZkPresentation,
        ));
    }

    if requirements.require_audience_binding
        && !capabilities
            .semantic_guarantees
            .contains(&ZkSemanticGuarantee::AudienceBound)
    {
        return Err(VerifierError::new(
            VerifierErrorReason::InvalidZkPresentation,
        ));
    }

    if requirements.require_transaction_data_binding
        && !capabilities
            .semantic_guarantees
            .contains(&ZkSemanticGuarantee::TransactionDataBound)
    {
        return Err(VerifierError::new(
            VerifierErrorReason::InvalidZkPresentation,
        ));
    }

    Ok(())
}
