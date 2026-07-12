// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;

use reallyme_openid4vp_types::PresentationValue;
use reallyme_zk_api::{
    ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkErrorReason, ZkHashStrategy,
    ZkProof, ZkProveRequest, ZkProver, ZkPublicInputs, ZkSessionBinding, ZkVerifier,
    ZkVerifyRequest, ZkWitness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::report_zk_error::{ZkFormatError, ZkFormatErrorReason};

/// ZK presentation marker used inside JSON-native `vp_token` entries.
pub const ZK_PRESENTATION_TYPE: &str = "reallyme.openid4vp.zk_presentation.v1";

/// Statement proven by a derived ZK presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedClaimStatement {
    /// Stable statement identifier from policy or DCQL matching context.
    pub statement_id: String,
    /// Non-PII semantic label, for example `age_over_18`.
    pub statement: String,
}

/// Binding hashes embedded in the ZK presentation envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPresentationBinding {
    /// SHA-256 hash of the active OpenID4VP nonce.
    pub nonce_hash: [u8; 32],
    /// SHA-256 hash of the verifier identity/audience.
    pub audience_hash: [u8; 32],
    /// SHA-256 hash of transaction data when present.
    pub transaction_data_hash: Option<[u8; 32]>,
}

impl From<ZkSessionBinding> for ZkPresentationBinding {
    fn from(binding: ZkSessionBinding) -> Self {
        Self {
            nonce_hash: binding.nonce_hash,
            audience_hash: binding.audience_hash,
            transaction_data_hash: binding.transaction_data_hash,
        }
    }
}

impl From<ZkPresentationBinding> for ZkSessionBinding {
    fn from(binding: ZkPresentationBinding) -> Self {
        Self {
            nonce_hash: binding.nonce_hash,
            audience_hash: binding.audience_hash,
            transaction_data_hash: binding.transaction_data_hash,
        }
    }
}

/// Exact imported circuit source used for an artifact-backed proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPresentationCircuitRef {
    /// Hash lane used by the concrete imported circuit.
    pub hash_strategy: String,
    /// VC circuit family.
    pub family: String,
    /// Stage within the circuit family.
    pub stage: String,
    /// Monotonic semantic circuit version.
    pub version: u32,
}

impl From<ZkCircuitRef> for ZkPresentationCircuitRef {
    fn from(circuit_ref: ZkCircuitRef) -> Self {
        Self {
            hash_strategy: circuit_ref.hash_strategy.as_str().to_owned(),
            family: circuit_ref.family.as_str().to_owned(),
            stage: circuit_ref.stage.as_str().to_owned(),
            version: circuit_ref.version,
        }
    }
}

/// JSON-native ZK `vp_token` presentation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPresentation {
    /// Format marker for fail-closed detection.
    #[serde(rename = "type")]
    pub type_: String,
    /// Canonical circuit identifier from `reallyme-zk-api`.
    pub circuit_id: String,
    /// Exact imported circuit source when the backend proof names one.
    pub circuit_ref: Option<ZkPresentationCircuitRef>,
    /// Opaque proof bytes owned by the injected backend.
    pub proof: Vec<u8>,
    /// Serialized circuit public inputs.
    pub public_inputs: Vec<u8>,
    /// Derived claims asserted by this proof.
    pub derived_claims: Vec<DerivedClaimStatement>,
    /// Session binding hashes duplicated for format-layer checking.
    pub binding: ZkPresentationBinding,
}

/// Request to build a ZK presentation from an injected prover.
pub struct ZkPresentationProveRequest<'a> {
    /// Circuit selected by identity policy.
    pub circuit_id: ZkCircuitId,
    /// Exact imported circuit source selected by a top-level backend, if known.
    pub circuit_ref: Option<ZkCircuitRef>,
    /// Secret witness/private inputs extracted by format glue.
    pub witness: &'a ZkWitness,
    /// Public inputs that must include session binding.
    pub public_inputs: &'a ZkPublicInputs,
    /// Expected binding for the active OpenID4VP session.
    pub session_binding: ZkSessionBinding,
    /// Derived claim statements to include in the `vp_token` entry.
    pub derived_claims: Vec<DerivedClaimStatement>,
}

/// Build a JSON-native ZK presentation value with an injected prover.
pub fn prove_zk_presentation(
    prover: &dyn ZkProver,
    request: ZkPresentationProveRequest<'_>,
) -> Result<PresentationValue, ZkFormatError> {
    let proof = prover
        .prove(ZkProveRequest {
            circuit_id: request.circuit_id,
            circuit_ref: request.circuit_ref,
            witness: request.witness,
            public_inputs: request.public_inputs,
            session_binding: request.session_binding,
        })
        .map_err(map_zk_error)?;
    let presentation = zk_proof_to_presentation(
        proof,
        request.derived_claims,
        request.session_binding.into(),
    );
    let value = serde_json::to_value(presentation)
        .map_err(|_| ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding))?;
    Ok(PresentationValue::Json(value))
}

/// Verify a JSON-native ZK presentation value with an injected verifier.
pub fn verify_zk_presentation(
    verifier: &dyn ZkVerifier,
    presentation: &ZkPresentation,
    expected_binding: ZkSessionBinding,
) -> Result<(), ZkFormatError> {
    validate_zk_presentation_binding(presentation.binding, expected_binding)?;
    let circuit_id = ZkCircuitId::from_str(&presentation.circuit_id)
        .map_err(|_| ZkFormatError::new(ZkFormatErrorReason::UnknownCircuit))?;
    let public_inputs =
        ZkPublicInputs::try_from_bytes(presentation.public_inputs.clone()).map_err(map_zk_error)?;
    validate_zk_public_input_binding(&public_inputs, expected_binding)?;
    let proof = match presentation.circuit_ref.as_ref() {
        Some(circuit_ref) => ZkProof::try_from_exact_parts(
            circuit_id,
            Some(parse_presentation_circuit_ref(circuit_ref)?),
            presentation.proof.clone(),
            public_inputs,
        )
        .map_err(map_zk_error)?,
        None => ZkProof::try_from_parts(circuit_id, presentation.proof.clone(), public_inputs)
            .map_err(map_zk_error)?,
    };
    let verification = verifier
        .verify(ZkVerifyRequest {
            proof: &proof,
            expected_binding,
        })
        .map_err(map_zk_error)?;
    if verification.circuit_id != circuit_id {
        return Err(ZkFormatError::new(
            ZkFormatErrorReason::CircuitVerificationMismatch,
        ));
    }
    if let Some(expected_ref) = presentation.circuit_ref.as_ref() {
        let Some(verified_ref) = verification.circuit_ref else {
            return Err(ZkFormatError::new(
                ZkFormatErrorReason::CircuitVerificationMismatch,
            ));
        };
        if parse_presentation_circuit_ref(expected_ref)? != verified_ref {
            return Err(ZkFormatError::new(
                ZkFormatErrorReason::CircuitVerificationMismatch,
            ));
        }
    }
    Ok(())
}

/// Parse a `vp_token` presentation value as a ZK presentation when marked.
pub fn parse_zk_presentation_value(
    value: &PresentationValue,
) -> Result<Option<ZkPresentation>, ZkFormatError> {
    let PresentationValue::Json(json) = value else {
        return Ok(None);
    };
    if json
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|value| value != ZK_PRESENTATION_TYPE)
    {
        return Ok(None);
    }
    serde_json::from_value(json.clone())
        .map(Some)
        .map_err(|_| ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding))
}

/// Return whether a presentation value is marked as a ReallyMe ZK presentation.
pub fn is_zk_presentation_value(value: &PresentationValue) -> bool {
    let PresentationValue::Json(json) = value else {
        return false;
    };
    json.get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == ZK_PRESENTATION_TYPE)
}

/// Build the session binding hashes expected by ZK presentation circuits.
pub fn build_zk_session_binding(
    nonce: &str,
    audience: &str,
    transaction_data_hash: Option<[u8; 32]>,
) -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: hash_openid4vp_nonce(nonce),
        audience_hash: hash_openid4vp_audience(audience),
        transaction_data_hash,
    }
}

/// Hash an OpenID4VP nonce for ZK public-input binding.
pub fn hash_openid4vp_nonce(nonce: &str) -> [u8; 32] {
    sha256_bytes(nonce.as_bytes())
}

/// Hash an OpenID4VP verifier audience for ZK public-input binding.
pub fn hash_openid4vp_audience(audience: &str) -> [u8; 32] {
    sha256_bytes(audience.as_bytes())
}

fn validate_zk_public_input_binding(
    public_inputs: &ZkPublicInputs,
    expected: ZkSessionBinding,
) -> Result<(), ZkFormatError> {
    if !expected.matches_public_input_prefix(public_inputs) {
        return Err(ZkFormatError::new(ZkFormatErrorReason::BindingMismatch));
    }
    Ok(())
}

fn validate_zk_presentation_binding(
    actual: ZkPresentationBinding,
    expected: ZkSessionBinding,
) -> Result<(), ZkFormatError> {
    let expected_binding: ZkPresentationBinding = expected.into();
    if actual != expected_binding {
        return Err(ZkFormatError::new(ZkFormatErrorReason::BindingMismatch));
    }
    Ok(())
}

fn zk_proof_to_presentation(
    proof: ZkProof,
    derived_claims: Vec<DerivedClaimStatement>,
    binding: ZkPresentationBinding,
) -> ZkPresentation {
    let (circuit_id, circuit_ref, proof, public_inputs) = proof.into_exact_parts();
    ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        circuit_id: circuit_id.as_str().to_owned(),
        circuit_ref: circuit_ref.map(ZkPresentationCircuitRef::from),
        proof,
        public_inputs: public_inputs.into_bytes(),
        derived_claims,
        binding,
    }
}

fn map_zk_error(error: reallyme_zk_api::ZkError) -> ZkFormatError {
    let reason = match error.reason() {
        ZkErrorReason::UnknownCircuit => ZkFormatErrorReason::UnknownCircuit,
        ZkErrorReason::UnsupportedCircuit => ZkFormatErrorReason::UnsupportedCircuit,
        ZkErrorReason::EmptyInput
        | ZkErrorReason::ProofTooLarge
        | ZkErrorReason::PublicInputsTooLarge
        | ZkErrorReason::InvalidPublicInputName
        | ZkErrorReason::PublicKeyTooLarge
        | ZkErrorReason::ClaimPayloadTooLarge
        | ZkErrorReason::InvalidProofBundle
        | ZkErrorReason::DuplicateStage
        | ZkErrorReason::MissingStage
        | ZkErrorReason::LengthOverflow
        | ZkErrorReason::InvalidProofEncoding => ZkFormatErrorReason::InvalidPresentationEncoding,
        ZkErrorReason::InvalidProof | ZkErrorReason::StageMismatch => {
            ZkFormatErrorReason::InvalidProof
        }
        ZkErrorReason::BindingMismatch => ZkFormatErrorReason::BindingMismatch,
        ZkErrorReason::ArtifactMismatch
        | ZkErrorReason::BackendUnavailable
        | ZkErrorReason::BackendFailure => ZkFormatErrorReason::VerifierUnavailable,
    };
    ZkFormatError::new(reason)
}

fn parse_presentation_circuit_ref(
    circuit_ref: &ZkPresentationCircuitRef,
) -> Result<ZkCircuitRef, ZkFormatError> {
    let hash_strategy = parse_hash_strategy(&circuit_ref.hash_strategy)?;
    let family = parse_circuit_family(&circuit_ref.family)?;
    let stage = parse_circuit_stage(&circuit_ref.stage)?;
    Ok(ZkCircuitRef {
        hash_strategy,
        family,
        stage,
        version: circuit_ref.version,
    })
}

fn parse_hash_strategy(value: &str) -> Result<ZkHashStrategy, ZkFormatError> {
    for hash_strategy in ZkHashStrategy::ALL {
        if hash_strategy.as_str() == value {
            return Ok(*hash_strategy);
        }
    }
    Err(ZkFormatError::new(
        ZkFormatErrorReason::InvalidPresentationEncoding,
    ))
}

fn parse_circuit_family(value: &str) -> Result<ZkCircuitFamily, ZkFormatError> {
    for family in ZkCircuitFamily::ALL {
        if family.as_str() == value {
            return Ok(*family);
        }
    }
    Err(ZkFormatError::new(
        ZkFormatErrorReason::InvalidPresentationEncoding,
    ))
}

fn parse_circuit_stage(value: &str) -> Result<ZkCircuitStage, ZkFormatError> {
    for stage in ZkCircuitStage::ALL {
        if stage.as_str() == value {
            return Ok(*stage);
        }
    }
    Err(ZkFormatError::new(
        ZkFormatErrorReason::InvalidPresentationEncoding,
    ))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use reallyme_zk_api::{
        ZkCircuitId, ZkError, ZkProof, ZkProveRequest, ZkProver, ZkPublicInputs, ZkVerification,
        ZkVerifier, ZkVerifyRequest, ZkWitness,
    };

    use crate::prove_zk_presentation::{
        build_zk_session_binding, parse_zk_presentation_value, prove_zk_presentation,
        verify_zk_presentation, DerivedClaimStatement, ZkPresentationProveRequest,
    };
    use crate::report_zk_error::{ZkFormatError, ZkFormatErrorReason};

    struct FixtureProver;

    impl ZkProver for FixtureProver {
        fn prove(&self, request: ZkProveRequest<'_>) -> Result<ZkProof, ZkError> {
            ZkProof::try_from_exact_parts(
                request.circuit_id,
                request.circuit_ref,
                vec![1, 2, 3],
                request.public_inputs.clone(),
            )
        }
    }

    struct FixtureVerifier;

    impl ZkVerifier for FixtureVerifier {
        fn verify(&self, request: ZkVerifyRequest<'_>) -> Result<ZkVerification, ZkError> {
            Ok(ZkVerification {
                circuit_id: request.proof.circuit_id(),
                circuit_ref: request.proof.circuit_ref(),
            })
        }
    }

    #[test]
    fn proves_and_verifies_zk_presentation_value() -> Result<(), ZkFormatError> {
        let binding = build_zk_session_binding("nonce", "x509_san_dns:verifier.example", None);
        let public_inputs = public_inputs_for_binding(binding)?;
        let witness = ZkWitness::from_bytes(vec![9]);
        let value = prove_zk_presentation(
            &FixtureProver,
            ZkPresentationProveRequest {
                circuit_id: ZkCircuitId::VcBaseV1,
                circuit_ref: None,
                witness: &witness,
                public_inputs: &public_inputs,
                session_binding: binding,
                derived_claims: vec![DerivedClaimStatement {
                    statement_id: "age".to_owned(),
                    statement: "age_over_18".to_owned(),
                }],
            },
        )?;
        let presentation = parse_zk_presentation_value(&value)?.ok_or(ZkFormatError::new(
            ZkFormatErrorReason::InvalidPresentationEncoding,
        ))?;

        verify_zk_presentation(&FixtureVerifier, &presentation, binding)
    }

    #[test]
    fn rejects_binding_mismatch_before_backend_verification() -> Result<(), ZkFormatError> {
        let binding = build_zk_session_binding("nonce", "x509_san_dns:verifier.example", None);
        let public_inputs = public_inputs_for_binding(binding)?;
        let witness = ZkWitness::from_bytes(vec![9]);
        let value = prove_zk_presentation(
            &FixtureProver,
            ZkPresentationProveRequest {
                circuit_id: ZkCircuitId::VcBaseV1,
                circuit_ref: None,
                witness: &witness,
                public_inputs: &public_inputs,
                session_binding: binding,
                derived_claims: Vec::new(),
            },
        )?;
        let presentation = parse_zk_presentation_value(&value)?.ok_or(ZkFormatError::new(
            ZkFormatErrorReason::InvalidPresentationEncoding,
        ))?;
        let other_binding =
            build_zk_session_binding("other", "x509_san_dns:verifier.example", None);
        let err = verify_zk_presentation(&FixtureVerifier, &presentation, other_binding)
            .err()
            .ok_or(ZkFormatError::new(ZkFormatErrorReason::VerifierUnavailable))?;

        assert_eq!(err.reason(), ZkFormatErrorReason::BindingMismatch);
        Ok(())
    }

    #[test]
    fn rejects_public_input_binding_mismatch_before_backend_verification(
    ) -> Result<(), ZkFormatError> {
        let binding = build_zk_session_binding("nonce", "x509_san_dns:verifier.example", None);
        let mut public_input_bytes = binding.public_input_prefix_bytes();
        if let Some(first) = public_input_bytes.first_mut() {
            *first = first.saturating_add(1);
        }
        let public_inputs = ZkPublicInputs::try_from_bytes(public_input_bytes)
            .map_err(|_| ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding))?;
        let witness = ZkWitness::from_bytes(vec![9]);
        let value = prove_zk_presentation(
            &FixtureProver,
            ZkPresentationProveRequest {
                circuit_id: ZkCircuitId::VcBaseV1,
                circuit_ref: None,
                witness: &witness,
                public_inputs: &public_inputs,
                session_binding: binding,
                derived_claims: Vec::new(),
            },
        )?;
        let presentation = parse_zk_presentation_value(&value)?.ok_or(ZkFormatError::new(
            ZkFormatErrorReason::InvalidPresentationEncoding,
        ))?;
        let err = verify_zk_presentation(&FixtureVerifier, &presentation, binding)
            .err()
            .ok_or(ZkFormatError::new(ZkFormatErrorReason::VerifierUnavailable))?;

        assert_eq!(err.reason(), ZkFormatErrorReason::BindingMismatch);
        Ok(())
    }

    fn public_inputs_for_binding(
        binding: reallyme_zk_api::ZkSessionBinding,
    ) -> Result<ZkPublicInputs, ZkFormatError> {
        let mut bytes = binding.public_input_prefix_bytes();
        bytes.push(7);
        ZkPublicInputs::try_from_bytes(bytes)
            .map_err(|_| ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding))
    }
}
