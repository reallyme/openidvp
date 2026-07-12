// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use buffa::MessageField;
use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_formats::{
    parse_zk_presentation_value, DerivedClaimStatement, ZkPresentation, ZkPresentationBinding,
    ZkPresentationCircuitRef,
};
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{
    AuthorizationResponse, PresentationValue, TransactionDataHashAlgorithm, VpToken,
};

use crate::report_proto_error::OpenId4VpProtoError;

/// Map a Rust AuthorizationResponse into the generated protobuf message.
pub fn authorization_response_to_proto(
    response: &AuthorizationResponse,
) -> Result<pb::AuthorizationResponse, OpenId4VpProtoError> {
    let vp_token = response
        .vp_token
        .iter()
        .map(|(query_id, presentations)| {
            let presentations = presentations
                .iter()
                .map(presentation_value_to_proto)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(pb::VpTokenEntry {
                query_id: query_id.as_str().to_owned(),
                presentations,
                __buffa_unknown_fields: Default::default(),
            })
        })
        .collect::<Result<Vec<_>, OpenId4VpProtoError>>()?;
    Ok(pb::AuthorizationResponse {
        vp_token,
        state: response.state.clone(),
        transaction_data_hashes: response.transaction_data_hashes.clone().unwrap_or_default(),
        transaction_data_hashes_alg: response
            .transaction_data_hashes_alg
            .map(transaction_data_hash_algorithm_to_proto),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map a generated protobuf AuthorizationResponse into the Rust response model.
pub fn proto_to_authorization_response(
    response: &pb::AuthorizationResponse,
) -> Result<AuthorizationResponse, OpenId4VpProtoError> {
    if response.vp_token.is_empty() {
        return Err(OpenId4VpProtoError::MissingField);
    }

    let mut vp_token: VpToken = BTreeMap::new();
    for entry in &response.vp_token {
        let query_id =
            QueryId::parse(&entry.query_id).map_err(|_| OpenId4VpProtoError::InvalidField)?;
        if entry.presentations.is_empty() {
            return Err(OpenId4VpProtoError::MissingField);
        }
        let presentations = entry
            .presentations
            .iter()
            .map(proto_to_presentation_value)
            .collect::<Result<Vec<_>, _>>()?;
        vp_token.insert(query_id, presentations);
    }

    let (transaction_data_hashes, transaction_data_hashes_alg) =
        proto_to_transaction_data_hash_binding(response)?;

    Ok(AuthorizationResponse {
        vp_token,
        state: response.state.clone(),
        transaction_data_hashes,
        transaction_data_hashes_alg,
    })
}

fn transaction_data_hash_algorithm_to_proto(algorithm: TransactionDataHashAlgorithm) -> String {
    match algorithm {
        TransactionDataHashAlgorithm::Sha256 => "sha-256".to_owned(),
    }
}

fn proto_to_transaction_data_hash_binding(
    response: &pb::AuthorizationResponse,
) -> Result<(Option<Vec<String>>, Option<TransactionDataHashAlgorithm>), OpenId4VpProtoError> {
    match (
        response.transaction_data_hashes.is_empty(),
        response.transaction_data_hashes_alg.as_deref(),
    ) {
        (true, None) => Ok((None, None)),
        (false, Some("sha-256")) => Ok((
            Some(response.transaction_data_hashes.clone()),
            Some(TransactionDataHashAlgorithm::Sha256),
        )),
        (false, Some(_)) | (true, Some(_)) | (false, None) => {
            Err(OpenId4VpProtoError::InvalidField)
        }
    }
}

fn presentation_value_to_proto(
    value: &PresentationValue,
) -> Result<pb::PresentationValue, OpenId4VpProtoError> {
    let kind = match value {
        PresentationValue::Compact(value) => {
            Some(pb::presentation_value::Kind::Compact(value.clone()))
        }
        PresentationValue::Json(json) => {
            let presentation = parse_zk_presentation_value(value)
                .map_err(|_| OpenId4VpProtoError::InvalidField)?;
            if let Some(presentation) = presentation {
                return Ok(pb::PresentationValue {
                    kind: Some(pb::presentation_value::Kind::Zk(Box::new(
                        zk_presentation_to_proto(&presentation),
                    ))),
                    __buffa_unknown_fields: Default::default(),
                });
            }
            let bytes = serde_json::to_vec(json).map_err(|_| OpenId4VpProtoError::JsonSerialize)?;
            Some(pb::presentation_value::Kind::Json(bytes))
        }
    };
    Ok(pb::PresentationValue {
        kind,
        __buffa_unknown_fields: Default::default(),
    })
}

fn proto_to_presentation_value(
    value: &pb::PresentationValue,
) -> Result<PresentationValue, OpenId4VpProtoError> {
    let Some(kind) = value.kind.as_ref() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    match kind {
        pb::presentation_value::Kind::Compact(value) => {
            Ok(PresentationValue::Compact(value.clone()))
        }
        pb::presentation_value::Kind::Json(value) => serde_json::from_slice(value)
            .map(PresentationValue::Json)
            .map_err(|_| OpenId4VpProtoError::JsonDeserialize),
        pb::presentation_value::Kind::Zk(value) => {
            let presentation = proto_to_zk_presentation(value.as_ref())?;
            serde_json::to_value(presentation)
                .map(PresentationValue::Json)
                .map_err(|_| OpenId4VpProtoError::JsonSerialize)
        }
    }
}

fn zk_presentation_to_proto(presentation: &ZkPresentation) -> pb::ZkPresentation {
    pb::ZkPresentation {
        r#type: presentation.type_.clone(),
        circuit_id: presentation.circuit_id.clone(),
        proof: presentation.proof.clone(),
        public_inputs: presentation.public_inputs.clone(),
        derived_claims: presentation
            .derived_claims
            .iter()
            .map(derived_claim_statement_to_proto)
            .collect(),
        binding: MessageField::some(zk_presentation_binding_to_proto(&presentation.binding)),
        circuit_ref: match presentation.circuit_ref.as_ref() {
            Some(circuit_ref) => {
                MessageField::some(zk_presentation_circuit_ref_to_proto(circuit_ref))
            }
            None => MessageField::none(),
        },
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_zk_presentation(
    presentation: &pb::ZkPresentation,
) -> Result<ZkPresentation, OpenId4VpProtoError> {
    let Some(binding) = presentation.binding.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    Ok(ZkPresentation {
        type_: presentation.r#type.clone(),
        circuit_id: presentation.circuit_id.clone(),
        proof: presentation.proof.clone(),
        public_inputs: presentation.public_inputs.clone(),
        derived_claims: presentation
            .derived_claims
            .iter()
            .map(proto_to_derived_claim_statement)
            .collect(),
        binding: proto_to_zk_presentation_binding(binding)?,
        circuit_ref: presentation
            .circuit_ref
            .as_option()
            .map(proto_to_zk_presentation_circuit_ref),
    })
}

fn derived_claim_statement_to_proto(
    statement: &DerivedClaimStatement,
) -> pb::DerivedClaimStatement {
    pb::DerivedClaimStatement {
        statement_id: statement.statement_id.clone(),
        statement: statement.statement.clone(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_derived_claim_statement(
    statement: &pb::DerivedClaimStatement,
) -> DerivedClaimStatement {
    DerivedClaimStatement {
        statement_id: statement.statement_id.clone(),
        statement: statement.statement.clone(),
    }
}

fn zk_presentation_binding_to_proto(binding: &ZkPresentationBinding) -> pb::ZkPresentationBinding {
    pb::ZkPresentationBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding.transaction_data_hash.map(|hash| hash.to_vec()),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_zk_presentation_binding(
    binding: &pb::ZkPresentationBinding,
) -> Result<ZkPresentationBinding, OpenId4VpProtoError> {
    Ok(ZkPresentationBinding {
        nonce_hash: hash_bytes_to_array(binding.nonce_hash.clone())?,
        audience_hash: hash_bytes_to_array(binding.audience_hash.clone())?,
        transaction_data_hash: match binding.transaction_data_hash.clone() {
            Some(hash) => Some(hash_bytes_to_array(hash)?),
            None => None,
        },
    })
}

fn zk_presentation_circuit_ref_to_proto(
    circuit_ref: &ZkPresentationCircuitRef,
) -> pb::ZkPresentationCircuitRef {
    pb::ZkPresentationCircuitRef {
        hash_strategy: circuit_ref.hash_strategy.clone(),
        family: circuit_ref.family.clone(),
        stage: circuit_ref.stage.clone(),
        version: circuit_ref.version,
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_zk_presentation_circuit_ref(
    circuit_ref: &pb::ZkPresentationCircuitRef,
) -> ZkPresentationCircuitRef {
    ZkPresentationCircuitRef {
        hash_strategy: circuit_ref.hash_strategy.clone(),
        family: circuit_ref.family.clone(),
        stage: circuit_ref.stage.clone(),
        version: circuit_ref.version,
    }
}

fn hash_bytes_to_array(value: Vec<u8>) -> Result<[u8; 32], OpenId4VpProtoError> {
    <[u8; 32]>::try_from(value).map_err(|_| OpenId4VpProtoError::InvalidField)
}
