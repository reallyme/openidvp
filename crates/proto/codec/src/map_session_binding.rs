// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::MessageField;
use reallyme_openid4vp_dcql::DcqlQuery;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_verifier::{
    HolderBindingClaims, RequestBinding, SessionRecord as VerifierSessionRecord,
};

use crate::map_client_identifier::{client_identifier_to_proto, proto_to_client_identifier};
use crate::report_proto_error::OpenId4VpProtoError;

/// Map verifier request binding into the generated protobuf message.
pub fn request_binding_to_proto(binding: &RequestBinding) -> pb::RequestBinding {
    pb::RequestBinding {
        client_id: MessageField::some(client_identifier_to_proto(&binding.client_id)),
        nonce: binding.nonce.clone(),
        response_uri: binding.response_uri.clone(),
        redirect_uri: binding.redirect_uri.clone(),
        expiry_unix: binding.expiry_unix,
        transaction_data_hash: binding.transaction_data_hash.map(|hash| hash.to_vec()),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map a generated protobuf request binding into verifier session binding.
pub fn proto_to_request_binding(
    binding: &pb::RequestBinding,
) -> Result<RequestBinding, OpenId4VpProtoError> {
    let Some(client_id) = binding.client_id.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    Ok(RequestBinding {
        client_id: proto_to_client_identifier(client_id)?,
        nonce: binding.nonce.clone(),
        response_uri: binding.response_uri.clone(),
        redirect_uri: binding.redirect_uri.clone(),
        expiry_unix: binding.expiry_unix,
        transaction_data_hash: optional_hash_bytes_to_array(binding.transaction_data_hash.clone())?,
    })
}

fn optional_hash_bytes_to_array(
    hash: Option<Vec<u8>>,
) -> Result<Option<[u8; 32]>, OpenId4VpProtoError> {
    let Some(hash) = hash else {
        return Ok(None);
    };
    let hash = <[u8; 32]>::try_from(hash).map_err(|_| OpenId4VpProtoError::InvalidField)?;
    Ok(Some(hash))
}

/// Map decoded holder-binding claims into the generated protobuf message.
pub fn holder_binding_claims_to_proto(claims: &HolderBindingClaims) -> pb::HolderBindingClaims {
    pb::HolderBindingClaims {
        audience: claims.audience.clone(),
        nonce: claims.nonce.clone(),
        expiration_unix: claims.expiration_unix,
        issued_at_unix: claims.issued_at_unix,
        sd_hash: claims.sd_hash.clone(),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated holder-binding claims into the verifier model.
pub fn proto_to_holder_binding_claims(claims: &pb::HolderBindingClaims) -> HolderBindingClaims {
    HolderBindingClaims {
        audience: claims.audience.clone(),
        nonce: claims.nonce.clone(),
        expiration_unix: claims.expiration_unix,
        issued_at_unix: claims.issued_at_unix,
        sd_hash: claims.sd_hash.clone(),
    }
}

/// Map a verifier session record into the generated protobuf message.
pub fn session_record_to_proto(
    record: &VerifierSessionRecord,
) -> Result<pb::SessionRecord, OpenId4VpProtoError> {
    let dcql_query_json =
        serde_json::to_vec(&record.dcql_query).map_err(|_| OpenId4VpProtoError::JsonSerialize)?;
    Ok(pb::SessionRecord {
        binding: MessageField::some(request_binding_to_proto(&record.binding)),
        state: record.state.clone(),
        dcql_query_json,
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map a generated protobuf session record into the verifier model.
pub fn proto_to_session_record(
    record: &pb::SessionRecord,
) -> Result<VerifierSessionRecord, OpenId4VpProtoError> {
    let Some(binding) = record.binding.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    let dcql_query = DcqlQuery::from_json_slice(&record.dcql_query_json)
        .map_err(|_| OpenId4VpProtoError::InvalidField)?;
    Ok(VerifierSessionRecord {
        binding: proto_to_request_binding(binding)?,
        state: record.state.clone(),
        dcql_query,
    })
}
