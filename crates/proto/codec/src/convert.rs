// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Buffa protobuf transport mappings for OpenID4VP.
//!
//! Protobuf is the primary transport boundary. JSON helpers serialize and parse
//! the generated protobuf JSON shape; they do not define a second wire model.

use buffa::MessageField;
use reallyme_openid4vp_dcql::DcqlQuery;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientMetadata, ResponseMode, ResponseType, TransactionData,
};

use crate::map_client_identifier::{client_identifier_to_proto, proto_to_client_identifier};
use crate::report_proto_error::OpenId4VpProtoError;

/// Map a Rust AuthorizationRequestObject into the generated protobuf message.
pub fn authorization_request_to_proto(
    request: &AuthorizationRequestObject,
) -> Result<pb::AuthorizationRequest, OpenId4VpProtoError> {
    let client_id = match request.client_id.as_ref() {
        Some(client_id) => MessageField::some(client_identifier_to_proto(client_id)),
        None => MessageField::none(),
    };
    let dcql_query_json =
        serde_json::to_vec(&request.dcql_query).map_err(|_| OpenId4VpProtoError::JsonSerialize)?;
    let transaction_data = match request.transaction_data.as_ref() {
        Some(values) => values
            .iter()
            .map(transaction_data_to_proto)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    let client_metadata = match request.client_metadata.as_ref() {
        Some(metadata) => MessageField::some(client_metadata_to_proto(metadata)?),
        None => MessageField::none(),
    };
    let expected_origins = match request.expected_origins.as_ref() {
        Some(origins) => origins.clone(),
        None => Vec::new(),
    };
    let aud = match request.aud.as_ref() {
        Some(audiences) => audiences.clone(),
        None => Vec::new(),
    };

    Ok(pb::AuthorizationRequest {
        client_id,
        response_type: buffa::EnumValue::from(response_type_to_proto(request.response_type)),
        response_mode: request
            .response_mode
            .map(response_mode_to_proto)
            .map(buffa::EnumValue::from),
        response_uri: request.response_uri.clone(),
        redirect_uri: request.redirect_uri.clone(),
        nonce: request.nonce.clone(),
        wallet_nonce: request.wallet_nonce.clone(),
        state: request.state.clone(),
        dcql_query_json,
        transaction_data,
        client_metadata,
        client_metadata_uri: request.client_metadata_uri.clone(),
        expected_origins,
        iss: request.iss.clone(),
        aud,
        iat: request.iat,
        exp: request.exp,
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map a generated protobuf AuthorizationRequest into the Rust request model.
pub fn proto_to_authorization_request(
    request: &pb::AuthorizationRequest,
) -> Result<AuthorizationRequestObject, OpenId4VpProtoError> {
    let response_type = proto_to_response_type(&request.response_type)?;
    let response_mode = match request.response_mode.as_ref() {
        Some(mode) => Some(proto_to_response_mode(mode)?),
        None => None,
    };
    let client_id = match request.client_id.as_option() {
        Some(client_id) => Some(proto_to_client_identifier(client_id)?),
        None => None,
    };
    let dcql_query = DcqlQuery::from_json_slice(&request.dcql_query_json)
        .map_err(|_| OpenId4VpProtoError::InvalidField)?;
    let transaction_data = if request.transaction_data.is_empty() {
        None
    } else {
        Some(
            request
                .transaction_data
                .iter()
                .map(proto_to_transaction_data)
                .collect::<Result<Vec<_>, _>>()?,
        )
    };
    let client_metadata = match request.client_metadata.as_option() {
        Some(metadata) => Some(proto_to_client_metadata(metadata)?),
        None => None,
    };
    let expected_origins = if request.expected_origins.is_empty() {
        None
    } else {
        Some(request.expected_origins.clone())
    };
    let aud = if request.aud.is_empty() {
        None
    } else {
        Some(request.aud.clone())
    };

    Ok(AuthorizationRequestObject {
        client_id,
        response_type,
        response_mode,
        response_uri: request.response_uri.clone(),
        redirect_uri: request.redirect_uri.clone(),
        nonce: request.nonce.clone(),
        wallet_nonce: request.wallet_nonce.clone(),
        state: request.state.clone(),
        dcql_query,
        transaction_data,
        client_metadata,
        client_metadata_uri: request.client_metadata_uri.clone(),
        expected_origins,
        iss: request.iss.clone(),
        aud,
        iat: request.iat,
        exp: request.exp,
    })
}

fn client_metadata_to_proto(
    metadata: &ClientMetadata,
) -> Result<pb::ClientMetadata, OpenId4VpProtoError> {
    let json = serde_json::to_vec(&metadata.raw).map_err(|_| OpenId4VpProtoError::JsonSerialize)?;
    Ok(pb::ClientMetadata {
        json,
        __buffa_unknown_fields: Default::default(),
    })
}

fn proto_to_client_metadata(
    metadata: &pb::ClientMetadata,
) -> Result<ClientMetadata, OpenId4VpProtoError> {
    let raw =
        serde_json::from_slice(&metadata.json).map_err(|_| OpenId4VpProtoError::InvalidField)?;
    Ok(ClientMetadata { raw })
}

fn transaction_data_to_proto(
    transaction_data: &TransactionData,
) -> Result<pb::TransactionData, OpenId4VpProtoError> {
    let payload_json = serde_json::to_vec(&transaction_data.payload)
        .map_err(|_| OpenId4VpProtoError::JsonSerialize)?;
    Ok(pb::TransactionData {
        r#type: transaction_data.transaction_type.clone(),
        credential_ids: transaction_data.credential_ids.clone(),
        payload_json,
        __buffa_unknown_fields: Default::default(),
    })
}

fn proto_to_transaction_data(
    transaction_data: &pb::TransactionData,
) -> Result<TransactionData, OpenId4VpProtoError> {
    let payload = serde_json::from_slice(&transaction_data.payload_json)
        .map_err(|_| OpenId4VpProtoError::InvalidField)?;
    Ok(TransactionData {
        transaction_type: transaction_data.r#type.clone(),
        credential_ids: transaction_data.credential_ids.clone(),
        payload,
    })
}

fn response_type_to_proto(response_type: ResponseType) -> pb::ResponseType {
    match response_type {
        ResponseType::VpToken => pb::ResponseType::VpToken,
        ResponseType::VpTokenIdToken => pb::ResponseType::VpTokenIdToken,
    }
}

fn proto_to_response_type(
    response_type: &buffa::EnumValue<pb::ResponseType>,
) -> Result<ResponseType, OpenId4VpProtoError> {
    match response_type.as_known() {
        Some(pb::ResponseType::VpToken) => Ok(ResponseType::VpToken),
        Some(pb::ResponseType::VpTokenIdToken) => Ok(ResponseType::VpTokenIdToken),
        Some(pb::ResponseType::Unspecified) | None => Err(OpenId4VpProtoError::InvalidEnumValue),
    }
}

fn response_mode_to_proto(response_mode: ResponseMode) -> pb::ResponseMode {
    match response_mode {
        ResponseMode::Fragment => pb::ResponseMode::Fragment,
        ResponseMode::FormPost => pb::ResponseMode::FormPost,
        ResponseMode::DirectPost => pb::ResponseMode::DirectPost,
        ResponseMode::DirectPostJwt => pb::ResponseMode::DirectPostJwt,
        ResponseMode::DcApi => pb::ResponseMode::DcApi,
        ResponseMode::DcApiJwt => pb::ResponseMode::DcApiJwt,
    }
}

fn proto_to_response_mode(
    response_mode: &buffa::EnumValue<pb::ResponseMode>,
) -> Result<ResponseMode, OpenId4VpProtoError> {
    match response_mode.as_known() {
        Some(pb::ResponseMode::Fragment) => Ok(ResponseMode::Fragment),
        Some(pb::ResponseMode::FormPost) => Ok(ResponseMode::FormPost),
        Some(pb::ResponseMode::DirectPost) => Ok(ResponseMode::DirectPost),
        Some(pb::ResponseMode::DirectPostJwt) => Ok(ResponseMode::DirectPostJwt),
        Some(pb::ResponseMode::DcApi) => Ok(ResponseMode::DcApi),
        Some(pb::ResponseMode::DcApiJwt) => Ok(ResponseMode::DcApiJwt),
        Some(pb::ResponseMode::Unspecified) | None => Err(OpenId4VpProtoError::InvalidEnumValue),
    }
}
