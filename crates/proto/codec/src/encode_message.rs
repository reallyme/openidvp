// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::Message;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{AuthorizationRequestObject, AuthorizationResponse};

use crate::convert::{authorization_request_to_proto, proto_to_authorization_request};
use crate::map_authorization_response::{
    authorization_response_to_proto, proto_to_authorization_response,
};
use crate::report_proto_error::OpenId4VpProtoError;

/// Encode a generated OpenID4VP protobuf message.
pub fn encode_authorization_response_proto(
    response: &pb::AuthorizationResponse,
) -> Result<Vec<u8>, OpenId4VpProtoError> {
    Ok(response.encode_to_vec())
}

/// Decode generated OpenID4VP AuthorizationResponse protobuf bytes.
pub fn decode_authorization_response_proto(
    bytes: &[u8],
) -> Result<pb::AuthorizationResponse, OpenId4VpProtoError> {
    pb::AuthorizationResponse::decode(&mut &bytes[..]).map_err(|_| OpenId4VpProtoError::Decode)
}

/// Encode a generated OpenID4VP AuthorizationRequest protobuf message.
pub fn encode_authorization_request_proto(
    request: &pb::AuthorizationRequest,
) -> Result<Vec<u8>, OpenId4VpProtoError> {
    Ok(request.encode_to_vec())
}

/// Decode generated OpenID4VP AuthorizationRequest protobuf bytes.
pub fn decode_authorization_request_proto(
    bytes: &[u8],
) -> Result<pb::AuthorizationRequest, OpenId4VpProtoError> {
    pb::AuthorizationRequest::decode(&mut &bytes[..]).map_err(|_| OpenId4VpProtoError::Decode)
}

/// Encode a Rust AuthorizationRequestObject as protobuf bytes.
pub fn encode_authorization_request(
    request: &AuthorizationRequestObject,
) -> Result<Vec<u8>, OpenId4VpProtoError> {
    let proto = authorization_request_to_proto(request)?;
    encode_authorization_request_proto(&proto)
}

/// Decode protobuf bytes into a Rust AuthorizationRequestObject.
pub fn decode_authorization_request(
    bytes: &[u8],
) -> Result<AuthorizationRequestObject, OpenId4VpProtoError> {
    let proto = decode_authorization_request_proto(bytes)?;
    proto_to_authorization_request(&proto)
}

/// Encode a Rust AuthorizationResponse as protobuf bytes.
pub fn encode_authorization_response(
    response: &AuthorizationResponse,
) -> Result<Vec<u8>, OpenId4VpProtoError> {
    let proto = authorization_response_to_proto(response)?;
    encode_authorization_response_proto(&proto)
}

/// Decode protobuf bytes into a Rust AuthorizationResponse.
pub fn decode_authorization_response(
    bytes: &[u8],
) -> Result<AuthorizationResponse, OpenId4VpProtoError> {
    let proto = decode_authorization_response_proto(bytes)?;
    proto_to_authorization_response(&proto)
}

/// Serialize a generated AuthorizationResponse with Buffa protobuf JSON rules.
pub fn authorization_response_proto_to_json(
    response: &pb::AuthorizationResponse,
) -> Result<String, OpenId4VpProtoError> {
    serde_json::to_string(response).map_err(|_| OpenId4VpProtoError::JsonSerialize)
}

/// Deserialize a generated AuthorizationResponse with Buffa protobuf JSON rules.
pub fn authorization_response_json_to_proto(
    json: &str,
) -> Result<pb::AuthorizationResponse, OpenId4VpProtoError> {
    serde_json::from_str(json).map_err(|_| OpenId4VpProtoError::JsonDeserialize)
}

/// Serialize a generated AuthorizationRequest with Buffa protobuf JSON rules.
pub fn authorization_request_proto_to_json(
    request: &pb::AuthorizationRequest,
) -> Result<String, OpenId4VpProtoError> {
    serde_json::to_string(request).map_err(|_| OpenId4VpProtoError::JsonSerialize)
}

/// Deserialize a generated AuthorizationRequest with Buffa protobuf JSON rules.
pub fn authorization_request_json_to_proto(
    json: &str,
) -> Result<pb::AuthorizationRequest, OpenId4VpProtoError> {
    serde_json::from_str(json).map_err(|_| OpenId4VpProtoError::JsonDeserialize)
}
