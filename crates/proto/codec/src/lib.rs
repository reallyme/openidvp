// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Buffa protobuf transport mappings for OpenID4VP.
//!
//! Protobuf is the primary transport boundary. JSON helpers serialize and parse
//! the generated protobuf JSON shape; they do not define a second wire model.

mod convert;
mod encode_message;
mod map_authorization_request_transport;
mod map_authorization_response;
mod map_client_identifier;
mod map_dc_api;
mod map_metadata;
mod map_problem_details;
mod map_session_binding;
mod report_proto_error;

pub use convert::{authorization_request_to_proto, proto_to_authorization_request};
pub use encode_message::{
    authorization_request_json_to_proto, authorization_request_proto_to_json,
    authorization_response_json_to_proto, authorization_response_proto_to_json,
    decode_authorization_request, decode_authorization_request_proto,
    decode_authorization_response, decode_authorization_response_proto,
    encode_authorization_request, encode_authorization_request_proto,
    encode_authorization_response, encode_authorization_response_proto,
};
pub use map_authorization_request_transport::{
    authorization_request_transport_to_proto, proto_to_authorization_request_transport,
};
pub use map_authorization_response::{
    authorization_response_to_proto, proto_to_authorization_response,
};
pub use map_client_identifier::{client_identifier_to_proto, proto_to_client_identifier};
pub use map_dc_api::{
    dc_api_authorization_response_to_proto, dc_api_protocol_to_proto,
    digital_credential_get_request_to_proto, digital_credential_request_options_to_proto,
    encrypted_dc_api_authorization_response_to_proto, proto_to_dc_api_authorization_response,
    proto_to_dc_api_protocol, proto_to_digital_credential_get_request,
    proto_to_digital_credential_request_options, proto_to_encrypted_dc_api_authorization_response,
};
pub use map_metadata::{
    proto_to_verifier_metadata, proto_to_wallet_metadata, verifier_metadata_to_proto,
    wallet_metadata_to_proto,
};
pub use map_problem_details::{problem_details_to_proto, proto_to_problem_details};
pub use map_session_binding::{
    holder_binding_claims_to_proto, proto_to_holder_binding_claims, proto_to_request_binding,
    proto_to_session_record, request_binding_to_proto, session_record_to_proto,
};
pub use report_proto_error::OpenId4VpProtoError;
