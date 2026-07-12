// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::MessageField;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use reallyme_openid4vp_dc_api::DigitalCredentialRequestOptions;
use reallyme_openid4vp_proto::generated::connect::openid4vp::v1::OpenId4VpDcApiService;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1::__buffa::oneof::decode_dc_api_authorization_response_request::Response;
use reallyme_openid4vp_proto_codec::{
    authorization_response_to_proto, digital_credential_request_options_to_proto,
    problem_details_to_proto, proto_to_dc_api_authorization_response,
    proto_to_digital_credential_get_request, proto_to_encrypted_dc_api_authorization_response,
};
use reallyme_openid4vp_types::{ProblemDetails, ProblemKind};

use crate::map_runtime_problem::runtime_error_to_problem_proto;
use crate::{RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

impl OpenId4VpDcApiService for VerifierRuntimeService {
    async fn build_digital_credential_request_options<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::BuildDigitalCredentialRequestOptionsRequest>,
    ) -> ServiceResult<
        impl connectrpc::Encodable<pb::BuildDigitalCredentialRequestOptionsResponse> + Send + use<'a>,
    > {
        let owned = request.to_owned_message();
        Ok(connectrpc::Response::new(
            self.build_digital_credential_request_options_body(&owned),
        ))
    }

    async fn decode_dc_api_authorization_response<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::DecodeDcApiAuthorizationResponseRequest>,
    ) -> ServiceResult<
        impl connectrpc::Encodable<pb::DecodeDcApiAuthorizationResponseResponse> + Send + use<'a>,
    > {
        let owned = request.to_owned_message();
        Ok(connectrpc::Response::new(
            self.decode_dc_api_authorization_response_body(&owned),
        ))
    }
}

impl VerifierRuntimeService {
    pub(crate) fn build_digital_credential_request_options_body(
        &self,
        request: &pb::BuildDigitalCredentialRequestOptionsRequest,
    ) -> pb::BuildDigitalCredentialRequestOptionsResponse {
        match self.try_build_digital_credential_request_options_body(request) {
            Ok(options) => pb::BuildDigitalCredentialRequestOptionsResponse {
                options: MessageField::some(options),
                ..Default::default()
            },
            Err(problem) => pb::BuildDigitalCredentialRequestOptionsResponse {
                problem: MessageField::some(problem),
                ..Default::default()
            },
        }
    }

    pub(crate) fn decode_dc_api_authorization_response_body(
        &self,
        request: &pb::DecodeDcApiAuthorizationResponseRequest,
    ) -> pb::DecodeDcApiAuthorizationResponseResponse {
        match self.try_decode_dc_api_authorization_response_body(request) {
            Ok(response) => pb::DecodeDcApiAuthorizationResponseResponse {
                response: MessageField::some(response),
                ..Default::default()
            },
            Err(problem) => pb::DecodeDcApiAuthorizationResponseResponse {
                problem: MessageField::some(problem),
                ..Default::default()
            },
        }
    }

    fn try_build_digital_credential_request_options_body(
        &self,
        request: &pb::BuildDigitalCredentialRequestOptionsRequest,
    ) -> Result<pb::DigitalCredentialRequestOptions, pb::ProblemDetails> {
        let requests = request
            .requests
            .iter()
            .map(proto_to_digital_credential_get_request)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid_request_problem())?;
        let options = DigitalCredentialRequestOptions::new(requests)
            .map_err(|_| invalid_request_problem())?;
        digital_credential_request_options_to_proto(&options).map_err(|_| invalid_request_problem())
    }

    fn try_decode_dc_api_authorization_response_body(
        &self,
        request: &pb::DecodeDcApiAuthorizationResponseRequest,
    ) -> Result<pb::AuthorizationResponse, pb::ProblemDetails> {
        let Some(response) = request.response.as_ref() else {
            return Err(runtime_error_to_problem_proto(RuntimeError::new(
                RuntimeErrorReason::MissingField,
            )));
        };
        let response = match response {
            Response::Plaintext(plaintext) => {
                proto_to_dc_api_authorization_response(plaintext)
                    .map_err(|_| invalid_request_problem())?
                    .data
            }
            Response::Encrypted(encrypted) => {
                let encrypted = proto_to_encrypted_dc_api_authorization_response(encrypted)
                    .map_err(|_| invalid_request_problem())?;
                let Some(decryptor) = self.response_jwt_decryptor() else {
                    return Err(runtime_error_to_problem_proto(RuntimeError::new(
                        RuntimeErrorReason::MissingResponseJwtDecryptor,
                    )));
                };
                decryptor
                    .decrypt_authorization_response_jwt(&encrypted.response)
                    .map_err(runtime_error_to_problem_proto)?
            }
        };
        authorization_response_to_proto(&response).map_err(|_| invalid_request_problem())
    }
}

fn invalid_request_problem() -> pb::ProblemDetails {
    problem_details_to_proto(&ProblemDetails::from_kind(ProblemKind::InvalidRequest))
}
