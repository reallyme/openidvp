// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::MessageField;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use reallyme_openid4vp_proto::generated::connect::openid4vp::v1::OpenId4VpVerifierService;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_request_to_proto, problem_details_to_proto, proto_to_authorization_request,
    proto_to_authorization_response, proto_to_session_record, request_binding_to_proto,
};
use reallyme_openid4vp_verifier::{
    validate_authorization_response_with_options, validate_jar_claims_for_signing, JarPolicy,
    RequestBinding, ResponseValidationOptions,
};

use crate::map_runtime_problem::runtime_error_to_problem_proto;
use crate::{RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

impl OpenId4VpVerifierService for VerifierRuntimeService {
    async fn build_authorization_request<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::BuildAuthorizationRequestRequest>,
    ) -> ServiceResult<
        impl connectrpc::Encodable<pb::BuildAuthorizationRequestResponse> + Send + use<'a>,
    > {
        let owned = request.to_owned_message();
        Ok(connectrpc::Response::new(
            self.build_authorization_request_response(&owned),
        ))
    }

    async fn validate_authorization_response<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::ValidateAuthorizationResponseRequest>,
    ) -> ServiceResult<
        impl connectrpc::Encodable<pb::ValidateAuthorizationResponseResponse> + Send + use<'a>,
    > {
        let owned = request.to_owned_message();
        Ok(connectrpc::Response::new(
            self.validate_authorization_response_body(&owned),
        ))
    }
}

impl VerifierRuntimeService {
    pub(crate) fn build_authorization_request_response(
        &self,
        request: &pb::BuildAuthorizationRequestRequest,
    ) -> pb::BuildAuthorizationRequestResponse {
        match self.try_build_authorization_request_response(request) {
            Ok(response) => response,
            Err(error) => pb::BuildAuthorizationRequestResponse {
                problem: MessageField::some(runtime_error_to_problem_proto(error)),
                ..Default::default()
            },
        }
    }

    pub(crate) fn validate_authorization_response_body(
        &self,
        request: &pb::ValidateAuthorizationResponseRequest,
    ) -> pb::ValidateAuthorizationResponseResponse {
        match self.try_validate_authorization_response_body(request) {
            Ok(()) => pb::ValidateAuthorizationResponseResponse {
                valid: true,
                ..Default::default()
            },
            Err(problem) => pb::ValidateAuthorizationResponseResponse {
                valid: false,
                problem: MessageField::some(problem),
                ..Default::default()
            },
        }
    }

    fn try_build_authorization_request_response(
        &self,
        request: &pb::BuildAuthorizationRequestRequest,
    ) -> Result<pb::BuildAuthorizationRequestResponse, RuntimeError> {
        let Some(proto_request) = request.request.as_option() else {
            return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
        };
        let domain_request = proto_to_authorization_request(proto_request)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
        let binding = request_binding_from_authorization_request(&domain_request)?;

        let mut response = pb::BuildAuthorizationRequestResponse {
            binding: MessageField::some(request_binding_to_proto(&binding)),
            ..Default::default()
        };

        if request.sign_request_object {
            let Some(signer) = self.signer() else {
                return Err(RuntimeError::new(RuntimeErrorReason::MissingSigner));
            };
            validate_jar_claims_for_signing(&domain_request, JarPolicy::default())
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
            let jwt = signer
                .sign_request_object(&domain_request)
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
            response.request_jwt = Some(jwt.as_str().to_owned());
        } else {
            response.request = MessageField::some(
                authorization_request_to_proto(&domain_request)
                    .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?,
            );
        }

        Ok(response)
    }

    fn try_validate_authorization_response_body(
        &self,
        request: &pb::ValidateAuthorizationResponseRequest,
    ) -> Result<(), pb::ProblemDetails> {
        let Some(proto_session) = request.session.as_option() else {
            return Err(runtime_error_to_problem_proto(RuntimeError::new(
                RuntimeErrorReason::MissingField,
            )));
        };
        let session = proto_to_session_record(proto_session).map_err(|_| {
            runtime_error_to_problem_proto(RuntimeError::new(RuntimeErrorReason::InvalidProto))
        })?;
        let Some(proto_response) = request.response.as_option() else {
            return Err(runtime_error_to_problem_proto(RuntimeError::new(
                RuntimeErrorReason::MissingField,
            )));
        };
        let response = proto_to_authorization_response(proto_response).map_err(|_| {
            problem_details_to_proto(&reallyme_openid4vp_types::ProblemDetails::from_kind(
                reallyme_openid4vp_types::ProblemKind::InvalidRequest,
            ))
        })?;

        validate_authorization_response_with_options(
            &session,
            &response,
            request.now_unix,
            ResponseValidationOptions {
                holder_binding_verifier: self.holder_binding_verifier(),
                zk_verifier: self.zk_verifier(),
                zk_policy: self.zk_policy(),
            },
        )
        .map_err(|error| problem_details_to_proto(&error.into()))
    }
}

pub(crate) fn request_binding_from_authorization_request(
    request: &reallyme_openid4vp_types::AuthorizationRequestObject,
) -> Result<RequestBinding, RuntimeError> {
    let Some(client_id) = request.client_id.clone() else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    };
    let Some(expiry_unix) = request.exp else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    };
    if request.nonce.is_empty() {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }
    Ok(RequestBinding {
        client_id,
        nonce: request.nonce.clone(),
        response_uri: request.response_uri.clone(),
        redirect_uri: request.redirect_uri.clone(),
        expiry_unix,
        transaction_data_hash: transaction_data_hash_from_request(request)?,
    })
}

fn transaction_data_hash_from_request(
    request: &reallyme_openid4vp_types::AuthorizationRequestObject,
) -> Result<Option<[u8; 32]>, RuntimeError> {
    let Some(transaction_data) = request.transaction_data.as_ref() else {
        return Ok(None);
    };
    if transaction_data.is_empty() {
        return Ok(None);
    }
    if transaction_data.len() != 1 {
        return Err(RuntimeError::new(RuntimeErrorReason::UnsupportedFeature));
    }
    let hash = reallyme_openid4vp_types::TransactionDataHash::sha256_transaction_data(
        &transaction_data[0],
    )
    .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
    Ok(Some(hash.digest))
}
