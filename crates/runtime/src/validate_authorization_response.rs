// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::MessageField;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{authorization_response_to_proto, session_record_to_proto};
use reallyme_openid4vp_types::AuthorizationResponse;
use reallyme_openid4vp_verifier::SessionRecord;

use crate::build_direct_post_success_response::direct_post_success_response;
use crate::build_problem_response::problem_proto_http_response;
use crate::{RuntimeError, RuntimeErrorReason, RuntimeHttpResponse, VerifierRuntimeService};

pub(crate) fn validate_authorization_response_for_session(
    service: &VerifierRuntimeService,
    response: &AuthorizationResponse,
    session: &SessionRecord,
    now_unix: u64,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let proto_response = authorization_response_to_proto(response)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
    let proto_session = session_record_to_proto(session)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
    let validation =
        service.validate_authorization_response_body(&pb::ValidateAuthorizationResponseRequest {
            session: MessageField::some(proto_session),
            response: MessageField::some(proto_response),
            now_unix,
            __buffa_unknown_fields: Default::default(),
        });
    if validation.valid {
        return Ok(direct_post_success_response());
    }
    let Some(problem) = validation.problem.as_option() else {
        return Err(RuntimeError::new(
            RuntimeErrorReason::ResponseValidationFailed,
        ));
    };
    Ok(problem_proto_http_response(problem))
}
