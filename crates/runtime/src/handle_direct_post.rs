// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::AuthorizationResponse;
use reallyme_openid4vp_verifier::SessionRecord;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::build_problem_response::problem_http_response;
use crate::define_http_message::{RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse};
use crate::handle_authorization_error_response::{
    handle_authorization_error_response, has_authorization_error,
};
use crate::parse_form_urlencoded::{
    optional_unique_field, parse_form_urlencoded, required_unique_field,
};
use crate::serve_request_object::form_urlencoded_media_type;
use crate::serve_request_object::validate_content_type;
use crate::validate_authorization_response::validate_authorization_response_for_session;
use crate::{runtime_error_to_problem, RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

const DEFAULT_MAX_DIRECT_POST_BODY_BYTES: usize = 128 * 1024;
const VP_TOKEN_FIELD: &str = "vp_token";
const STATE_FIELD: &str = "state";

/// Validation context for a `direct_post` Authorization Response.
pub struct DirectPostValidationContext<'a> {
    /// Session state loaded by the HTTP adapter.
    pub session: &'a SessionRecord,
    /// Current Unix timestamp.
    pub now_unix: u64,
    /// Maximum accepted form body size.
    pub max_body_bytes: usize,
}

impl<'a> DirectPostValidationContext<'a> {
    /// Build a validation context with default body-size policy.
    pub const fn new(session: &'a SessionRecord, now_unix: u64) -> Self {
        Self {
            session,
            now_unix,
            max_body_bytes: DEFAULT_MAX_DIRECT_POST_BODY_BYTES,
        }
    }

    /// Override maximum accepted form body size.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

/// Handle an OpenID4VP `direct_post` HTTP response.
pub fn handle_direct_post_http(
    service: &VerifierRuntimeService,
    request: &RuntimeHttpRequest,
    context: DirectPostValidationContext<'_>,
) -> RuntimeHttpResponse {
    match try_handle_direct_post_http(service, request, context) {
        Ok(response) => response,
        Err(error) => problem_http_response(runtime_error_to_problem(error)),
    }
}

fn try_handle_direct_post_http(
    service: &VerifierRuntimeService,
    request: &RuntimeHttpRequest,
    context: DirectPostValidationContext<'_>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    if request.method != RuntimeHttpMethod::Post {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidHttpMethod));
    }
    validate_content_type(
        request.content_type.as_deref(),
        form_urlencoded_media_type(),
    )?;
    if request.body.len() > context.max_body_bytes {
        return Err(RuntimeError::new(RuntimeErrorReason::BodyTooLarge));
    }

    let pairs = parse_form_urlencoded(&request.body)?;
    if has_authorization_error(&pairs) {
        return handle_authorization_error_response(&pairs, context.session);
    }

    let response = parse_direct_post_response_pairs(&pairs)?;
    validate_authorization_response_for_session(
        service,
        &response,
        context.session,
        context.now_unix,
    )
}

pub(crate) fn parse_direct_post_response_pairs(
    pairs: &[crate::parse_form_urlencoded::FormPair],
) -> Result<AuthorizationResponse, RuntimeError> {
    let vp_token = required_unique_field(pairs, VP_TOKEN_FIELD)?;
    let state = optional_unique_field(pairs, STATE_FIELD)?;
    let vp_token_json: JsonValue = serde_json::from_str(&vp_token)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidFormBody))?;

    let mut response = JsonMap::new();
    response.insert(VP_TOKEN_FIELD.to_owned(), vp_token_json);
    if let Some(state) = state {
        response.insert(STATE_FIELD.to_owned(), JsonValue::String(state));
    }
    serde_json::from_value(JsonValue::Object(response))
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidFormBody))
}
