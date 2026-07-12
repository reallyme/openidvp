// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::JSON_MEDIA_TYPE;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::build_authorization_request_launch_response::authorization_request_launch_response;
use crate::build_problem_response::problem_http_response;
use crate::serve_request_object::validate_content_type;
use crate::{
    runtime_error_to_problem, AuthorizationRequestLaunchRequest, AuthorizationRequestLaunchStore,
    RuntimeError, RuntimeErrorReason, RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse,
    VerifierRuntimeService,
};

const DEFAULT_MAX_LAUNCH_BODY_BYTES: usize = 16 * 1024;
const AUTHORIZATION_ENDPOINT_FIELD: &str = "authorization_endpoint";
const MODULE_ID_FIELD: &str = "module_id";
const MODULE_NAME_FIELD: &str = "module_name";

/// Parsed request from the OIDF verifier flow driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequestLaunchHttpRequest {
    /// OIDF mock wallet authorization endpoint.
    pub authorization_endpoint: String,
    /// OIDF module id.
    pub module_id: String,
    /// OIDF module name, when exposed by the suite.
    pub module_name: Option<String>,
}

/// Host-owned planner for conformance verifier launch requests.
///
/// The runtime validates transport shape and signs/stores the resulting request,
/// but host policy decides the DCQL query, client identifier prefix, session
/// keys, request_uri, response_uri, and metadata for each conformance module.
pub trait AuthorizationRequestLaunchPlanner: Send + Sync {
    /// Build a final OpenID4VP launch request from the OIDF module context.
    fn plan_authorization_request_launch(
        &self,
        request: &AuthorizationRequestLaunchHttpRequest,
    ) -> Result<AuthorizationRequestLaunchRequest, RuntimeError>;
}

/// Dependencies for the framework-neutral launch endpoint.
pub struct AuthorizationRequestLaunchHttpContext<'a> {
    /// Runtime verifier service with signer and policy dependencies.
    pub service: &'a VerifierRuntimeService,
    /// Host launch planner.
    pub planner: &'a dyn AuthorizationRequestLaunchPlanner,
    /// Atomic host store for session and hosted Request Object material.
    pub store: &'a dyn AuthorizationRequestLaunchStore,
    /// Current Unix timestamp.
    pub now_unix: u64,
    /// Maximum accepted JSON body size.
    pub max_body_bytes: usize,
}

impl<'a> AuthorizationRequestLaunchHttpContext<'a> {
    /// Build a launch context with default body-size policy.
    pub const fn new(
        service: &'a VerifierRuntimeService,
        planner: &'a dyn AuthorizationRequestLaunchPlanner,
        store: &'a dyn AuthorizationRequestLaunchStore,
        now_unix: u64,
    ) -> Self {
        Self {
            service,
            planner,
            store,
            now_unix,
            max_body_bytes: DEFAULT_MAX_LAUNCH_BODY_BYTES,
        }
    }

    /// Override maximum accepted JSON body size.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

/// Handle the conformance-only verifier launch endpoint.
pub fn handle_authorization_request_launch_http(
    request: &RuntimeHttpRequest,
    context: AuthorizationRequestLaunchHttpContext<'_>,
) -> RuntimeHttpResponse {
    match try_handle_authorization_request_launch_http(request, context) {
        Ok(response) => response,
        Err(error) => problem_http_response(runtime_error_to_problem(error)),
    }
}

fn try_handle_authorization_request_launch_http(
    request: &RuntimeHttpRequest,
    context: AuthorizationRequestLaunchHttpContext<'_>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    if request.method != RuntimeHttpMethod::Post {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidHttpMethod));
    }
    validate_content_type(request.content_type.as_deref(), JSON_MEDIA_TYPE)?;
    if request.body.len() > context.max_body_bytes {
        return Err(RuntimeError::new(RuntimeErrorReason::BodyTooLarge));
    }
    let launch_request = parse_launch_http_request(&request.body)?;
    let planned = context
        .planner
        .plan_authorization_request_launch(&launch_request)?;
    let launch = context.service.prepare_authorization_request_launch(
        &planned,
        context.store,
        context.now_unix,
    )?;
    authorization_request_launch_response(&launch)
}

fn parse_launch_http_request(
    body: &[u8],
) -> Result<AuthorizationRequestLaunchHttpRequest, RuntimeError> {
    let value: JsonValue = serde_json::from_slice(body)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidFormBody))?;
    let Some(object) = value.as_object() else {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    };
    Ok(AuthorizationRequestLaunchHttpRequest {
        authorization_endpoint: required_json_string(object, AUTHORIZATION_ENDPOINT_FIELD)?,
        module_id: required_json_string(object, MODULE_ID_FIELD)?,
        module_name: optional_json_string(object, MODULE_NAME_FIELD)?,
    })
}

fn required_json_string(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> Result<String, RuntimeError> {
    let Some(value) = object.get(key) else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    };
    let Some(value) = value.as_str() else {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    };
    if value.is_empty() {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }
    Ok(value.to_owned())
}

fn optional_json_string(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> Result<Option<String>, RuntimeError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    };
    if value.is_empty() {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }
    Ok(Some(value.to_owned()))
}
