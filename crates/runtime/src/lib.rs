// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Runtime Connect and HTTP service adapters for OpenID4VP.

mod build_authorization_request_launch_response;
mod build_connect_router;
mod build_direct_post_success_response;
mod build_problem_response;
mod build_verifier_service;
mod compare_secret;
mod consume_verifier_session;
mod decrypt_authorization_response_jwt;
#[cfg(feature = "jose")]
mod decrypt_authorization_response_with_jose;
mod define_http_message;
mod handle_authorization_error_response;
mod handle_authorization_request_launch;
mod handle_direct_post;
mod handle_direct_post_jwt;
mod implement_dc_api_connect;
mod implement_verifier_connect;
mod load_request_object;
mod map_runtime_problem;
mod parse_form_urlencoded;
mod prepare_authorization_request_launch;
mod read_runtime_clock;
mod report_runtime_error;
mod route_verifier_http;
mod serve_request_object;
#[cfg(feature = "native")]
mod serve_verifier_connect;
mod validate_authorization_response;
#[cfg(test)]
mod verify_runtime;

pub use build_authorization_request_launch_response::authorization_request_launch_response;
pub use build_connect_router::build_verifier_connect_router;
pub use build_verifier_service::{VerifierRuntimeConfig, VerifierRuntimeService};
pub use consume_verifier_session::VerifierSessionStore;
pub use decrypt_authorization_response_jwt::AuthorizationResponseJwtDecryptor;
#[cfg(feature = "jose")]
pub use decrypt_authorization_response_with_jose::JoseAuthorizationResponseJwtDecryptor;
pub use define_http_message::{RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse};
pub use handle_authorization_request_launch::{
    handle_authorization_request_launch_http, AuthorizationRequestLaunchHttpContext,
    AuthorizationRequestLaunchHttpRequest, AuthorizationRequestLaunchPlanner,
};
pub use handle_direct_post::{handle_direct_post_http, DirectPostValidationContext};
pub use handle_direct_post_jwt::handle_direct_post_jwt_http;
pub use load_request_object::{HostedRequestObject, RequestObjectStore};
pub use map_runtime_problem::runtime_error_to_problem;
pub use prepare_authorization_request_launch::{
    AuthorizationRequestLaunch, AuthorizationRequestLaunchRequest, AuthorizationRequestLaunchStore,
    AuthorizationRequestLaunchStoreRecord, AuthorizationRequestParameter,
    AuthorizationRequestParameterName,
};
pub use read_runtime_clock::{RuntimeClock, SystemRuntimeClock};
pub use report_runtime_error::{RuntimeError, RuntimeErrorReason};
pub use route_verifier_http::{VerifierHttpEndpoint, VerifierHttpRuntime};
pub use serve_request_object::serve_request_object_http;
#[cfg(feature = "native")]
pub use serve_verifier_connect::{
    build_verifier_connect_server, serve_verifier_connect, serve_verifier_connect_with_shutdown,
};
