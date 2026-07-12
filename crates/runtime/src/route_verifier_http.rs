// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::build_problem_response::problem_http_response;
use crate::consume_verifier_session::VerifierSessionStore;
use crate::handle_direct_post::handle_direct_post_http;
use crate::handle_direct_post_jwt::handle_direct_post_jwt_http;
use crate::load_request_object::RequestObjectStore;
use crate::read_runtime_clock::RuntimeClock;
use crate::serve_request_object::serve_request_object_http;
use crate::{
    runtime_error_to_problem, DirectPostValidationContext, RuntimeHttpRequest, RuntimeHttpResponse,
    VerifierRuntimeService,
};

/// Runtime HTTP endpoint routed by the verifier host facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierHttpEndpoint<'a> {
    /// Hosted `request_uri` Request Object endpoint.
    RequestObject {
        /// Adapter-defined Request Object lookup key.
        request_object_key: &'a str,
    },
    /// Plain `direct_post` response endpoint.
    DirectPost {
        /// Adapter-defined verifier session lookup key.
        session_key: &'a str,
    },
    /// Encrypted `direct_post.jwt` response endpoint.
    DirectPostJwt {
        /// Adapter-defined verifier session lookup key.
        session_key: &'a str,
    },
}

/// Framework-neutral verifier HTTP runtime host.
pub struct VerifierHttpRuntime {
    service: Arc<VerifierRuntimeService>,
    sessions: Arc<dyn VerifierSessionStore + Send + Sync>,
    request_objects: Arc<dyn RequestObjectStore>,
    clock: Arc<dyn RuntimeClock>,
    max_direct_post_body_bytes: usize,
}

impl VerifierHttpRuntime {
    /// Construct a verifier HTTP runtime host.
    pub fn new(
        service: Arc<VerifierRuntimeService>,
        sessions: Arc<dyn VerifierSessionStore + Send + Sync>,
        request_objects: Arc<dyn RequestObjectStore>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Self {
        Self {
            service,
            sessions,
            request_objects,
            clock,
            max_direct_post_body_bytes: default_max_direct_post_body_bytes(),
        }
    }

    /// Override direct-post body-size policy.
    #[must_use]
    pub const fn with_max_direct_post_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_direct_post_body_bytes = max_body_bytes;
        self
    }

    /// Route a framework-neutral HTTP request to the selected verifier endpoint.
    pub fn handle(
        &self,
        endpoint: VerifierHttpEndpoint<'_>,
        request: &RuntimeHttpRequest,
    ) -> RuntimeHttpResponse {
        match endpoint {
            VerifierHttpEndpoint::RequestObject { request_object_key } => {
                self.handle_request_object(request_object_key, request)
            }
            VerifierHttpEndpoint::DirectPost { session_key } => {
                self.handle_direct_post(session_key, request, DirectPostKind::Plain)
            }
            VerifierHttpEndpoint::DirectPostJwt { session_key } => {
                self.handle_direct_post(session_key, request, DirectPostKind::Jwt)
            }
        }
    }

    fn handle_request_object(
        &self,
        request_object_key: &str,
        request: &RuntimeHttpRequest,
    ) -> RuntimeHttpResponse {
        let hosted = match self.request_objects.load_request_object(request_object_key) {
            Ok(hosted) => hosted,
            Err(error) => return problem_http_response(runtime_error_to_problem(error)),
        };
        match serve_request_object_http(
            request,
            &hosted.request_object_jwt,
            hosted.wallet_nonce.as_deref(),
        ) {
            Ok(response) => response,
            Err(error) => problem_http_response(runtime_error_to_problem(error)),
        }
    }

    fn handle_direct_post(
        &self,
        session_key: &str,
        request: &RuntimeHttpRequest,
        kind: DirectPostKind,
    ) -> RuntimeHttpResponse {
        let session = match self.sessions.take_session(session_key) {
            Ok(session) => session,
            Err(error) => return problem_http_response(error.into()),
        };
        let now_unix = match self.clock.now_unix() {
            Ok(now_unix) => now_unix,
            Err(error) => return problem_http_response(runtime_error_to_problem(error)),
        };
        let context = DirectPostValidationContext::new(&session, now_unix)
            .with_max_body_bytes(self.max_direct_post_body_bytes);
        match kind {
            DirectPostKind::Plain => handle_direct_post_http(&self.service, request, context),
            DirectPostKind::Jwt => handle_direct_post_jwt_http(&self.service, request, context),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectPostKind {
    Plain,
    Jwt,
}

const fn default_max_direct_post_body_bytes() -> usize {
    128 * 1024
}
