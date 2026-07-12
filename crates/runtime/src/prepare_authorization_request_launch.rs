// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{AuthorizationRequestObject, RequestUriMethod};
use reallyme_openid4vp_verifier::{validate_jar_claims, JarPolicy, RequestBinding, SessionRecord};

use crate::implement_verifier_connect::request_binding_from_authorization_request;
use crate::{HostedRequestObject, RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

/// Request for launching an OpenID4VP authorization flow through a hosted
/// Request Object.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationRequestLaunchRequest {
    /// Wallet authorization endpoint, for example the OIDF mock wallet endpoint.
    pub authorization_endpoint: String,
    /// Final OpenID4VP Authorization Request Object to sign and host.
    pub authorization_request: AuthorizationRequestObject,
    /// Adapter-defined verifier session key used by the direct-post endpoint.
    pub session_key: String,
    /// Adapter-defined hosted Request Object key used by the request_uri endpoint.
    pub request_object_key: String,
    /// Absolute request_uri that resolves to the hosted Request Object endpoint.
    pub request_uri: String,
    /// Request URI retrieval method advertised to the wallet.
    pub request_uri_method: RequestUriMethod,
}

/// Stored launch material supplied atomically to the service host.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationRequestLaunchStoreRecord<'a> {
    /// Adapter-defined verifier session key.
    pub session_key: &'a str,
    /// Session record used later for response validation.
    pub session: SessionRecord,
    /// Adapter-defined hosted Request Object key.
    pub request_object_key: &'a str,
    /// Hosted compact Request Object JWT and request_uri POST nonce policy.
    pub request_object: HostedRequestObject,
}

/// Host storage boundary for verifier launch material.
///
/// The session and hosted Request Object should be committed together. A
/// response without a stored session fails validation, and a request_uri without
/// a stored object strands the wallet before consent.
pub trait AuthorizationRequestLaunchStore: Send + Sync {
    /// Store all material needed to complete one verifier authorization flow.
    fn store_authorization_request_launch(
        &self,
        record: AuthorizationRequestLaunchStoreRecord<'_>,
    ) -> Result<(), RuntimeError>;
}

/// Authorization endpoint parameter name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationRequestParameterName {
    /// `client_id`.
    ClientId,
    /// `request_uri`.
    RequestUri,
    /// `request_uri_method`.
    RequestUriMethod,
}

impl AuthorizationRequestParameterName {
    /// Return the OpenID4VP authorization endpoint parameter name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientId => "client_id",
            Self::RequestUri => "request_uri",
            Self::RequestUriMethod => "request_uri_method",
        }
    }
}

/// Authorization endpoint parameter returned to a service host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequestParameter {
    /// Strong parameter name.
    pub name: AuthorizationRequestParameterName,
    /// Parameter value.
    pub value: String,
}

/// Launch material ready for the host to send to the wallet authorization
/// endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequestLaunch {
    /// Wallet authorization endpoint.
    pub authorization_endpoint: String,
    /// Form/query parameters for the authorization endpoint.
    pub parameters: Vec<AuthorizationRequestParameter>,
}

impl VerifierRuntimeService {
    /// Sign, store, and return authorization endpoint parameters for a verifier
    /// request_uri flow.
    pub fn prepare_authorization_request_launch(
        &self,
        request: &AuthorizationRequestLaunchRequest,
        store: &dyn AuthorizationRequestLaunchStore,
        now_unix: u64,
    ) -> Result<AuthorizationRequestLaunch, RuntimeError> {
        validate_launch_request(request)?;
        let Some(signer) = self.signer() else {
            return Err(RuntimeError::new(RuntimeErrorReason::MissingSigner));
        };
        validate_jar_claims(
            &request.authorization_request,
            now_unix,
            JarPolicy::default(),
        )
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
        let jwt = signer
            .sign_request_object(&request.authorization_request)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
        let binding = request_binding_from_authorization_request(&request.authorization_request)?;
        let session = session_from_request(&request.authorization_request, binding);
        let request_object = HostedRequestObject::new(
            jwt.as_str().to_owned(),
            request.authorization_request.wallet_nonce.clone(),
        )?;
        store.store_authorization_request_launch(AuthorizationRequestLaunchStoreRecord {
            session_key: &request.session_key,
            session,
            request_object_key: &request.request_object_key,
            request_object,
        })?;
        Ok(AuthorizationRequestLaunch {
            authorization_endpoint: request.authorization_endpoint.clone(),
            parameters: authorization_endpoint_parameters(request)?,
        })
    }
}

fn validate_launch_request(
    request: &AuthorizationRequestLaunchRequest,
) -> Result<(), RuntimeError> {
    if request.authorization_endpoint.is_empty()
        || request.session_key.is_empty()
        || request.request_object_key.is_empty()
        || request.request_uri.is_empty()
    {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }
    Ok(())
}

fn session_from_request(
    request: &AuthorizationRequestObject,
    binding: RequestBinding,
) -> SessionRecord {
    SessionRecord {
        binding,
        state: request.state.clone(),
        dcql_query: request.dcql_query.clone(),
    }
}

fn authorization_endpoint_parameters(
    request: &AuthorizationRequestLaunchRequest,
) -> Result<Vec<AuthorizationRequestParameter>, RuntimeError> {
    let Some(client_id) = request.authorization_request.client_id.as_ref() else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    };
    let mut parameters = vec![
        AuthorizationRequestParameter {
            name: AuthorizationRequestParameterName::ClientId,
            value: client_id.to_wire_value(),
        },
        AuthorizationRequestParameter {
            name: AuthorizationRequestParameterName::RequestUri,
            value: request.request_uri.clone(),
        },
    ];
    if request.request_uri_method == RequestUriMethod::Post {
        parameters.push(AuthorizationRequestParameter {
            name: AuthorizationRequestParameterName::RequestUriMethod,
            value: "post".to_owned(),
        });
    }
    Ok(parameters)
}
