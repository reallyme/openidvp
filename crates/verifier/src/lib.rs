// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Verifier-side OpenID4VP request and response validation boundary.

mod binding;
mod compare_secret;
mod enforce_zk_policy;
mod error;
mod holder_binding;
mod jar;
mod request_object;
mod response;
mod session;
mod verify_holder_binding;

pub use binding::{validate_request_binding, RequestBinding};
pub use enforce_zk_policy::{enforce_zk_policy, ZkPolicyRequirements};
pub use error::{VerifierError, VerifierErrorReason};
pub use holder_binding::{
    holder_binding_claims_from_verified_payload, validate_holder_binding_claims,
    HolderBindingClaims,
};
pub use jar::{
    build_signed_request_object, validate_jar_claims, validate_jar_claims_for_signing, CompactJwt,
    JarPolicy, RequestObjectSigner, REQUEST_OBJECT_MEDIA_TYPE,
};
pub use request_object::{RequestObjectVerifier, VerifiedRequestObject};
pub use response::{
    validate_authorization_response, validate_authorization_response_with_options,
    validate_authorization_response_with_zk, ResponseValidationOptions,
};
pub use session::{SessionRecord, SessionStore};
pub use verify_holder_binding::HolderBindingVerifier;
