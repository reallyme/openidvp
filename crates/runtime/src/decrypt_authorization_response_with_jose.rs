// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_jose::jwe::{
    decrypt_compact_jwe_json, CompactJwePolicy, JweContentEncryptionKeyResolver,
};
use reallyme_openid4vp_types::AuthorizationResponse;

use crate::{AuthorizationResponseJwtDecryptor, RuntimeError, RuntimeErrorReason};

/// `reallyme-jose` backed decryptor for OpenID4VP encrypted Authorization Responses.
///
/// The runtime still depends on the [`AuthorizationResponseJwtDecryptor`] trait
/// at service boundaries so SDKs and services can inject platform key storage.
/// This adapter is the production JOSE implementation for hosts that already
/// resolve a content-encryption key through `reallyme-jose`.
pub struct JoseAuthorizationResponseJwtDecryptor<R> {
    key_resolver: R,
    policy: CompactJwePolicy<'static>,
}

impl<R> JoseAuthorizationResponseJwtDecryptor<R> {
    /// Build a decryptor using the OpenID4VP `direct_post.jwt` JWE policy.
    pub fn new(key_resolver: R) -> Self {
        Self {
            key_resolver,
            policy: CompactJwePolicy::openid4vp_direct_post_jwt(),
        }
    }

    /// Build a decryptor with an explicit JOSE policy.
    ///
    /// This exists for HAIP, conformance, and service-host profiles that need
    /// stricter header constraints such as mandatory `kid` or expected `cty`.
    pub fn with_policy(key_resolver: R, policy: CompactJwePolicy<'static>) -> Self {
        Self {
            key_resolver,
            policy,
        }
    }
}

impl<R> AuthorizationResponseJwtDecryptor for JoseAuthorizationResponseJwtDecryptor<R>
where
    R: JweContentEncryptionKeyResolver + Send + Sync,
{
    fn decrypt_authorization_response_jwt(
        &self,
        jwt: &str,
    ) -> Result<AuthorizationResponse, RuntimeError> {
        decrypt_compact_jwe_json(jwt, &self.policy, &self.key_resolver)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::ResponseJwtDecryptionFailed))
    }
}
