// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::AuthorizationResponse;

use crate::RuntimeError;

/// Adapter boundary for encrypted OpenID4VP Authorization Responses.
///
/// Implementations are expected to decrypt an unsigned encrypted JWT/JWE,
/// enforce JOSE header policy (`alg`, `enc`, optional `kid`), and decode a
/// payload whose top-level members are the Authorization Response parameters.
/// Keeping this trait in the runtime layer lets identity-sdk inject the
/// concrete `reallyme-crypto` backend without teaching protocol crates about
/// platform key storage.
pub trait AuthorizationResponseJwtDecryptor: Send + Sync {
    /// Decrypt a compact JWE Authorization Response.
    fn decrypt_authorization_response_jwt(
        &self,
        jwt: &str,
    ) -> Result<AuthorizationResponse, RuntimeError>;
}
