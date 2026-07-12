// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::AuthorizationRequestObject;

use crate::VerifierError;

/// Verified Request Object and its parsed claims.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedRequestObject {
    /// Parsed Authorization Request Object.
    pub request: AuthorizationRequestObject,
}

/// Network-free Request Object verifier.
///
/// Implementations resolve keys from already-injected trust material or from
/// caller-provided adapters. Fetching `request_uri`, DID documents, federation
/// chains, or X.509 trust lists belongs outside this trait.
pub trait RequestObjectVerifier: Send + Sync {
    /// Verify a compact Request Object JWT and return parsed claims.
    fn verify_and_parse(
        &self,
        jwt: &str,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, VerifierError>;
}
