// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_dcql::DcqlQuery;

use crate::{RequestBinding, VerifierError};

/// Verifier session record retained between request creation and response validation.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRecord {
    /// Request binding material.
    pub binding: RequestBinding,
    /// OIDC state value, when used.
    pub state: Option<String>,
    /// DCQL query used to create the authorization request.
    pub dcql_query: DcqlQuery,
}

/// Storage boundary for verifier sessions.
pub trait SessionStore: Send + Sync {
    /// Load a verifier session by an adapter-defined lookup key.
    fn load(&self, key: &str) -> Result<SessionRecord, VerifierError>;
}
