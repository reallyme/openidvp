// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_verifier::{SessionRecord, VerifierError};

/// Single-use verifier session storage for response endpoints.
///
/// Runtime HTTP hosts use this instead of a read-only session lookup so a
/// captured `direct_post` body cannot be replayed against the same verifier
/// session. Implementations should atomically remove or mark the session as
/// consumed before returning it.
pub trait VerifierSessionStore: Send + Sync {
    /// Take a verifier session by an adapter-defined lookup key.
    fn take_session(&self, key: &str) -> Result<SessionRecord, VerifierError>;
}
