// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::PresentationValue;

use crate::{HolderBindingClaims, VerifierError};

/// Host-injected verifier for presentation-format holder binding.
///
/// Credential envelope parsing and signature verification stay in
/// `reallyme/identity` format crates. This verifier boundary only requires the
/// decoded nonce/audience/expiration claims needed to bind a presentation to
/// the active OpenID4VP session.
pub trait HolderBindingVerifier: Send + Sync {
    /// Verify the presentation's holder-binding proof and return decoded claims.
    fn verify_holder_binding(
        &self,
        presentation: &PresentationValue,
    ) -> Result<HolderBindingClaims, VerifierError>;
}
