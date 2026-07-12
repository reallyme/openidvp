// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_formats::{prove_zk_presentation, ZkPresentationProveRequest};
use reallyme_openid4vp_types::PresentationValue;
use reallyme_zk_api::ZkProver;

use crate::{WalletError, WalletErrorReason};

/// Execute an identity-policy ZK derivation plan with an injected prover.
///
/// The policy engine decides whether derivation is acceptable. This wallet
/// boundary only turns that decision into a format-layer `vp_token` value.
pub fn derive_zk_presentation(
    prover: &dyn ZkProver,
    request: ZkPresentationProveRequest<'_>,
) -> Result<PresentationValue, WalletError> {
    prove_zk_presentation(prover, request)
        .map_err(|_| WalletError::new(WalletErrorReason::ZkDerivationFailed))
}
