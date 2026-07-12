// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Wallet-side OpenID4VP error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP wallet error: {reason:?}")]
pub struct WalletError {
    reason: WalletErrorReason,
}

impl WalletError {
    /// Build a wallet error from a stable reason.
    pub const fn new(reason: WalletErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> WalletErrorReason {
        self.reason
    }
}

/// Stable wallet error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletErrorReason {
    /// Incoming authorization request transport could not be parsed.
    InvalidAuthorizationRequestTransport,
    /// A security-sensitive authorization request parameter appeared twice.
    DuplicateAuthorizationRequestParameter,
    /// Both `request` and `request_uri` were supplied.
    ConflictingRequestObjectParameters,
    /// A wallet-generated `wallet_nonce` was required by a downstream adapter.
    MissingWalletNonce,
    /// `wallet_nonce` was supplied for a transport where it is not valid.
    UnexpectedWalletNonce,
    /// `request_uri_method` is not a supported final-spec value.
    UnsupportedRequestUriMethod,
    /// Transport-level `client_id` does not match the signed Request Object.
    TransportClientIdentifierMismatch,
    /// Response endpoint host does not match the signed client identifier.
    ResponseEndpointClientIdentifierMismatch,
    /// POST `request_uri` wallet_nonce does not match the signed Request Object.
    TransportWalletNonceMismatch,
    /// Request Object JWT exceeds policy.
    RequestObjectTooLarge,
    /// Request Object signature or claims failed verification.
    InvalidRequestObject,
    /// The Request Object expired.
    RequestObjectExpired,
    /// The Request Object was issued in the future.
    RequestObjectIssuedInFuture,
    /// Signed request did not bind a final-spec client_id prefix.
    InvalidClientIdentifierPrefix,
    /// Verifier attestation evidence was absent or failed request binding.
    InvalidVerifierAttestation,
    /// Referenced verifier metadata was absent, stale, or not bound to the request.
    InvalidMetadataReference,
    /// Digital Credentials API request origin is not listed in `expected_origins`.
    ExpectedOriginMismatch,
    /// The wallet does not support the requested feature.
    UnsupportedFeature,
    /// ZK derivation failed or the prover was unavailable.
    ZkDerivationFailed,
}
