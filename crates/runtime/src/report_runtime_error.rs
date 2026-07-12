// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Runtime service error with deterministic, non-PII reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP runtime error: {reason:?}")]
pub struct RuntimeError {
    reason: RuntimeErrorReason,
}

impl RuntimeError {
    /// Construct a runtime error from a stable reason.
    pub const fn new(reason: RuntimeErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for API and FFI mapping.
    pub const fn reason(self) -> RuntimeErrorReason {
        self.reason
    }
}

/// Stable runtime error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeErrorReason {
    /// The protobuf request omitted a required field.
    MissingField,
    /// A protobuf/domain mapping failed.
    InvalidProto,
    /// The request asks for signing but no signer is configured.
    MissingSigner,
    /// The request uses a valid feature this runtime instance does not support.
    UnsupportedFeature,
    /// Request Object signing failed.
    SigningFailed,
    /// No decryptor is configured for encrypted Authorization Responses.
    MissingResponseJwtDecryptor,
    /// Encrypted Authorization Response compact serialization is malformed.
    InvalidResponseJwt,
    /// Encrypted Authorization Response decryption failed.
    ResponseJwtDecryptionFailed,
    /// Runtime clock could not provide a trusted timestamp.
    ClockUnavailable,
    /// Hosted Request Object could not be loaded.
    RequestObjectNotFound,
    /// Authorization Response validation failed.
    ResponseValidationFailed,
    /// HTTP method is not allowed for this endpoint.
    InvalidHttpMethod,
    /// HTTP content type is missing or unsupported.
    InvalidContentType,
    /// HTTP Accept header does not allow the response media type.
    InvalidAcceptHeader,
    /// HTTP request body exceeded endpoint policy.
    BodyTooLarge,
    /// Form-urlencoded body is malformed.
    InvalidFormBody,
    /// Required form field is absent.
    MissingFormField,
    /// Form field appeared more than once where duplicates are unsafe.
    DuplicateFormField,
    /// Request URI POST wallet_nonce did not match the hosted request.
    WalletNonceMismatch,
    /// The native Connect server could not bind its listening socket.
    ConnectServerBindFailed,
    /// The native Connect server stopped because of a transport failure.
    ConnectServerServeFailed,
    /// The verifier host failed to store launch material atomically.
    LaunchStoreFailed,
    /// The verifier launch response could not be encoded.
    LaunchEncodingFailed,
}
