// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Digital Credentials API binding error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP Digital Credentials API error: {reason:?}")]
pub struct DcApiError {
    reason: DcApiErrorReason,
}

impl DcApiError {
    /// Build an error from a stable reason.
    pub const fn new(reason: DcApiErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> DcApiErrorReason {
        self.reason
    }
}

/// Stable Digital Credentials API binding error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcApiErrorReason {
    /// A required input was empty.
    EmptyValue,
    /// The DC API request set was empty.
    EmptyRequestSet,
    /// The protocol identifier is unsupported or malformed.
    InvalidProtocol,
    /// Handover CBOR encoding failed in the delegated mdoc adapter.
    HandoverEncodingFailed,
}
