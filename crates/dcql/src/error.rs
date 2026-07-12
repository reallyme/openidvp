// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Error returned by DCQL parsing, validation, and evaluation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid DCQL query: {reason:?}")]
pub struct DcqlError {
    reason: DcqlErrorReason,
}

impl DcqlError {
    /// Build an error from a stable, non-PII reason.
    pub const fn new(reason: DcqlErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic FFI and API mapping.
    pub const fn reason(self) -> DcqlErrorReason {
        self.reason
    }
}

/// Stable DCQL error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcqlErrorReason {
    /// The JSON input could not be decoded as a DCQL query.
    InvalidJson,
    /// A required array or string was empty.
    EmptyValue,
    /// A query or claim identifier contains an invalid character.
    InvalidIdentifier,
    /// The same identifier appears more than once in one scope.
    DuplicateIdentifier,
    /// A `claim_sets` entry was present without a `claims` array.
    ClaimSetsWithoutClaims,
    /// A `claim_sets` or `credential_sets` reference targets an unknown id.
    UnknownReference,
    /// A claims path is syntactically invalid for the credential format.
    InvalidClaimsPath,
    /// A claims path could not be processed against the supplied credential.
    ClaimsPathMismatch,
    /// A claim value constraint used a type outside the DCQL value domain.
    InvalidClaimValue,
    /// The query exceeds this crate's bounded evaluation policy.
    QueryTooLarge,
    /// Format-specific credential metadata is absent or malformed.
    InvalidCredentialMetadata,
    /// The wallet inventory cannot satisfy a required credential query or set.
    UnsatisfiedRequiredCredential,
}
