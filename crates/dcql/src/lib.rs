// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! DCQL query model, validation, and wallet-side evaluation.
//!
//! The crate intentionally has no OpenID4VP transport dependencies. It models
//! the OpenID4VP 1.0 final DCQL structures and evaluates them against an
//! injected inventory of wallet credentials.

mod error;
mod evaluate;
mod model;
mod path;
mod validate;
mod zeroize_json;

pub use error::{DcqlError, DcqlErrorReason};
pub use evaluate::{
    evaluate_query, CredentialCandidate, CredentialMatch, Evaluation, EvaluationCredential,
};
pub use model::{
    ClaimQuery, ClaimSet, ClaimValue, ClaimsPath, ClaimsPathComponent, CredentialFormat,
    CredentialQuery, CredentialSetQuery, DcqlQuery, QueryId, TrustedAuthorityQuery,
};
pub use path::{process_json_claims_path, ProcessedClaimValues};
pub use validate::validate_query;
