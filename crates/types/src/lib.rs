// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! OpenID4VP 1.0 final protocol types.

mod classify_request_object_jwt;
mod client_id;
mod define_media_types;
mod define_metadata;
mod error;
mod problem_details;
mod request;
mod response;
mod transaction_data;
mod zeroize_json;

pub use classify_request_object_jwt::{classify_request_object_jwt, RequestObjectJwtKind};
pub use client_id::{ClientIdentifier, ClientIdentifierPrefix};
pub use define_media_types::{
    JSON_MEDIA_TYPE, REQUEST_OBJECT_MEDIA_TYPE, VERIFIER_ATTESTATION_MEDIA_TYPE,
};
pub use define_metadata::{
    negotiate_response_mode, AlgorithmIdentifier, ClientMetadata, VerifierMetadata, WalletMetadata,
};
pub use error::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};
pub use problem_details::{
    HttpStatusCode, ProblemDetails, ProblemDetailsExt, ProblemInstance, ProblemKind, ProblemTitle,
    ProblemType, PROBLEM_JSON_MEDIA_TYPE,
};
pub use request::{AuthorizationRequestObject, RequestUriMethod, ResponseMode, ResponseType};
pub use response::{AuthorizationResponse, PresentationValue, VpToken};
pub use transaction_data::{
    canonical_transaction_data_bytes, canonicalize_json, decode_transaction_data_string,
    encoded_transaction_data_string, TransactionData, TransactionDataHash,
    TransactionDataHashAlgorithm,
};
