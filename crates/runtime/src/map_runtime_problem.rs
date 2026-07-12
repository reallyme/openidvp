// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::problem_details_to_proto;
use reallyme_openid4vp_types::{ProblemDetails, ProblemKind};

use crate::{RuntimeError, RuntimeErrorReason};

/// Convert a runtime error into RFC 9457 problem details.
pub fn runtime_error_to_problem(error: RuntimeError) -> ProblemDetails {
    let kind = match error.reason() {
        RuntimeErrorReason::MissingField | RuntimeErrorReason::InvalidProto => {
            ProblemKind::InvalidRequest
        }
        RuntimeErrorReason::MissingSigner
        | RuntimeErrorReason::UnsupportedFeature
        | RuntimeErrorReason::MissingResponseJwtDecryptor => ProblemKind::UnsupportedFeature,
        RuntimeErrorReason::SigningFailed => ProblemKind::InvalidRequestObject,
        RuntimeErrorReason::InvalidResponseJwt
        | RuntimeErrorReason::ResponseJwtDecryptionFailed => ProblemKind::InvalidRequest,
        RuntimeErrorReason::ClockUnavailable => ProblemKind::Internal,
        RuntimeErrorReason::ConnectServerBindFailed
        | RuntimeErrorReason::ConnectServerServeFailed
        | RuntimeErrorReason::LaunchStoreFailed
        | RuntimeErrorReason::LaunchEncodingFailed => ProblemKind::Internal,
        RuntimeErrorReason::RequestObjectNotFound => ProblemKind::SessionNotFound,
        RuntimeErrorReason::ResponseValidationFailed
        | RuntimeErrorReason::InvalidHttpMethod
        | RuntimeErrorReason::InvalidContentType
        | RuntimeErrorReason::InvalidAcceptHeader
        | RuntimeErrorReason::BodyTooLarge
        | RuntimeErrorReason::InvalidFormBody
        | RuntimeErrorReason::MissingFormField
        | RuntimeErrorReason::DuplicateFormField
        | RuntimeErrorReason::WalletNonceMismatch => ProblemKind::InvalidRequest,
    };
    ProblemDetails::from_kind(kind)
}

pub(crate) fn runtime_error_to_problem_proto(error: RuntimeError) -> pb::ProblemDetails {
    problem_details_to_proto(&runtime_error_to_problem(error))
}
