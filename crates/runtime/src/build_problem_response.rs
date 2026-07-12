// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{ProblemDetails, PROBLEM_JSON_MEDIA_TYPE};

use crate::RuntimeHttpResponse;

const INTERNAL_PROBLEM_JSON: &[u8] = br#"{"type":"https://really.me/problems/internal","title":"Internal server error","status":500,"kind":"Internal"}"#;

pub(crate) fn problem_proto_http_response(problem: &pb::ProblemDetails) -> RuntimeHttpResponse {
    let status = problem_status(problem.status);
    let body = match serde_json::to_vec(problem) {
        Ok(body) => body,
        Err(_error) => INTERNAL_PROBLEM_JSON.to_vec(),
    };
    RuntimeHttpResponse::with_body(status, PROBLEM_JSON_MEDIA_TYPE, body)
}

pub(crate) fn problem_http_response(problem: ProblemDetails) -> RuntimeHttpResponse {
    let status = problem.status.as_u16();
    let body = match serde_json::to_vec(&problem) {
        Ok(body) => body,
        Err(_error) => INTERNAL_PROBLEM_JSON.to_vec(),
    };
    RuntimeHttpResponse::with_body(status, PROBLEM_JSON_MEDIA_TYPE, body)
}

fn problem_status(status: u32) -> u16 {
    u16::try_from(status).map_or(500, core::convert::identity)
}
