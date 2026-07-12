// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the SDK-facing root facade.

#[test]
#[cfg(feature = "proto")]
fn verify_root_facade_exposes_generated_proto_and_codec() {
    let problem = reallyme_openid4vp::types::ProblemDetails::from_kind(
        reallyme_openid4vp::types::ProblemKind::InvalidRequestObject,
    );
    let proto = reallyme_openid4vp::proto_codec::problem_details_to_proto(&problem);
    let mapped = reallyme_openid4vp::proto_codec::proto_to_problem_details(&proto);

    assert!(
        mapped.is_ok(),
        "facade proto codec mapping remains available"
    );
}

#[test]
#[cfg(feature = "connect")]
fn verify_root_facade_exposes_connect_services() {
    assert_eq!(
        reallyme_openid4vp::proto::generated::connect::openid4vp::v1::OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME,
        "openid4vp.v1.OpenId4VpVerifierService"
    );
}

#[test]
fn verify_root_facade_exposes_sdk_policy() {
    let policy = reallyme_openid4vp::policy::OpenId4VpProtocolPolicy::production();
    let wallet_policy = policy.wallet_transport_policy();

    assert!(wallet_policy.require_signed_request_object);
}

#[test]
#[cfg(feature = "runtime")]
fn verify_root_facade_exposes_runtime_wrapper() {
    let service = std::sync::Arc::new(reallyme_openid4vp::runtime::VerifierRuntimeService::new(
        reallyme_openid4vp::runtime::VerifierRuntimeConfig::new(),
    ));
    let _router =
        reallyme_openid4vp::runtime::build_verifier_connect_router(std::sync::Arc::clone(&service));
    #[cfg(feature = "native")]
    let _server = reallyme_openid4vp::runtime::build_verifier_connect_server(service);

    let hosted = reallyme_openid4vp::runtime::HostedRequestObject::new(
        "header.payload.signature".to_owned(),
        Some("nonce".to_owned()),
    );

    assert!(hosted.is_ok(), "facade exposes hosted request objects");
    assert!(matches!(
        reallyme_openid4vp::runtime::VerifierHttpEndpoint::DirectPost {
            session_key: "session"
        },
        reallyme_openid4vp::runtime::VerifierHttpEndpoint::DirectPost { .. }
    ));
}
