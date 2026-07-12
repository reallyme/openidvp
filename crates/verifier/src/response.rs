// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;
use std::collections::BTreeSet;

use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_formats::{
    build_zk_session_binding, parse_zk_presentation_value, verify_zk_presentation,
};
use reallyme_openid4vp_types::{AuthorizationResponse, TransactionDataHashAlgorithm};
use reallyme_zk_api::{ZkCircuitId, ZkVerifier};

use crate::compare_secret::constant_time_str_eq;
use crate::{
    enforce_zk_policy, validate_holder_binding_claims, validate_request_binding,
    HolderBindingVerifier, SessionRecord, VerifierError, VerifierErrorReason, ZkPolicyRequirements,
};

/// Response-validation dependencies and policy.
#[derive(Clone, Copy, Default)]
pub struct ResponseValidationOptions<'a> {
    /// Verifier for presentation holder-binding proofs.
    pub holder_binding_verifier: Option<&'a dyn HolderBindingVerifier>,
    /// Optional verifier for ZK presentations.
    pub zk_verifier: Option<&'a dyn ZkVerifier>,
    /// Policy for accepted ZK circuit semantics.
    pub zk_policy: ZkPolicyRequirements,
}

/// Validate a final OpenID4VP Authorization Response against verifier session state.
///
/// This ports the useful meproto response guard while preserving final-spec
/// response shape: `vp_token` is a DCQL-query-id-keyed object rather than the
/// old vector of opaque VP bytes.
pub fn validate_authorization_response(
    session: &SessionRecord,
    response: &AuthorizationResponse,
    now_unix: u64,
) -> Result<(), VerifierError> {
    validate_authorization_response_with_options(
        session,
        response,
        now_unix,
        ResponseValidationOptions::default(),
    )
}

/// Validate an Authorization Response and verify any ZK presentations with an injected verifier.
pub fn validate_authorization_response_with_zk(
    session: &SessionRecord,
    response: &AuthorizationResponse,
    now_unix: u64,
    zk_verifier: Option<&dyn ZkVerifier>,
    zk_policy: ZkPolicyRequirements,
) -> Result<(), VerifierError> {
    validate_authorization_response_with_options(
        session,
        response,
        now_unix,
        ResponseValidationOptions {
            holder_binding_verifier: None,
            zk_verifier,
            zk_policy,
        },
    )
}

/// Validate an Authorization Response with explicit format verifiers.
pub fn validate_authorization_response_with_options(
    session: &SessionRecord,
    response: &AuthorizationResponse,
    now_unix: u64,
    options: ResponseValidationOptions<'_>,
) -> Result<(), VerifierError> {
    validate_request_binding(&session.binding, now_unix)?;

    if !optional_secret_eq(response.state.as_deref(), session.state.as_deref()) {
        return Err(VerifierError::new(VerifierErrorReason::SessionMismatch));
    }

    if response.vp_token.is_empty() {
        return Err(VerifierError::new(VerifierErrorReason::EmptyVpToken));
    }

    validate_vp_token_query_coverage(session, response)?;
    validate_transaction_data_response_binding(session, response)?;

    if response
        .vp_token
        .values()
        .any(|presentations| presentations.is_empty())
    {
        return Err(VerifierError::new(
            VerifierErrorReason::EmptyPresentationList,
        ));
    }

    validate_presentations(session, response, now_unix, options)?;

    Ok(())
}

fn validate_transaction_data_response_binding(
    session: &SessionRecord,
    response: &AuthorizationResponse,
) -> Result<(), VerifierError> {
    let Some(expected_hash) = session.binding.transaction_data_hash else {
        return Ok(());
    };
    if response.transaction_data_hashes_alg != Some(TransactionDataHashAlgorithm::Sha256) {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    let Some(hashes) = response.transaction_data_hashes.as_ref() else {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    };
    for hash in hashes {
        let Ok(decoded) = base64url_to_bytes(hash) else {
            return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
        };
        if decoded.as_slice() == expected_hash {
            return Ok(());
        }
    }
    Err(VerifierError::new(VerifierErrorReason::InvalidBinding))
}

fn validate_vp_token_query_coverage(
    session: &SessionRecord,
    response: &AuthorizationResponse,
) -> Result<(), VerifierError> {
    let expected_ids = session
        .dcql_query
        .credentials
        .iter()
        .map(|query| query.id.clone())
        .collect::<BTreeSet<QueryId>>();
    let actual_ids = response
        .vp_token
        .keys()
        .cloned()
        .collect::<BTreeSet<QueryId>>();
    if expected_ids != actual_ids {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    for query in &session.dcql_query.credentials {
        if !query.multiple
            && response
                .vp_token
                .get(&query.id)
                .is_some_and(|presentations| presentations.len() > 1)
        {
            return Err(VerifierError::new(
                VerifierErrorReason::VpTokenCardinalityMismatch,
            ));
        }
    }
    Ok(())
}

fn optional_secret_eq(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time_str_eq(left, right),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn validate_presentations(
    session: &SessionRecord,
    response: &AuthorizationResponse,
    now_unix: u64,
    options: ResponseValidationOptions<'_>,
) -> Result<(), VerifierError> {
    let expected_binding = build_zk_session_binding(
        &session.binding.nonce,
        &session.binding.client_id.to_wire_value(),
        session.binding.transaction_data_hash,
    );
    for presentations in response.vp_token.values() {
        for presentation in presentations {
            let Some(zk_presentation) = parse_zk_presentation_value(presentation)
                .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidZkPresentation))?
            else {
                validate_holder_bound_presentation(session, presentation, now_unix, options)?;
                continue;
            };
            let Some(verifier) = options.zk_verifier else {
                return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
            };
            let circuit_id = ZkCircuitId::from_str(&zk_presentation.circuit_id)
                .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidZkPresentation))?;
            enforce_zk_policy(
                circuit_id,
                zk_policy_for_session(session, options.zk_policy),
            )?;
            verify_zk_presentation(verifier, &zk_presentation, expected_binding)
                .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidZkPresentation))?;
        }
    }
    Ok(())
}

fn zk_policy_for_session(
    session: &SessionRecord,
    mut policy: ZkPolicyRequirements,
) -> ZkPolicyRequirements {
    if session.binding.transaction_data_hash.is_some() {
        policy.require_transaction_data_binding = true;
    }
    policy
}

fn validate_holder_bound_presentation(
    session: &SessionRecord,
    presentation: &reallyme_openid4vp_types::PresentationValue,
    now_unix: u64,
    options: ResponseValidationOptions<'_>,
) -> Result<(), VerifierError> {
    let Some(verifier) = options.holder_binding_verifier else {
        return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
    };
    let claims = verifier.verify_holder_binding(presentation)?;
    validate_holder_binding_claims(&session.binding, &claims, now_unix)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeMap;

    use reallyme_codec::base64url::bytes_to_base64url;
    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_formats::{
        build_zk_session_binding, ZkPresentation, ZkPresentationBinding, ZK_PRESENTATION_TYPE,
    };
    use reallyme_openid4vp_types::{
        AuthorizationResponse, ClientIdentifier, PresentationValue, TransactionDataHashAlgorithm,
    };
    use reallyme_zk_api::{
        ZkCircuitId, ZkError, ZkPublicInputs, ZkVerification, ZkVerifier, ZkVerifyRequest,
    };

    use crate::response::{
        validate_authorization_response, validate_authorization_response_with_options,
        validate_authorization_response_with_zk, ResponseValidationOptions,
    };
    use crate::{
        HolderBindingClaims, HolderBindingVerifier, RequestBinding, SessionRecord, VerifierError,
        VerifierErrorReason, ZkPolicyRequirements,
    };

    fn session() -> SessionRecord {
        SessionRecord {
            binding: RequestBinding {
                client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                    .expect("test client id is valid"),
                nonce: "nonce".to_owned(),
                response_uri: Some("https://verifier.example/response".to_owned()),
                redirect_uri: None,
                expiry_unix: 100,
                transaction_data_hash: None,
            },
            state: Some("state".to_owned()),
            dcql_query: dcql_query(false),
        }
    }

    fn dcql_query(multiple: bool) -> DcqlQuery {
        DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id is valid"),
                format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                    .expect("test format is valid"),
                multiple,
                meta: Default::default(),
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        }
    }

    struct FixtureHolderBindingVerifier;

    impl HolderBindingVerifier for FixtureHolderBindingVerifier {
        fn verify_holder_binding(
            &self,
            _presentation: &PresentationValue,
        ) -> Result<HolderBindingClaims, VerifierError> {
            Ok(HolderBindingClaims {
                audience: vec!["x509_san_dns:verifier.example".to_owned()],
                nonce: "nonce".to_owned(),
                expiration_unix: 100,
                issued_at_unix: 10,
                sd_hash: None,
            })
        }
    }

    #[test]
    fn accepts_response_matching_session() {
        let response = AuthorizationResponse::single(
            QueryId::parse("pid").expect("test query id is valid"),
            vec![PresentationValue::Compact("presentation".to_owned())],
            Some("state".to_owned()),
        )
        .expect("test response is valid");

        validate_authorization_response_with_options(
            &session(),
            &response,
            10,
            ResponseValidationOptions {
                holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
                ..ResponseValidationOptions::default()
            },
        )
        .expect("response matches session");
    }

    #[test]
    fn rejects_non_zk_presentation_without_holder_binding_verifier() {
        let response = AuthorizationResponse::single(
            QueryId::parse("pid").expect("test query id is valid"),
            vec![PresentationValue::Compact("presentation".to_owned())],
            Some("state".to_owned()),
        )
        .expect("test response is valid");

        let err = validate_authorization_response(&session(), &response, 10)
            .expect_err("non-zk presentation requires holder-binding verifier");

        assert_eq!(err.reason(), VerifierErrorReason::UnsupportedFormat);
    }

    #[test]
    fn rejects_state_mismatch() {
        let response = AuthorizationResponse::single(
            QueryId::parse("pid").expect("test query id is valid"),
            vec![PresentationValue::Compact("presentation".to_owned())],
            Some("other".to_owned()),
        )
        .expect("test response is valid");

        let err = validate_authorization_response(&session(), &response, 10)
            .expect_err("state mismatch is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::SessionMismatch);
    }

    #[test]
    fn rejects_empty_vp_token_object() {
        let response = AuthorizationResponse {
            vp_token: BTreeMap::new(),
            state: Some("state".to_owned()),
            transaction_data_hashes: None,
            transaction_data_hashes_alg: None,
        };

        let err = validate_authorization_response(&session(), &response, 10)
            .expect_err("empty vp_token object is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::EmptyVpToken);
    }

    #[test]
    fn rejects_empty_presentation_list_for_query() {
        let mut vp_token = BTreeMap::new();
        vp_token.insert(
            QueryId::parse("pid").expect("test query id is valid"),
            Vec::new(),
        );
        let response = AuthorizationResponse {
            vp_token,
            state: Some("state".to_owned()),
            transaction_data_hashes: None,
            transaction_data_hashes_alg: None,
        };

        let err = validate_authorization_response(&session(), &response, 10)
            .expect_err("empty per-query presentation list is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::EmptyPresentationList);
    }

    #[test]
    fn rejects_unknown_vp_token_query_id() {
        let response = AuthorizationResponse::single(
            QueryId::parse("other").expect("test query id is valid"),
            vec![PresentationValue::Compact("presentation".to_owned())],
            Some("state".to_owned()),
        )
        .expect("test response is valid");

        let err = validate_authorization_response_with_options(
            &session(),
            &response,
            10,
            ResponseValidationOptions {
                holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
                ..ResponseValidationOptions::default()
            },
        )
        .expect_err("response query ids must match session DCQL");

        assert_eq!(err.reason(), VerifierErrorReason::VpTokenQueryMismatch);
    }

    #[test]
    fn rejects_multiple_presentations_for_single_query() {
        let response = AuthorizationResponse::single(
            QueryId::parse("pid").expect("test query id is valid"),
            vec![
                PresentationValue::Compact("presentation-one".to_owned()),
                PresentationValue::Compact("presentation-two".to_owned()),
            ],
            Some("state".to_owned()),
        )
        .expect("test response is valid");

        let err = validate_authorization_response_with_options(
            &session(),
            &response,
            10,
            ResponseValidationOptions {
                holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
                ..ResponseValidationOptions::default()
            },
        )
        .expect_err("multiple:false query accepts one presentation");

        assert_eq!(
            err.reason(),
            VerifierErrorReason::VpTokenCardinalityMismatch
        );
    }

    #[test]
    fn rejects_expired_request_binding_before_response_shape_checks() {
        let mut session = session();
        session.binding.expiry_unix = 9;
        let response = AuthorizationResponse::single(
            QueryId::parse("pid").expect("test query id is valid"),
            vec![PresentationValue::Compact("presentation".to_owned())],
            Some("state".to_owned()),
        )
        .expect("test response is valid");

        let err = validate_authorization_response(&session, &response, 10)
            .expect_err("expired session binding is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::BindingExpired);
    }

    struct FixtureZkVerifier;

    impl ZkVerifier for FixtureZkVerifier {
        fn verify(&self, request: ZkVerifyRequest<'_>) -> Result<ZkVerification, ZkError> {
            Ok(ZkVerification {
                circuit_id: request.proof.circuit_id(),
                circuit_ref: request.proof.circuit_ref(),
            })
        }
    }

    fn zk_response() -> AuthorizationResponse {
        zk_response_for_binding(build_zk_session_binding(
            "nonce",
            "x509_san_dns:verifier.example",
            None,
        ))
    }

    fn zk_response_for_binding(
        binding: reallyme_zk_api::ZkSessionBinding,
    ) -> AuthorizationResponse {
        let public_inputs =
            public_inputs_for_binding(binding).expect("test public inputs are valid");
        let presentation = ZkPresentation {
            type_: ZK_PRESENTATION_TYPE.to_owned(),
            circuit_id: ZkCircuitId::VcBaseV1.as_str().to_owned(),
            circuit_ref: None,
            proof: vec![1, 2, 3],
            public_inputs,
            derived_claims: Vec::new(),
            binding: ZkPresentationBinding::from(binding),
        };
        AuthorizationResponse::single(
            QueryId::parse("pid").expect("test query id is valid"),
            vec![PresentationValue::Json(
                serde_json::to_value(presentation).expect("test presentation serializes"),
            )],
            Some("state".to_owned()),
        )
        .expect("test response is valid")
    }

    fn transaction_bound_session() -> SessionRecord {
        let mut session = session();
        session.binding.transaction_data_hash = Some([3; 32]);
        session
    }

    fn transaction_bound_zk_response() -> AuthorizationResponse {
        zk_response_for_binding(build_zk_session_binding(
            "nonce",
            "x509_san_dns:verifier.example",
            Some([3; 32]),
        ))
        .with_transaction_data_hashes(
            vec![bytes_to_base64url(&[3; 32])],
            TransactionDataHashAlgorithm::Sha256,
        )
        .expect("test transaction data hashes are valid")
    }

    #[test]
    fn rejects_transaction_bound_response_without_response_hashes() {
        let response = zk_response_for_binding(build_zk_session_binding(
            "nonce",
            "x509_san_dns:verifier.example",
            Some([3; 32]),
        ));

        let err = validate_authorization_response_with_zk(
            &transaction_bound_session(),
            &response,
            10,
            Some(&FixtureZkVerifier),
            ZkPolicyRequirements::default(),
        )
        .expect_err("transaction-bound sessions require response transaction_data_hashes");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidBinding);
    }

    fn public_inputs_for_binding(
        binding: reallyme_zk_api::ZkSessionBinding,
    ) -> Result<Vec<u8>, ZkError> {
        let mut bytes = binding.public_input_prefix_bytes();
        bytes.push(7);
        Ok(ZkPublicInputs::try_from_bytes(bytes)?.into_bytes())
    }

    #[test]
    fn rejects_zk_presentation_without_injected_verifier() {
        let err = validate_authorization_response(&session(), &zk_response(), 10)
            .expect_err("zk presentation requires an injected verifier");

        assert_eq!(err.reason(), VerifierErrorReason::UnsupportedFormat);
    }

    #[test]
    fn accepts_zk_presentation_with_injected_verifier() {
        validate_authorization_response_with_zk(
            &session(),
            &zk_response(),
            10,
            Some(&FixtureZkVerifier),
            ZkPolicyRequirements::default(),
        )
        .expect("zk presentation validates with injected verifier");
    }

    #[test]
    fn accepts_zk_presentation_with_transaction_data_binding() {
        validate_authorization_response_with_zk(
            &transaction_bound_session(),
            &transaction_bound_zk_response(),
            10,
            Some(&FixtureZkVerifier),
            ZkPolicyRequirements::default(),
        )
        .expect("transaction-bound zk presentation validates with injected verifier");
    }

    #[test]
    fn rejects_zk_presentation_when_policy_disallows_zk() {
        let err = validate_authorization_response_with_zk(
            &session(),
            &zk_response(),
            10,
            Some(&FixtureZkVerifier),
            ZkPolicyRequirements {
                allow_zk_presentations: false,
                ..ZkPolicyRequirements::default()
            },
        )
        .expect_err("zk policy can disable zk presentations");

        assert_eq!(err.reason(), VerifierErrorReason::UnsupportedFormat);
    }
}
