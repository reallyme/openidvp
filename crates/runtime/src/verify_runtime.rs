// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1::__buffa::oneof::decode_dc_api_authorization_response_request::Response as DcApiResponseOneof;
use reallyme_openid4vp_proto_codec::{
    authorization_request_to_proto, authorization_response_to_proto,
    dc_api_authorization_response_to_proto, encrypted_dc_api_authorization_response_to_proto,
    session_record_to_proto,
};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, AuthorizationResponse, ClientIdentifier, PresentationValue,
    RequestUriMethod, ResponseMode, ResponseType, JSON_MEDIA_TYPE, PROBLEM_JSON_MEDIA_TYPE,
    REQUEST_OBJECT_MEDIA_TYPE,
};
use reallyme_openid4vp_verifier::{
    CompactJwt, HolderBindingClaims, HolderBindingVerifier, RequestBinding, RequestObjectSigner,
    SessionRecord, VerifierError, VerifierErrorReason,
};
use serde_json::{json, Map as JsonMap};

use crate::{
    authorization_request_launch_response, handle_authorization_request_launch_http,
    handle_direct_post_http, handle_direct_post_jwt_http, serve_request_object_http,
    AuthorizationRequestLaunchHttpContext, AuthorizationRequestLaunchHttpRequest,
    AuthorizationRequestLaunchPlanner, AuthorizationRequestLaunchRequest,
    AuthorizationRequestLaunchStore, AuthorizationRequestLaunchStoreRecord,
    AuthorizationRequestParameterName, AuthorizationResponseJwtDecryptor,
    DirectPostValidationContext, HostedRequestObject, RequestObjectStore, RuntimeClock,
    RuntimeError, RuntimeErrorReason, RuntimeHttpMethod, RuntimeHttpRequest, VerifierHttpEndpoint,
    VerifierHttpRuntime, VerifierRuntimeConfig, VerifierRuntimeService, VerifierSessionStore,
};

#[cfg(feature = "native")]
use crate::build_verifier_connect_server;
#[cfg(feature = "jose")]
use crate::JoseAuthorizationResponseJwtDecryptor;

#[cfg(feature = "jose")]
static TEST_JWE_KEY: [u8; 16] = [7u8; 16];
#[cfg(all(feature = "jose", feature = "native"))]
static TEST_P256_RECIPIENT_SECRET: [u8; 32] = [
    0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf, 0xee,
    0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91, 0xc3, 0x44,
];
#[cfg(all(feature = "jose", feature = "native"))]
static TEST_P256_EPHEMERAL_SECRET: [u8; 32] = [
    0x6a, 0x10, 0x45, 0xf2, 0x33, 0x9e, 0x80, 0x12, 0xab, 0x74, 0xc6, 0x28, 0xde, 0x91, 0x07, 0x5b,
    0x49, 0xef, 0x32, 0x18, 0x84, 0x2d, 0xbc, 0x60, 0x13, 0xa5, 0x77, 0xc9, 0x0e, 0x4b, 0x26, 0xd1,
];

struct FixtureSigner;
struct FixtureHolderBindingVerifier;
struct FixtureResponseJwtDecryptor;
struct FixtureSessionStore {
    session: Mutex<Option<SessionRecord>>,
}
struct FixtureRequestObjectStore;
#[derive(Default)]
struct FixtureLaunchStore {
    records: Mutex<Vec<StoredLaunchRecord>>,
}
struct FixtureLaunchPlanner;
struct FailingLaunchStore;
struct FixtureClock;
#[cfg(all(feature = "jose", feature = "native"))]
struct FixtureEcdhEsP256Resolver;

#[derive(Debug, Clone, PartialEq)]
struct StoredLaunchRecord {
    session_key: String,
    session: SessionRecord,
    request_object_key: String,
    request_object: HostedRequestObject,
}

impl RequestObjectSigner for FixtureSigner {
    fn sign_request_object(
        &self,
        _request: &AuthorizationRequestObject,
    ) -> Result<CompactJwt, VerifierError> {
        CompactJwt::new(valid_compact_jws().to_owned())
    }
}

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

impl AuthorizationResponseJwtDecryptor for FixtureResponseJwtDecryptor {
    fn decrypt_authorization_response_jwt(
        &self,
        jwt: &str,
    ) -> Result<AuthorizationResponse, RuntimeError> {
        if jwt == valid_compact_jwe() {
            return Ok(response("state"));
        }
        Err(RuntimeError::new(
            RuntimeErrorReason::ResponseJwtDecryptionFailed,
        ))
    }
}

#[cfg(all(feature = "jose", feature = "native"))]
impl reallyme_jose::jwe::JweContentEncryptionKeyResolver for FixtureEcdhEsP256Resolver {
    fn resolve_content_encryption_key(
        &self,
        header: &reallyme_jose::jwe::CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, reallyme_jose::jwe::JweError> {
        if header.alg != reallyme_jose::jwe::JweKeyManagementAlgorithm::EcdhEs
            || !encrypted_key.is_empty()
        {
            return Err(reallyme_jose::jwe::JweError::InvalidEncryptedKey);
        }

        let epk = header
            .epk
            .as_ref()
            .ok_or(reallyme_jose::jwe::JweError::MissingRequiredHeaderParameter)?;
        let public_key = p256_public_key_from_epk(epk)?;
        let shared_secret = reallyme_crypto::p256::derive_p256_shared_secret(
            &TEST_P256_RECIPIENT_SECRET,
            &public_key,
        )
        .map_err(|_| reallyme_jose::jwe::JweError::Decrypt)?;
        reallyme_jose::jwe::derive_ecdh_es_content_encryption_key(&shared_secret, header)
    }
}

impl FixtureSessionStore {
    fn new() -> Self {
        Self {
            session: Mutex::new(Some(session())),
        }
    }
}

impl VerifierSessionStore for FixtureSessionStore {
    fn take_session(&self, key: &str) -> Result<SessionRecord, VerifierError> {
        if key == "session" {
            let mut session = self
                .session
                .lock()
                .expect("fixture store lock is available");
            return session
                .take()
                .ok_or(VerifierError::new(VerifierErrorReason::SessionNotFound));
        }
        Err(VerifierError::new(VerifierErrorReason::SessionNotFound))
    }
}

impl RequestObjectStore for FixtureRequestObjectStore {
    fn load_request_object(&self, key: &str) -> Result<HostedRequestObject, RuntimeError> {
        if key == "request" {
            return HostedRequestObject::new(
                "header.payload.signature".to_owned(),
                Some("nonce".to_owned()),
            );
        }
        Err(RuntimeError::new(RuntimeErrorReason::RequestObjectNotFound))
    }
}

impl AuthorizationRequestLaunchStore for FixtureLaunchStore {
    fn store_authorization_request_launch(
        &self,
        record: AuthorizationRequestLaunchStoreRecord<'_>,
    ) -> Result<(), RuntimeError> {
        let mut records = self
            .records
            .lock()
            .expect("fixture store lock is available");
        records.push(StoredLaunchRecord {
            session_key: record.session_key.to_owned(),
            session: record.session,
            request_object_key: record.request_object_key.to_owned(),
            request_object: record.request_object,
        });
        Ok(())
    }
}

impl AuthorizationRequestLaunchStore for FailingLaunchStore {
    fn store_authorization_request_launch(
        &self,
        _record: AuthorizationRequestLaunchStoreRecord<'_>,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::LaunchStoreFailed))
    }
}

impl AuthorizationRequestLaunchPlanner for FixtureLaunchPlanner {
    fn plan_authorization_request_launch(
        &self,
        request: &AuthorizationRequestLaunchHttpRequest,
    ) -> Result<AuthorizationRequestLaunchRequest, RuntimeError> {
        let mut planned = authorization_launch_request();
        planned.authorization_endpoint = request.authorization_endpoint.clone();
        planned.session_key = request.module_id.clone();
        planned.request_object_key = request.module_id.clone();
        planned.request_uri = "https://verifier.example/request/module-1".to_owned();
        Ok(planned)
    }
}

impl RuntimeClock for FixtureClock {
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        Ok(10)
    }
}

fn valid_compact_jwe() -> &'static str {
    "eyJhbGciOiJFQ0RILUVTIn0..aXY.Yw.dGFn"
}

fn valid_compact_jws() -> &'static str {
    "c2lnbmVk.cmVxdWVzdA.and0"
}

fn dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").expect("test query id is valid"),
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                .expect("test format is valid"),
            multiple: false,
            meta: JsonMap::from_iter([(
                "vct_values".to_owned(),
                json!(["https://credentials.example.com/identity_credential"]),
            )]),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims: None,
            claim_sets: None,
        }],
        credential_sets: None,
    }
}

fn authorization_request() -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: None,
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: "nonce".to_owned(),
        wallet_nonce: None,
        state: Some("state".to_owned()),
        dcql_query: dcql_query(),
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: None,
        iss: Some("x509_san_dns:verifier.example".to_owned()),
        aud: Some(vec!["openid4vp://".to_owned()]),
        iat: Some(10),
        exp: Some(100),
    }
}

fn authorization_launch_request() -> AuthorizationRequestLaunchRequest {
    let mut request = authorization_request();
    request.response_mode = Some(ResponseMode::DirectPostJwt);
    request.response_uri = Some("https://verifier.example/direct_post.jwt/session-1".to_owned());
    request.wallet_nonce = Some("wallet-nonce".to_owned());
    AuthorizationRequestLaunchRequest {
        authorization_endpoint: "https://suite.example/test/a/module/authorize".to_owned(),
        authorization_request: request,
        session_key: "session-1".to_owned(),
        request_object_key: "request-1".to_owned(),
        request_uri: "https://verifier.example/request/request-1".to_owned(),
        request_uri_method: RequestUriMethod::Post,
    }
}

fn build_request(sign_request_object: bool) -> pb::BuildAuthorizationRequestRequest {
    pb::BuildAuthorizationRequestRequest {
        request: buffa::MessageField::some(
            authorization_request_to_proto(&authorization_request())
                .expect("request maps to proto"),
        ),
        sign_request_object,
        __buffa_unknown_fields: Default::default(),
    }
}

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
        dcql_query: dcql_query(),
    }
}

fn response(state: &str) -> AuthorizationResponse {
    AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some(state.to_owned()),
    )
    .expect("test response is valid")
}

fn config_with_holder_binding() -> VerifierRuntimeConfig {
    VerifierRuntimeConfig::new()
        .with_holder_binding_verifier(Arc::new(FixtureHolderBindingVerifier))
}

#[test]
fn prepares_authorization_request_launch() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();

    let launch = service
        .prepare_authorization_request_launch(&authorization_launch_request(), &store, 10)
        .expect("launch preparation succeeds");

    assert_eq!(
        launch.authorization_endpoint,
        "https://suite.example/test/a/module/authorize"
    );
    assert_eq!(launch.parameters.len(), 3);
    assert_eq!(
        launch.parameters[0].name,
        AuthorizationRequestParameterName::ClientId
    );
    assert_eq!(launch.parameters[0].value, "x509_san_dns:verifier.example");
    assert_eq!(
        launch.parameters[1].name,
        AuthorizationRequestParameterName::RequestUri
    );
    assert_eq!(
        launch.parameters[1].value,
        "https://verifier.example/request/request-1"
    );
    assert_eq!(
        launch.parameters[2].name,
        AuthorizationRequestParameterName::RequestUriMethod
    );
    assert_eq!(launch.parameters[2].value, "post");

    let records = store
        .records
        .lock()
        .expect("fixture store lock is available");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].session_key, "session-1");
    assert_eq!(records[0].request_object_key, "request-1");
    assert_eq!(records[0].session.state.as_deref(), Some("state"));
    assert_eq!(records[0].session.binding.nonce, "nonce");
    assert_eq!(
        records[0].session.binding.response_uri.as_deref(),
        Some("https://verifier.example/direct_post.jwt/session-1")
    );
    assert_eq!(
        records[0].request_object.request_object_jwt,
        valid_compact_jws()
    );
    assert_eq!(
        records[0].request_object.wallet_nonce.as_deref(),
        Some("wallet-nonce")
    );
}

#[test]
fn builds_authorization_request_launch_response_body() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let launch = service
        .prepare_authorization_request_launch(&authorization_launch_request(), &store, 10)
        .expect("launch preparation succeeds");

    let response = authorization_request_launch_response(&launch).expect("launch response encodes");

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.cache_control, Some("no-store"));
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("response is valid json");
    assert_eq!(
        body["authorization_endpoint"],
        "https://suite.example/test/a/module/authorize"
    );
    assert_eq!(body["parameters"][0]["name"], "client_id");
    assert_eq!(
        body["parameters"][1]["value"],
        "https://verifier.example/request/request-1"
    );
}

#[test]
fn handles_authorization_request_launch_http() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some(JSON_MEDIA_TYPE.to_owned()),
        body: br#"{"authorization_endpoint":"https://suite.example/test/a/module/authorize","module_id":"module-1","module_name":"happy"}"#.to_vec(),
    };

    let response = handle_authorization_request_launch_http(
        &request,
        AuthorizationRequestLaunchHttpContext::new(&service, &FixtureLaunchPlanner, &store, 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("response is valid json");
    assert_eq!(
        body["authorization_endpoint"],
        "https://suite.example/test/a/module/authorize"
    );
    assert_eq!(
        body["parameters"][1]["value"],
        "https://verifier.example/request/module-1"
    );
    let records = store
        .records
        .lock()
        .expect("fixture store lock is available");
    assert_eq!(records[0].session_key, "module-1");
    assert_eq!(records[0].request_object_key, "module-1");
}

#[test]
fn launch_http_rejects_non_post() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Get,
        accept: None,
        content_type: Some(JSON_MEDIA_TYPE.to_owned()),
        body: Vec::new(),
    };

    let response = handle_authorization_request_launch_http(
        &request,
        AuthorizationRequestLaunchHttpContext::new(&service, &FixtureLaunchPlanner, &store, 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn launch_http_rejects_malformed_json() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some(JSON_MEDIA_TYPE.to_owned()),
        body: b"not-json".to_vec(),
    };

    let response = handle_authorization_request_launch_http(
        &request,
        AuthorizationRequestLaunchHttpContext::new(&service, &FixtureLaunchPlanner, &store, 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn launch_preparation_requires_signer() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let store = FixtureLaunchStore::default();

    let err = service
        .prepare_authorization_request_launch(&authorization_launch_request(), &store, 10)
        .expect_err("missing signer is rejected");

    assert_eq!(err.reason(), RuntimeErrorReason::MissingSigner);
}

#[test]
fn launch_preparation_surfaces_store_failure() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );

    let err = service
        .prepare_authorization_request_launch(
            &authorization_launch_request(),
            &FailingLaunchStore,
            10,
        )
        .expect_err("store failure is rejected");

    assert_eq!(err.reason(), RuntimeErrorReason::LaunchStoreFailed);
}

#[test]
fn builds_unsigned_authorization_request() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());

    let result = service.build_authorization_request_response(&build_request(false));

    assert!(result.request.as_option().is_some());
    assert!(result.request_jwt.is_none());
    assert!(result.binding.as_option().is_some());
    assert!(result.problem.as_option().is_none());
}

#[test]
fn builds_signed_authorization_request_with_injected_signer() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );

    let result = service.build_authorization_request_response(&build_request(true));

    assert_eq!(result.request_jwt.as_deref(), Some(valid_compact_jws()));
    assert!(result.request.as_option().is_none());
    assert!(result.binding.as_option().is_some());
    assert!(result.problem.as_option().is_none());
}

#[test]
fn reports_problem_when_signer_is_missing() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());

    let result = service.build_authorization_request_response(&build_request(true));
    let problem = result.problem.as_option().expect("problem is returned");

    assert_eq!(
        problem.kind.as_known(),
        Some(pb::ProblemKind::UnsupportedFeature)
    );
    assert!(result.request_jwt.is_none());
}

#[test]
fn validates_authorization_response() {
    let service = VerifierRuntimeService::new(config_with_holder_binding());
    let request = pb::ValidateAuthorizationResponseRequest {
        session: buffa::MessageField::some(
            session_record_to_proto(&session()).expect("test session maps to proto"),
        ),
        response: buffa::MessageField::some(
            authorization_response_to_proto(&response("state")).expect("response maps to proto"),
        ),
        now_unix: 10,
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.validate_authorization_response_body(&request);

    assert!(result.valid);
    assert!(result.problem.as_option().is_none());
}

#[test]
fn maps_response_validation_failure_to_problem() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = pb::ValidateAuthorizationResponseRequest {
        session: buffa::MessageField::some(
            session_record_to_proto(&session()).expect("test session maps to proto"),
        ),
        response: buffa::MessageField::some(
            authorization_response_to_proto(&response("other")).expect("response maps to proto"),
        ),
        now_unix: 10,
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.validate_authorization_response_body(&request);
    let problem = result.problem.as_option().expect("problem is returned");

    assert!(!result.valid);
    assert_eq!(
        problem.kind.as_known(),
        Some(pb::ProblemKind::SessionMismatch)
    );
}

#[test]
fn builds_digital_credential_request_options() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let mut request = authorization_request();
    request.response_mode = Some(ResponseMode::DcApiJwt);
    request.client_id = None;
    let proto_request = pb::BuildDigitalCredentialRequestOptionsRequest {
        requests: vec![pb::DigitalCredentialGetRequest {
            protocol: "openid4vp-v1-unsigned".to_owned(),
            data: Some(pb::digital_credential_get_request::Data::UnsignedRequest(
                Box::new(authorization_request_to_proto(&request).expect("request maps to proto")),
            )),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.build_digital_credential_request_options_body(&proto_request);

    assert!(result.problem.as_option().is_none());
    let options = result.options.as_option().expect("options are returned");
    assert_eq!(options.requests.len(), 1);
    assert_eq!(options.requests[0].protocol, "openid4vp-v1-unsigned");
}

#[test]
fn decodes_plain_dc_api_authorization_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let plaintext = reallyme_openid4vp_dc_api::DcApiAuthorizationResponse {
        data: response("state"),
    };
    let request = pb::DecodeDcApiAuthorizationResponseRequest {
        response: Some(DcApiResponseOneof::Plaintext(Box::new(
            dc_api_authorization_response_to_proto(&plaintext).expect("DC API response maps"),
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.decode_dc_api_authorization_response_body(&request);

    assert!(result.problem.as_option().is_none());
    assert!(result.response.as_option().is_some());
}

#[cfg(feature = "jose")]
#[test]
fn decodes_encrypted_dc_api_authorization_response_with_jose(
) -> Result<(), reallyme_jose::jwe::JweError> {
    let compact = compact_jwe_dir_a128gcm(
        &TEST_JWE_KEY,
        &[9u8; 12],
        br#"{"vp_token":{"pid":["presentation"]},"state":"state"}"#,
    )?;
    let encrypted = reallyme_openid4vp_dc_api::EncryptedDcApiAuthorizationResponse::new(compact)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidPayloadJson)?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(
        reallyme_jose::jwe::DirectJweKeyResolver::new(&TEST_JWE_KEY),
    );
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = pb::DecodeDcApiAuthorizationResponseRequest {
        response: Some(DcApiResponseOneof::Encrypted(Box::new(
            encrypted_dc_api_authorization_response_to_proto(&encrypted),
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.decode_dc_api_authorization_response_body(&request);

    assert!(result.problem.as_option().is_none());
    assert!(result.response.as_option().is_some());
    Ok(())
}

#[cfg(all(feature = "jose", feature = "native"))]
#[test]
fn decodes_encrypted_dc_api_authorization_response_with_ecdh_es_jose(
) -> Result<(), reallyme_jose::jwe::JweError> {
    let compact =
        compact_jwe_ecdh_es_a128gcm(br#"{"vp_token":{"pid":["presentation"]},"state":"state"}"#)?;
    let encrypted = reallyme_openid4vp_dc_api::EncryptedDcApiAuthorizationResponse::new(compact)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidPayloadJson)?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(FixtureEcdhEsP256Resolver);
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = pb::DecodeDcApiAuthorizationResponseRequest {
        response: Some(DcApiResponseOneof::Encrypted(Box::new(
            encrypted_dc_api_authorization_response_to_proto(&encrypted),
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.decode_dc_api_authorization_response_body(&request);

    assert!(result.problem.as_option().is_none());
    assert!(result.response.as_option().is_some());
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn builds_native_connect_server() {
    let service = Arc::new(VerifierRuntimeService::new(VerifierRuntimeConfig::new()));

    let _server = build_verifier_connect_server(service);
}

#[test]
fn serves_request_object_by_get() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Get,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: None,
        body: Vec::new(),
    };

    let response = serve_request_object_http(&request, "header.payload.signature", None)
        .expect("request object is served");

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(REQUEST_OBJECT_MEDIA_TYPE));
    assert_eq!(response.cache_control, Some("no-store"));
    assert_eq!(response.body, b"header.payload.signature");
}

#[test]
fn serves_request_object_by_post_with_wallet_nonce() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some("application/*".to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=nonce".to_vec(),
    };

    let response = serve_request_object_http(&request, "header.payload.signature", Some("nonce"))
        .expect("request object is served");

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(REQUEST_OBJECT_MEDIA_TYPE));
}

#[test]
fn rejects_request_object_post_wallet_nonce_mismatch() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=other".to_vec(),
    };

    let err = serve_request_object_http(&request, "header.payload.signature", Some("nonce"))
        .expect_err("wallet_nonce mismatch is rejected");

    assert_eq!(err.reason(), RuntimeErrorReason::WalletNonceMismatch);
}

#[test]
fn handles_valid_direct_post() {
    let service = VerifierRuntimeService::new(config_with_holder_binding());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded; charset=utf-8".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=state".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.cache_control, Some("no-store"));
    assert_eq!(response.body, b"{}");
}

#[test]
fn maps_direct_post_session_mismatch_to_problem_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=other".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
    assert!(!response.body.is_empty());
}

#[test]
fn maps_malformed_direct_post_form_to_problem_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%XY".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn handles_direct_post_authorization_error_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=state".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.body, b"{}");
}

#[test]
fn rejects_direct_post_authorization_error_state_mismatch() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=other".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_mixed_direct_post_success_and_error_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body:
            b"error=access_denied&vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=state"
                .to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_direct_post_authorization_error_with_bad_error_code() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access+denied&state=state".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_oversized_direct_post_body() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=state".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10).with_max_body_bytes(4),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn handles_valid_direct_post_jwt() {
    let service = VerifierRuntimeService::new(
        config_with_holder_binding()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.body, b"{}");
}

#[cfg(feature = "jose")]
#[test]
fn jose_decryptor_handles_valid_a128gcm_direct_post_jwt() -> Result<(), reallyme_jose::jwe::JweError>
{
    let compact = compact_jwe_dir_a128gcm(
        &TEST_JWE_KEY,
        &[9u8; 12],
        br#"{"vp_token":{"pid":["presentation"]},"state":"state"}"#,
    )?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(
        reallyme_jose::jwe::DirectJweKeyResolver::new(&TEST_JWE_KEY),
    );
    let service = VerifierRuntimeService::new(
        config_with_holder_binding().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={compact}").into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.body, b"{}");
    Ok(())
}

#[cfg(all(feature = "jose", feature = "native"))]
#[test]
fn jose_decryptor_handles_valid_ecdh_es_direct_post_jwt() -> Result<(), reallyme_jose::jwe::JweError>
{
    let compact =
        compact_jwe_ecdh_es_a128gcm(br#"{"vp_token":{"pid":["presentation"]},"state":"state"}"#)?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(FixtureEcdhEsP256Resolver);
    let service = VerifierRuntimeService::new(
        config_with_holder_binding().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={compact}").into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.body, b"{}");
    Ok(())
}

#[test]
fn rejects_direct_post_jwt_without_decryptor() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
    assert!(!response.body.is_empty());
}

#[test]
fn rejects_malformed_direct_post_jwt_before_decryption() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"response=header.payload.signature".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_direct_post_jwt_with_non_base64url_segment() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"response=eyJhbGciOiJFQ0RILUVTIn0..a+b.b.c".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_direct_post_jwt_mixed_error_and_encrypted_response() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!(
            "error=access_denied&response={}&state=state",
            valid_compact_jwe()
        )
        .into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_duplicate_direct_post_jwt_response_fields() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!(
            "response={}&response={}",
            valid_compact_jwe(),
            valid_compact_jwe()
        )
        .into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn direct_post_jwt_accepts_plain_direct_post_fallback() {
    let service = VerifierRuntimeService::new(config_with_holder_binding());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=state".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
}

#[test]
fn direct_post_jwt_accepts_plain_authorization_error_fallback() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=wallet_unavailable&state=state".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_routes_request_object_endpoint() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(VerifierRuntimeConfig::new())),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=nonce".to_vec(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::RequestObject {
            request_object_key: "request",
        },
        &request,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(REQUEST_OBJECT_MEDIA_TYPE));
    assert_eq!(response.body, b"header.payload.signature");
}

#[test]
fn verifier_http_runtime_routes_direct_post_jwt_endpoint() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            config_with_holder_binding()
                .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
        )),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPostJwt {
            session_key: "session",
        },
        &request,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_consumes_session_after_direct_post() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=state".to_vec(),
    };

    let first = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &request,
    );
    let replay = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &request,
    );

    assert_eq!(first.status, 200);
    assert_eq!(replay.status, 404);
    assert_eq!(replay.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_maps_missing_session_to_problem() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(VerifierRuntimeConfig::new())),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=state".to_vec(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "missing",
        },
        &request,
    );

    assert_eq!(response.status, 404);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[cfg(feature = "jose")]
fn compact_jwe_dir_a128gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<String, reallyme_jose::jwe::JweError> {
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&serde_json::json!({"alg":"dir","enc":"A128GCM"}))
            .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?,
    );
    compact_jwe_a128gcm(&protected, "", key, nonce, payload)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn compact_jwe_ecdh_es_a128gcm(payload: &[u8]) -> Result<String, reallyme_jose::jwe::JweError> {
    let (recipient_public_key, _recipient_secret) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&TEST_P256_RECIPIENT_SECRET)
            .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let (ephemeral_public_key, _ephemeral_secret) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&TEST_P256_EPHEMERAL_SECRET)
            .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let epk = p256_public_key_to_epk(&ephemeral_public_key)?;
    let apu = reallyme_codec::base64url::bytes_to_base64url(b"wallet.example");
    let apv = reallyme_codec::base64url::bytes_to_base64url(b"verifier.example");
    let protected_header = reallyme_jose::jwe::CompactJweProtectedHeader {
        alg: reallyme_jose::jwe::JweKeyManagementAlgorithm::EcdhEs,
        enc: reallyme_jose::jwe::JweContentEncryptionAlgorithm::A128Gcm,
        kid: Some("verifier-key-1".to_owned()),
        apu: Some(apu.clone()),
        apv: Some(apv.clone()),
        epk: Some(epk.clone()),
        typ: None,
        cty: None,
    };
    let shared_secret = reallyme_crypto::p256::derive_p256_shared_secret(
        &TEST_P256_EPHEMERAL_SECRET,
        &recipient_public_key,
    )
    .map_err(|_| reallyme_jose::jwe::JweError::Decrypt)?;
    let cek = reallyme_jose::jwe::derive_ecdh_es_content_encryption_key(
        &shared_secret,
        &protected_header,
    )?;
    let cek = <&[u8; 16]>::try_from(cek.as_slice())
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&serde_json::json!({
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "kid": "verifier-key-1",
            "apu": apu,
            "apv": apv,
            "epk": epk,
        }))
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?,
    );
    compact_jwe_a128gcm(&protected, "", cek, &[10u8; 12], payload)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn p256_public_key_to_epk(
    public_key: &[u8],
) -> Result<serde_json::Value, reallyme_jose::jwe::JweError> {
    let uncompressed = reallyme_crypto::p256::decompress_public_key(public_key)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?;
    let uncompressed = <&[u8; 65]>::try_from(uncompressed.as_slice())
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?;
    if uncompressed[0] != 4 {
        return Err(reallyme_jose::jwe::JweError::InvalidHeader);
    }
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": reallyme_codec::base64url::bytes_to_base64url(&uncompressed[1..33]),
        "y": reallyme_codec::base64url::bytes_to_base64url(&uncompressed[33..65]),
    }))
}

#[cfg(all(feature = "jose", feature = "native"))]
fn p256_public_key_from_epk(
    epk: &serde_json::Value,
) -> Result<Vec<u8>, reallyme_jose::jwe::JweError> {
    let kty = epk_member(epk, "kty")?;
    let crv = epk_member(epk, "crv")?;
    if kty != "EC" || crv != "P-256" {
        return Err(reallyme_jose::jwe::JweError::InvalidHeader);
    }
    let x = decode_p256_coordinate(epk_member(epk, "x")?)?;
    let y = decode_p256_coordinate(epk_member(epk, "y")?)?;
    let mut public_key = [0u8; 65];
    public_key[0] = 4;
    public_key[1..33].copy_from_slice(&x);
    public_key[33..65].copy_from_slice(&y);
    reallyme_crypto::p256::compress_public_key(&public_key)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn epk_member<'a>(
    epk: &'a serde_json::Value,
    name: &str,
) -> Result<&'a str, reallyme_jose::jwe::JweError> {
    epk.get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(reallyme_jose::jwe::JweError::InvalidHeader)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn decode_p256_coordinate(input: &str) -> Result<[u8; 32], reallyme_jose::jwe::JweError> {
    let bytes = reallyme_codec::base64url::base64url_to_bytes(input)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?;
    <[u8; 32]>::try_from(bytes).map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)
}

#[cfg(feature = "jose")]
fn compact_jwe_a128gcm(
    protected: &str,
    encrypted_key: &str,
    key: &[u8; 16],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<String, reallyme_jose::jwe::JweError> {
    let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(key)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let nonce_value = reallyme_crypto::aes::Aes128GcmNonce::from_slice(nonce)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentCipherInput)?;
    let ciphertext_with_tag =
        reallyme_crypto::aes::encrypt_aes128_gcm(&reallyme_crypto::aes::Aes128GcmEncryptRequest {
            key: &key,
            nonce: nonce_value,
            aad: protected.as_bytes(),
            plaintext: payload,
        })
        .map_err(|_| reallyme_jose::jwe::JweError::Decrypt)?;

    let ciphertext_and_tag = ciphertext_with_tag.as_bytes();
    let tag_len = reallyme_jose::jwe::JweContentEncryptionAlgorithm::A128Gcm.tag_len();
    let split_at = ciphertext_and_tag
        .len()
        .checked_sub(tag_len)
        .ok_or(reallyme_jose::jwe::JweError::LengthOverflow)?;
    let ciphertext = reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[..split_at]);
    let tag = reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[split_at..]);
    let iv = reallyme_codec::base64url::bytes_to_base64url(nonce);

    Ok(format!(
        "{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}"
    ))
}
