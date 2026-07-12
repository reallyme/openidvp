// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for OpenID4VP protobuf codec mappings.

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dc_api::{
    DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest, DigitalCredentialRequestOptions,
};
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::{
    DerivedClaimStatement, ZkPresentation, ZkPresentationBinding, ZK_PRESENTATION_TYPE,
};
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_request_transport_to_proto, authorization_response_to_proto,
    client_identifier_to_proto, decode_authorization_request, decode_authorization_response,
    digital_credential_request_options_to_proto, encode_authorization_request,
    encode_authorization_response, problem_details_to_proto,
    proto_to_authorization_request_transport, proto_to_authorization_response,
    proto_to_digital_credential_request_options, proto_to_problem_details,
    proto_to_verifier_metadata, proto_to_wallet_metadata, verifier_metadata_to_proto,
    wallet_metadata_to_proto, OpenId4VpProtoError,
};
use reallyme_openid4vp_types::{
    AlgorithmIdentifier, AuthorizationRequestObject, AuthorizationResponse, ClientIdentifier,
    ClientIdentifierPrefix, ClientMetadata, PresentationValue, ProblemDetails, ProblemInstance,
    ProblemKind, RequestUriMethod, ResponseMode, ResponseType, TransactionData, VerifierMetadata,
    WalletMetadata,
};
use reallyme_openid4vp_wallet::AuthorizationRequestTransport;
use serde_json::{json, Map as JsonMap};

fn dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").expect("test query id is valid"),
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                .expect("test credential format is valid"),
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

#[test]
fn encodes_and_decodes_authorization_response_proto() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![
            PresentationValue::Compact("header.payload.signature".to_owned()),
            PresentationValue::Json(json!({"proof": true})),
        ],
        Some("state".to_owned()),
    )
    .expect("test response is valid");

    let encoded = encode_authorization_response(&response).expect("response encodes");
    let decoded = decode_authorization_response(&encoded).expect("response decodes");

    assert_eq!(decoded, response);
}

#[test]
fn encodes_zk_presentation_as_typed_proto_oneof() {
    let presentation = ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        circuit_id: "rm-zk-vc-base-v1".to_owned(),
        circuit_ref: None,
        proof: vec![1, 2, 3],
        public_inputs: vec![4, 5, 6],
        derived_claims: vec![DerivedClaimStatement {
            statement_id: "age".to_owned(),
            statement: "age_over_18".to_owned(),
        }],
        binding: ZkPresentationBinding {
            nonce_hash: [7; 32],
            audience_hash: [8; 32],
            transaction_data_hash: Some([9; 32]),
        },
    };
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Json(
            serde_json::to_value(presentation).expect("test presentation serializes"),
        )],
        None,
    )
    .expect("test response is valid");

    let proto = authorization_response_to_proto(&response).expect("response maps to proto");
    let circuit_id = proto
        .vp_token
        .first()
        .and_then(|entry| entry.presentations.first())
        .and_then(|value| value.kind.as_ref())
        .and_then(|kind| match kind {
            pb::presentation_value::Kind::Zk(zk) => Some(zk.circuit_id.as_str()),
            _ => None,
        });

    assert_eq!(circuit_id, Some("rm-zk-vc-base-v1"));
    let decoded = proto_to_authorization_response(&proto).expect("typed zk proto decodes");
    assert_eq!(decoded, response);
}

#[test]
fn rejects_empty_authorization_response_proto() {
    let proto = pb::AuthorizationResponse {
        vp_token: Vec::new(),
        state: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
        __buffa_unknown_fields: Default::default(),
    };

    let err = proto_to_authorization_response(&proto)
        .expect_err("empty final vp_token object is rejected");

    assert_eq!(err, OpenId4VpProtoError::MissingField);
}

#[test]
fn rejects_invalid_vp_token_query_id() {
    let proto = pb::AuthorizationResponse {
        vp_token: vec![pb::VpTokenEntry {
            query_id: "not a valid id".to_owned(),
            presentations: vec![pb::PresentationValue {
                kind: Some(pb::presentation_value::Kind::Compact(
                    "header.payload.signature".to_owned(),
                )),
                __buffa_unknown_fields: Default::default(),
            }],
            __buffa_unknown_fields: Default::default(),
        }],
        state: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
        __buffa_unknown_fields: Default::default(),
    };

    let err =
        proto_to_authorization_response(&proto).expect_err("invalid DCQL query id is rejected");

    assert_eq!(err, OpenId4VpProtoError::InvalidField);
}

#[test]
fn rejects_empty_presentation_list_in_response_proto() {
    let proto = pb::AuthorizationResponse {
        vp_token: vec![pb::VpTokenEntry {
            query_id: "pid".to_owned(),
            presentations: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        }],
        state: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
        __buffa_unknown_fields: Default::default(),
    };

    let err = proto_to_authorization_response(&proto)
        .expect_err("empty per-query presentation list is rejected");

    assert_eq!(err, OpenId4VpProtoError::MissingField);
}

#[test]
fn maps_client_identifier_to_generated_proto() {
    let client_id =
        ClientIdentifier::parse("x509_san_dns:verifier.example").expect("test client id is valid");
    let proto = client_identifier_to_proto(&client_id);

    assert_eq!(proto.wire_value, "x509_san_dns:verifier.example");
    assert_eq!(proto.identifier, "verifier.example");
}

#[test]
fn maps_metadata_capabilities_to_generated_proto() {
    let verifier_metadata = VerifierMetadata::new(
        vec![ResponseMode::DirectPostJwt, ResponseMode::DirectPost],
        vec![ClientIdentifierPrefix::X509SanDns],
        vec![
            CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                .expect("test credential format is valid"),
        ],
        vec![AlgorithmIdentifier::new("ES256".to_owned()).expect("test alg is valid")],
        vec![AlgorithmIdentifier::new("ECDH-ES".to_owned()).expect("test alg is valid")],
        vec![AlgorithmIdentifier::new("A128GCM".to_owned()).expect("test alg is valid")],
    )
    .expect("test verifier metadata is valid");
    let wallet_metadata = WalletMetadata::new(
        vec![ResponseMode::DirectPost],
        vec![RequestUriMethod::Get, RequestUriMethod::Post],
        vec![
            CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                .expect("test credential format is valid"),
        ],
        vec![AlgorithmIdentifier::new("ECDH-ES".to_owned()).expect("test alg is valid")],
        vec![AlgorithmIdentifier::new("A128GCM".to_owned()).expect("test alg is valid")],
    )
    .expect("test wallet metadata is valid");

    let verifier_proto = verifier_metadata_to_proto(&verifier_metadata);
    let wallet_proto = wallet_metadata_to_proto(&wallet_metadata);
    let verifier_decoded =
        proto_to_verifier_metadata(&verifier_proto).expect("verifier metadata decodes");
    let wallet_decoded = proto_to_wallet_metadata(&wallet_proto).expect("wallet metadata decodes");

    assert_eq!(verifier_decoded, verifier_metadata);
    assert_eq!(wallet_decoded, wallet_metadata);
}

#[test]
fn rejects_empty_metadata_capabilities_proto() {
    let proto = pb::WalletMetadataCapabilities {
        response_modes_supported: Vec::new(),
        request_uri_methods_supported: Vec::new(),
        vp_formats_supported: Vec::new(),
        response_encryption_alg_values_supported: Vec::new(),
        response_encryption_enc_values_supported: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };

    let err = proto_to_wallet_metadata(&proto).expect_err("empty metadata is rejected");

    assert_eq!(err, OpenId4VpProtoError::InvalidField);
}

#[test]
fn encodes_and_decodes_authorization_request_proto() {
    let request = AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPostJwt),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: "nonce".to_owned(),
        wallet_nonce: None,
        state: Some("state".to_owned()),
        dcql_query: dcql_query(),
        transaction_data: Some(vec![TransactionData {
            transaction_type: "payment".to_owned(),
            credential_ids: vec!["pid".to_owned()],
            payload: json!({"amount": "10.00", "currency": "EUR"}),
        }]),
        client_metadata: Some(ClientMetadata {
            raw: json!({"jwks_uri": "https://verifier.example/jwks.json"}),
        }),
        client_metadata_uri: Some("https://verifier.example/metadata.json".to_owned()),
        expected_origins: Some(vec!["https://verifier.example".to_owned()]),
        iss: Some("x509_san_dns:verifier.example".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(10),
        exp: Some(70),
    };

    let encoded = encode_authorization_request(&request).expect("request encodes");
    let decoded = decode_authorization_request(&encoded).expect("request decodes");

    assert_eq!(decoded, request);
}

#[test]
fn maps_wallet_request_transport_oneof() {
    let transport = AuthorizationRequestTransport::RequestUri {
        uri: "https://verifier.example/request.jwt".to_owned(),
        method: RequestUriMethod::Post,
        wallet_nonce: Some("wallet-nonce".to_owned()),
        expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
    };

    let proto = authorization_request_transport_to_proto(&transport);
    let mapped = proto_to_authorization_request_transport(&proto).expect("transport maps");

    assert_eq!(mapped, transport);
}

#[test]
fn maps_problem_details_without_detail_text() {
    let problem = ProblemDetails::from_kind(ProblemKind::InvalidRequestObject)
        .with_instance(ProblemInstance::new("urn:trace:test".to_owned()));

    let proto = problem_details_to_proto(&problem);
    let mapped = proto_to_problem_details(&proto).expect("problem details map");

    assert_eq!(mapped.extensions.kind, ProblemKind::InvalidRequestObject);
    assert_eq!(
        mapped.instance.as_ref().map(ProblemInstance::as_str),
        Some("urn:trace:test")
    );
}

#[test]
fn maps_dc_api_request_options() {
    let request = AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApi),
        response_uri: None,
        redirect_uri: None,
        nonce: "nonce".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: dcql_query(),
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    };
    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("test DC API request is valid");
    let options = DigitalCredentialRequestOptions::new(vec![entry])
        .expect("test DC API request options are valid");

    let proto = digital_credential_request_options_to_proto(&options).expect("DC API options map");
    let mapped =
        proto_to_digital_credential_request_options(&proto).expect("DC API options map back");

    assert_eq!(mapped, options);
}
