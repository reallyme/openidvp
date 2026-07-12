// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_runtime::{
    handle_direct_post_jwt_http, DirectPostValidationContext,
    JoseAuthorizationResponseJwtDecryptor, RuntimeHttpMethod, RuntimeHttpRequest,
    VerifierRuntimeConfig, VerifierRuntimeService,
};
use reallyme_openid4vp_types::ClientIdentifier;
use reallyme_openid4vp_verifier::{RequestBinding, SessionRecord};
use serde_json::{json, Map as JsonMap};

const FUZZ_MAX_DIRECT_POST_JWT_BODY_BYTES: usize = 512;
const FUZZ_DIRECT_JWE_KEY: [u8; 16] = [9u8; 16];

fuzz_target!(|data: &[u8]| {
    let Some(session) = session() else {
        return;
    };
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(
        reallyme_jose::jwe::DirectJweKeyResolver::new(&FUZZ_DIRECT_JWE_KEY),
    );
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let selector = match data.first().copied() {
        Some(value) => value,
        None => 0,
    };
    let body = data.get(1..).map_or_else(Vec::new, <[u8]>::to_vec);
    let request = RuntimeHttpRequest {
        method: if selector & 1 == 0 {
            RuntimeHttpMethod::Post
        } else {
            RuntimeHttpMethod::Get
        },
        accept: None,
        content_type: (selector & 2 == 0).then(|| "application/x-www-form-urlencoded".to_owned()),
        body,
    };
    let context = DirectPostValidationContext::new(&session, 10)
        .with_max_body_bytes(FUZZ_MAX_DIRECT_POST_JWT_BODY_BYTES);
    let _ = handle_direct_post_jwt_http(&service, &request, context);
});

fn session() -> Option<SessionRecord> {
    let client_id = ClientIdentifier::parse("x509_san_dns:verifier.example").ok()?;
    Some(SessionRecord {
        binding: RequestBinding {
            client_id,
            nonce: "nonce".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            expiry_unix: 100,
            transaction_data_hash: None,
        },
        state: Some("state".to_owned()),
        dcql_query: dcql_query()?,
    })
}

fn dcql_query() -> Option<DcqlQuery> {
    Some(DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").ok()?,
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()).ok()?,
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
    })
}
