// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::AuthorizationRequestObject;

use crate::{
    RequestObjectSignatureVerifier, VerifiedClientMetadataReference, VerifiedVerifierAttestation,
    WalletError, WalletErrorReason,
};

const REQUEST_OBJECT_TYP_VALUES: &[&str] = &["oauth-authz-req+jwt"];

/// Verification material for a signed Request Object JWT.
#[derive(Debug, Clone, Copy)]
pub struct JoseRequestObjectVerificationKey<'a> {
    jwk: &'a reallyme_crypto::jwk::Jwk,
    public_key: &'a [u8],
}

impl<'a> JoseRequestObjectVerificationKey<'a> {
    /// Build a JOSE verification key from trusted resolver-owned material.
    pub const fn new(jwk: &'a reallyme_crypto::jwk::Jwk, public_key: &'a [u8]) -> Self {
        Self { jwk, public_key }
    }
}

/// Resolves trusted key material for a signed OpenID4VP Request Object.
///
/// The resolver owns verifier trust: `kid`, `client_id` prefix rules, X.509
/// chains, DID documents, federation metadata, verifier attestations, and cache
/// policy all sit outside this protocol crate. This adapter only applies JOSE
/// verification once a host has supplied trusted key material.
pub trait JoseRequestObjectVerificationKeyResolver: Send + Sync {
    /// Resolve the public verification key for the compact Request Object JWT.
    fn resolve_request_object_verification_key<'a>(
        &'a self,
        jwt: &str,
    ) -> Result<JoseRequestObjectVerificationKey<'a>, WalletError>;

    /// Return verified verifier attestation evidence from the Request Object JOSE header.
    fn verified_verifier_attestation(
        &self,
        _jwt: &str,
    ) -> Result<Option<VerifiedVerifierAttestation>, WalletError> {
        Ok(None)
    }

    /// Return fresh trusted metadata-reference evidence for the Request Object.
    fn verified_client_metadata_reference(
        &self,
        _jwt: &str,
    ) -> Result<Option<VerifiedClientMetadataReference>, WalletError> {
        Ok(None)
    }
}

/// `reallyme-jose` backed verifier for signed RFC 9101 Request Objects.
pub struct JoseSignedRequestObjectVerifier<R> {
    key_resolver: R,
    temporal_policy: reallyme_jose::jwt::JwtTemporalValidationPolicy,
    header_validation: reallyme_jose::jwt::JwtHeaderValidationOptions<'static>,
}

impl<R> JoseSignedRequestObjectVerifier<R> {
    /// Build a verifier with the OpenID4VP signed Request Object policy.
    pub fn new(key_resolver: R) -> Self {
        Self {
            key_resolver,
            temporal_policy: request_object_temporal_policy(),
            header_validation: request_object_header_validation(),
        }
    }

    /// Build a verifier with explicit JOSE policy.
    ///
    /// HAIP, conformance, and deployment profiles can tighten temporal or
    /// protected-header rules without changing the wallet request pipeline.
    pub const fn with_policy(
        key_resolver: R,
        temporal_policy: reallyme_jose::jwt::JwtTemporalValidationPolicy,
        header_validation: reallyme_jose::jwt::JwtHeaderValidationOptions<'static>,
    ) -> Self {
        Self {
            key_resolver,
            temporal_policy,
            header_validation,
        }
    }
}

impl<R> RequestObjectSignatureVerifier for JoseSignedRequestObjectVerifier<R>
where
    R: JoseRequestObjectVerificationKeyResolver,
{
    fn verify_request_object(
        &self,
        jwt: &str,
        now_unix: u64,
    ) -> Result<AuthorizationRequestObject, WalletError> {
        let key = self
            .key_resolver
            .resolve_request_object_verification_key(jwt)?;
        reallyme_jose::jwt::decode_verify_jwt_with_temporal_validation_and_header_validation(
            jwt,
            key.jwk,
            key.public_key,
            now_unix,
            self.temporal_policy,
            &self.header_validation,
        )
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))
    }

    fn verified_verifier_attestation(
        &self,
        jwt: &str,
    ) -> Result<Option<VerifiedVerifierAttestation>, WalletError> {
        self.key_resolver.verified_verifier_attestation(jwt)
    }

    fn verified_client_metadata_reference(
        &self,
        jwt: &str,
    ) -> Result<Option<VerifiedClientMetadataReference>, WalletError> {
        self.key_resolver.verified_client_metadata_reference(jwt)
    }
}

const fn request_object_header_validation(
) -> reallyme_jose::jwt::JwtHeaderValidationOptions<'static> {
    reallyme_jose::jwt::JwtHeaderValidationOptions {
        allow_missing_typ: false,
        accepted_typ_values: REQUEST_OBJECT_TYP_VALUES,
    }
}

const fn request_object_temporal_policy() -> reallyme_jose::jwt::JwtTemporalValidationPolicy {
    reallyme_jose::jwt::JwtTemporalValidationPolicy {
        require_exp: true,
        require_nbf: false,
        require_iat: false,
        clock_skew_seconds: 60,
        max_future_iat_skew_seconds: 60,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_types::{
        AuthorizationRequestObject, ClientIdentifier, ClientIdentifierPrefix, ResponseMode,
        ResponseType,
    };
    use serde_json::Map as JsonMap;

    use crate::{
        verify_signed_request_object, JoseRequestObjectVerificationKey,
        JoseRequestObjectVerificationKeyResolver, JoseSignedRequestObjectVerifier,
        VerifiedVerifierAttestation, WalletError, WalletErrorReason,
    };

    static TEST_P256_SECRET: [u8; 32] = [
        0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf,
        0xee, 0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91,
        0xc3, 0x44,
    ];
    static WRONG_P256_SECRET: [u8; 32] = [
        0x6a, 0x10, 0x45, 0xf2, 0x33, 0x9e, 0x80, 0x12, 0xab, 0x74, 0xc6, 0x28, 0xde, 0x91, 0x07,
        0x5b, 0x49, 0xef, 0x32, 0x18, 0x84, 0x2d, 0xbc, 0x60, 0x13, 0xa5, 0x77, 0xc9, 0x0e, 0x4b,
        0x26, 0xd1,
    ];

    struct FixtureKeyResolver {
        jwk: reallyme_crypto::jwk::Jwk,
        public_key: Vec<u8>,
        verifier_attestation: Option<Result<VerifiedVerifierAttestation, WalletErrorReason>>,
    }

    impl JoseRequestObjectVerificationKeyResolver for FixtureKeyResolver {
        fn resolve_request_object_verification_key<'a>(
            &'a self,
            _jwt: &str,
        ) -> Result<JoseRequestObjectVerificationKey<'a>, WalletError> {
            Ok(JoseRequestObjectVerificationKey::new(
                &self.jwk,
                &self.public_key,
            ))
        }

        fn verified_verifier_attestation(
            &self,
            _jwt: &str,
        ) -> Result<Option<VerifiedVerifierAttestation>, WalletError> {
            match self.verifier_attestation.as_ref() {
                Some(Ok(attestation)) => Ok(Some(attestation.clone())),
                Some(Err(reason)) => Err(WalletError::new(*reason)),
                None => Ok(None),
            }
        }
    }

    fn request(exp: u64, iat: u64) -> AuthorizationRequestObject {
        AuthorizationRequestObject {
            client_id: Some(
                ClientIdentifier::parse("x509_san_dns:verifier.example")
                    .expect("test client id is valid"),
            ),
            response_type: ResponseType::VpToken,
            response_mode: Some(ResponseMode::DcApiJwt),
            response_uri: None,
            redirect_uri: None,
            nonce: "nonce".to_owned(),
            wallet_nonce: None,
            state: None,
            dcql_query: DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: QueryId::parse("pid").expect("test query id is valid"),
                    format: CredentialFormat::new(CredentialFormat::MSO_MDOC.to_owned())
                        .expect("test format is valid"),
                    multiple: false,
                    meta: JsonMap::new(),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: true,
                    claims: None,
                    claim_sets: None,
                }],
                credential_sets: None,
            },
            transaction_data: None,
            client_metadata: None,
            client_metadata_uri: None,
            expected_origins: Some(vec!["https://rp.example".to_owned()]),
            iss: Some("x509_san_dns:verifier.example".to_owned()),
            aud: Some(vec!["wallet".to_owned()]),
            iat: Some(iat),
            exp: Some(exp),
        }
    }

    fn key_resolver(secret: &[u8; 32]) -> FixtureKeyResolver {
        let (public_key, _secret_key) =
            reallyme_crypto::p256::generate_p256_keypair_from_secret_key(secret)
                .expect("test P-256 key is valid");
        let jwk = reallyme_crypto::jwk::p256_public_key_to_jwk(
            &public_key,
            reallyme_crypto::jwk::JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: Some("verifier-key-1".to_owned()),
            },
        )
        .expect("test JWK is valid");
        FixtureKeyResolver {
            jwk: reallyme_crypto::jwk::Jwk::Ec(jwk),
            public_key,
            verifier_attestation: None,
        }
    }

    fn key_resolver_with_attestation(
        verifier_attestation: Result<VerifiedVerifierAttestation, WalletErrorReason>,
    ) -> FixtureKeyResolver {
        let mut resolver = key_resolver(&TEST_P256_SECRET);
        resolver.verifier_attestation = Some(verifier_attestation);
        resolver
    }

    fn signed_request_object() -> String {
        signed_request_object_for(&request(20, 10))
    }

    fn signed_request_object_for(request: &AuthorizationRequestObject) -> String {
        signed_request_object_for_typ(request, Some("oauth-authz-req+jwt".to_owned()))
    }

    fn signed_request_object_for_typ(
        request: &AuthorizationRequestObject,
        typ: Option<String>,
    ) -> String {
        let resolver = key_resolver(&TEST_P256_SECRET);
        reallyme_jose::jwt::encode_signed_jwt_with_header_options(
            request,
            &resolver.jwk,
            &TEST_P256_SECRET,
            &reallyme_jose::jwt::JwtHeaderEncodeOptions { typ },
        )
        .expect("test request object signs")
    }

    fn verifier_attestation_request() -> AuthorizationRequestObject {
        let mut request = request(20, 10);
        request.client_id = Some(
            ClientIdentifier::parse("verifier_attestation:verifier.example")
                .expect("test verifier attestation client id is valid"),
        );
        request.iss = Some("verifier_attestation:verifier.example".to_owned());
        request.response_mode = Some(ResponseMode::DirectPost);
        request.response_uri = Some("https://verifier.example/response".to_owned());
        request.redirect_uri = Some("https://verifier.example/cb".to_owned());
        request.expected_origins = None;
        request
    }

    #[test]
    fn verifies_signed_request_object_with_jose() {
        let jwt = signed_request_object();
        let verifier = JoseSignedRequestObjectVerifier::new(key_resolver(&TEST_P256_SECRET));
        let verified =
            verify_signed_request_object(&verifier, &jwt, Some("https://rp.example"), 11)
                .expect("signed Request Object verifies");

        assert_eq!(verified.request.nonce, "nonce");
    }

    #[test]
    fn rejects_signed_request_object_with_wrong_key() {
        let jwt = signed_request_object();
        let verifier = JoseSignedRequestObjectVerifier::new(key_resolver(&WRONG_P256_SECRET));
        let err = verify_signed_request_object(&verifier, &jwt, Some("https://rp.example"), 11)
            .expect_err("wrong key must not verify");

        assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
    }

    #[test]
    fn rejects_signed_request_object_without_typ() {
        let jwt = signed_request_object_for_typ(&request(20, 10), None);
        let verifier = JoseSignedRequestObjectVerifier::new(key_resolver(&TEST_P256_SECRET));
        let err = verify_signed_request_object(&verifier, &jwt, Some("https://rp.example"), 11)
            .expect_err("missing typ is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
    }

    #[test]
    fn rejects_signed_request_object_with_generic_jwt_typ() {
        let jwt = signed_request_object_for_typ(&request(20, 10), Some("JWT".to_owned()));
        let verifier = JoseSignedRequestObjectVerifier::new(key_resolver(&TEST_P256_SECRET));
        let err = verify_signed_request_object(&verifier, &jwt, Some("https://rp.example"), 11)
            .expect_err("generic JWT typ is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
    }

    #[test]
    fn accepts_verifier_attestation_evidence_from_jose_resolver() {
        let jwt = signed_request_object_for(&verifier_attestation_request());
        let attestation = VerifiedVerifierAttestation::new(
            "verifier.example".to_owned(),
            Some(vec!["https://verifier.example/cb".to_owned()]),
        )
        .expect("test attestation evidence is valid");
        let verifier =
            JoseSignedRequestObjectVerifier::new(key_resolver_with_attestation(Ok(attestation)));

        let verified = verify_signed_request_object(&verifier, &jwt, None, 11)
            .expect("host-verified attestation evidence is accepted");

        assert_eq!(
            verified.request.client_id.map(|client_id| client_id.prefix),
            Some(ClientIdentifierPrefix::VerifierAttestation)
        );
    }

    #[test]
    fn rejects_verifier_attestation_jws_failure_from_jose_resolver() {
        let jwt = signed_request_object_for(&verifier_attestation_request());
        let verifier = JoseSignedRequestObjectVerifier::new(key_resolver_with_attestation(Err(
            WalletErrorReason::InvalidVerifierAttestation,
        )));

        let err = verify_signed_request_object(&verifier, &jwt, None, 11)
            .expect_err("attestation JWS validation failure is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn rejects_verifier_attestation_subject_from_jose_resolver() {
        let jwt = signed_request_object_for(&verifier_attestation_request());
        let attestation = VerifiedVerifierAttestation::new("other.example".to_owned(), None)
            .expect("test attestation evidence is valid");
        let verifier =
            JoseSignedRequestObjectVerifier::new(key_resolver_with_attestation(Ok(attestation)));

        let err = verify_signed_request_object(&verifier, &jwt, None, 11)
            .expect_err("attestation subject binding is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }
}
