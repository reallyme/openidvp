// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{classify_request_object_jwt, AuthorizationRequestObject};
use zeroize::Zeroize;

use crate::{RequestObjectSignatureVerifier, WalletError, WalletErrorReason};

const DEFAULT_MAX_NESTED_REQUEST_OBJECT_BYTES: usize = 64 * 1024;

/// `reallyme-jose` backed verifier for encrypted nested RFC 9101 Request Objects.
///
/// RFC 9101 requires Request Objects using both signature and encryption to be
/// signed first, then encrypted. This adapter decrypts the outer compact JWE,
/// validates that the plaintext is a compact signed Request Object, and then
/// delegates signature verification to the injected inner verifier.
pub struct JoseNestedRequestObjectVerifier<D, V> {
    decryptor: D,
    inner_verifier: V,
    policy: reallyme_jose::jwe::CompactJwePolicy<'static>,
    max_plaintext_jwt_bytes: usize,
}

impl<D, V> JoseNestedRequestObjectVerifier<D, V> {
    /// Build a verifier with OpenID4VP nested Request Object defaults.
    pub fn new(decryptor: D, inner_verifier: V) -> Self {
        Self {
            decryptor,
            inner_verifier,
            policy: reallyme_jose::jwe::CompactJwePolicy::openid4vp_direct_post_jwt(),
            max_plaintext_jwt_bytes: DEFAULT_MAX_NESTED_REQUEST_OBJECT_BYTES,
        }
    }

    /// Build a verifier with explicit JWE policy and plaintext size bound.
    pub const fn with_policy(
        decryptor: D,
        inner_verifier: V,
        policy: reallyme_jose::jwe::CompactJwePolicy<'static>,
        max_plaintext_jwt_bytes: usize,
    ) -> Self {
        Self {
            decryptor,
            inner_verifier,
            policy,
            max_plaintext_jwt_bytes,
        }
    }
}

impl<D, V> RequestObjectSignatureVerifier for JoseNestedRequestObjectVerifier<D, V>
where
    D: reallyme_jose::jwe::JweContentEncryptionKeyResolver + Send + Sync,
    V: RequestObjectSignatureVerifier,
{
    fn verify_request_object(
        &self,
        jwt: &str,
        now_unix: u64,
    ) -> Result<AuthorizationRequestObject, WalletError> {
        let mut plaintext =
            reallyme_jose::jwe::decrypt_compact_jwe_bytes(jwt, &self.policy, &self.decryptor)
                .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
        let result = verify_nested_plaintext(
            plaintext.as_slice(),
            self.max_plaintext_jwt_bytes,
            &self.inner_verifier,
            now_unix,
        );
        plaintext.zeroize();
        result
    }
}

fn verify_nested_plaintext(
    plaintext: &[u8],
    max_plaintext_jwt_bytes: usize,
    inner_verifier: &impl RequestObjectSignatureVerifier,
    now_unix: u64,
) -> Result<AuthorizationRequestObject, WalletError> {
    if plaintext.len() > max_plaintext_jwt_bytes {
        return Err(WalletError::new(WalletErrorReason::RequestObjectTooLarge));
    }
    let signed_jwt = core::str::from_utf8(plaintext)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    let kind = classify_request_object_jwt(signed_jwt)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    if kind != reallyme_openid4vp_types::RequestObjectJwtKind::Signed {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }
    inner_verifier.verify_request_object(signed_jwt, now_unix)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_types::{
        AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
    };
    use serde_json::Map as JsonMap;

    use crate::{
        verify_signed_request_object, JoseNestedRequestObjectVerifier,
        JoseRequestObjectVerificationKey, JoseRequestObjectVerificationKeyResolver,
        JoseSignedRequestObjectVerifier, WalletError, WalletErrorReason,
    };

    static TEST_JWE_KEY: [u8; 16] = [9u8; 16];
    static TEST_P256_SECRET: [u8; 32] = [
        0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf,
        0xee, 0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91,
        0xc3, 0x44,
    ];

    struct FixtureKeyResolver {
        jwk: reallyme_crypto::jwk::Jwk,
        public_key: Vec<u8>,
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

    fn key_resolver() -> FixtureKeyResolver {
        let (public_key, _secret_key) =
            reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&TEST_P256_SECRET)
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
        }
    }

    fn signed_request_object() -> String {
        let resolver = key_resolver();
        reallyme_jose::jwt::encode_signed_jwt_with_header_options(
            &request(20, 10),
            &resolver.jwk,
            &TEST_P256_SECRET,
            &reallyme_jose::jwt::JwtHeaderEncodeOptions {
                typ: Some("oauth-authz-req+jwt".to_owned()),
            },
        )
        .expect("test request object signs")
    }

    fn compact_jwe_dir_a128gcm(payload: &[u8]) -> String {
        let protected = reallyme_codec::base64url::bytes_to_base64url(
            &serde_json::to_vec(&serde_json::json!({"alg":"dir","enc":"A128GCM"}))
                .expect("test header serializes"),
        );
        let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(&TEST_JWE_KEY)
            .expect("test key is valid");
        let nonce = reallyme_crypto::aes::Aes128GcmNonce::from_slice(&[7u8; 12])
            .expect("test nonce is valid");
        let ciphertext_with_tag = reallyme_crypto::aes::encrypt_aes128_gcm(
            &reallyme_crypto::aes::Aes128GcmEncryptRequest {
                key: &key,
                nonce,
                aad: protected.as_bytes(),
                plaintext: payload,
            },
        )
        .expect("test payload encrypts");
        let ciphertext_and_tag = ciphertext_with_tag.as_bytes();
        let split_at = ciphertext_and_tag
            .len()
            .checked_sub(reallyme_jose::jwe::JweContentEncryptionAlgorithm::A128Gcm.tag_len())
            .expect("test ciphertext includes tag");
        let ciphertext =
            reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[..split_at]);
        let tag = reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[split_at..]);
        let iv = reallyme_codec::base64url::bytes_to_base64url(&[7u8; 12]);
        format!("{protected}..{iv}.{ciphertext}.{tag}")
    }

    #[test]
    fn verifies_nested_signed_then_encrypted_request_object_with_jose() {
        let signed = signed_request_object();
        let encrypted = compact_jwe_dir_a128gcm(signed.as_bytes());
        let inner = JoseSignedRequestObjectVerifier::new(key_resolver());
        let verifier = JoseNestedRequestObjectVerifier::new(
            reallyme_jose::jwe::DirectJweKeyResolver::new(&TEST_JWE_KEY),
            inner,
        );

        let verified =
            verify_signed_request_object(&verifier, &encrypted, Some("https://rp.example"), 11)
                .expect("nested Request Object verifies");

        assert_eq!(verified.request.nonce, "nonce");
    }

    #[test]
    fn rejects_nested_request_object_with_unsigned_plaintext() {
        let encrypted = compact_jwe_dir_a128gcm(br#"{"nonce":"nonce"}"#);
        let inner = JoseSignedRequestObjectVerifier::new(key_resolver());
        let verifier = JoseNestedRequestObjectVerifier::new(
            reallyme_jose::jwe::DirectJweKeyResolver::new(&TEST_JWE_KEY),
            inner,
        );

        let err =
            verify_signed_request_object(&verifier, &encrypted, Some("https://rp.example"), 11)
                .expect_err("encrypted plaintext must be an inner signed JWT");

        assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
    }
}
