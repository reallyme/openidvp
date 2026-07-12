// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifierPrefix, ProblemDetails, ProblemKind,
};
use subtle::ConstantTimeEq;

use crate::{
    validate_client_metadata_reference_binding, validate_response_endpoint_binding,
    validate_verifier_attestation_binding, VerifiedClientMetadataReference,
    VerifiedVerifierAttestation, VerifiedX509CertificateBinding,
};
use crate::{AuthorizationRequestTransport, WalletError, WalletErrorReason};

/// Verified wallet request with parsed OpenID4VP claims.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedWalletRequest {
    /// Parsed Authorization Request Object.
    pub request: AuthorizationRequestObject,
}

/// Wallet-side Request Object verifier.
///
/// Implementations verify compact JWT syntax, JWS/JWE policy, signature,
/// `kid` to verifier key binding, and claim decoding using injected trust
/// material. Network fetching belongs outside this trait.
pub trait RequestObjectSignatureVerifier: Send + Sync {
    /// Verify a compact Request Object JWT and return parsed claims.
    fn verify_request_object(
        &self,
        jwt: &str,
        now_unix: u64,
    ) -> Result<AuthorizationRequestObject, WalletError>;

    /// Return verifier attestation evidence already validated while verifying the Request Object.
    fn verified_verifier_attestation(
        &self,
        _jwt: &str,
    ) -> Result<Option<VerifiedVerifierAttestation>, WalletError> {
        Ok(None)
    }

    /// Return verifier metadata-by-reference evidence resolved and trusted by the host.
    fn verified_client_metadata_reference(
        &self,
        _jwt: &str,
    ) -> Result<Option<VerifiedClientMetadataReference>, WalletError> {
        Ok(None)
    }

    /// Return DNS SAN evidence from the certificate used for an `x509_hash` client id.
    fn verified_x509_certificate_binding(
        &self,
        _jwt: &str,
    ) -> Result<Option<VerifiedX509CertificateBinding>, WalletError> {
        Ok(None)
    }
}

/// Host-supplied trust evidence for wallet Request Object validation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WalletRequestTrustEvidence {
    /// Verified Verifier Attestation JWT summary.
    pub verifier_attestation: Option<VerifiedVerifierAttestation>,
    /// Fresh trusted metadata resolved from a metadata reference extension.
    pub client_metadata_reference: Option<VerifiedClientMetadataReference>,
    /// Verified DNS SAN evidence for an `x509_hash` Request Object signer certificate.
    pub x509_certificate_binding: Option<VerifiedX509CertificateBinding>,
}

/// Verify and validate a signed Request Object for wallet processing.
pub fn verify_signed_request_object(
    verifier: &impl RequestObjectSignatureVerifier,
    jwt: &str,
    expected_origin: Option<&str>,
    now_unix: u64,
) -> Result<VerifiedWalletRequest, WalletError> {
    let request = verifier.verify_request_object(jwt, now_unix)?;
    let evidence = WalletRequestTrustEvidence {
        verifier_attestation: verifier.verified_verifier_attestation(jwt)?,
        client_metadata_reference: verifier.verified_client_metadata_reference(jwt)?,
        x509_certificate_binding: verifier.verified_x509_certificate_binding(jwt)?,
    };
    validate_wallet_request_object_with_evidence(&request, expected_origin, now_unix, &evidence)?;
    Ok(VerifiedWalletRequest { request })
}

/// Verify a by-value Request Object transport and enforce transport bindings.
pub fn verify_request_transport(
    verifier: &impl RequestObjectSignatureVerifier,
    transport: AuthorizationRequestTransport,
    expected_origin: Option<&str>,
    now_unix: u64,
) -> Result<VerifiedWalletRequest, WalletError> {
    let AuthorizationRequestTransport::RequestJwt {
        jwt,
        expected_client_id,
        expected_wallet_nonce,
    } = transport
    else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    };

    let request = verifier.verify_request_object(&jwt, now_unix)?;
    validate_transport_client_id_binding(expected_client_id.as_deref(), &request)?;
    validate_transport_wallet_nonce_binding(expected_wallet_nonce.as_deref(), &request)?;
    let evidence = WalletRequestTrustEvidence {
        verifier_attestation: verifier.verified_verifier_attestation(&jwt)?,
        client_metadata_reference: verifier.verified_client_metadata_reference(&jwt)?,
        x509_certificate_binding: verifier.verified_x509_certificate_binding(&jwt)?,
    };
    validate_wallet_request_object_with_evidence(&request, expected_origin, now_unix, &evidence)?;
    Ok(VerifiedWalletRequest { request })
}

/// Validate wallet-enforced OpenID4VP Request Object claims.
pub fn validate_wallet_request_object(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
) -> Result<(), WalletError> {
    validate_wallet_request_object_with_trust(request, expected_origin, now_unix, None)
}

/// Validate wallet-enforced OpenID4VP Request Object claims with trust evidence.
pub fn validate_wallet_request_object_with_trust(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
    verifier_attestation: Option<&VerifiedVerifierAttestation>,
) -> Result<(), WalletError> {
    let evidence = WalletRequestTrustEvidence {
        verifier_attestation: verifier_attestation.cloned(),
        client_metadata_reference: None,
        x509_certificate_binding: None,
    };
    validate_wallet_request_object_with_evidence(request, expected_origin, now_unix, &evidence)
}

/// Validate wallet-enforced OpenID4VP Request Object claims with trust evidence.
pub fn validate_wallet_request_object_with_evidence(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
    evidence: &WalletRequestTrustEvidence,
) -> Result<(), WalletError> {
    let Some(client_id) = request.client_id.as_ref() else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidClientIdentifierPrefix,
        ));
    };

    match client_id.prefix {
        ClientIdentifierPrefix::None | ClientIdentifierPrefix::Origin => {
            return Err(WalletError::new(
                WalletErrorReason::InvalidClientIdentifierPrefix,
            ));
        }
        ClientIdentifierPrefix::RedirectUri => {
            return Err(WalletError::new(
                WalletErrorReason::InvalidClientIdentifierPrefix,
            ));
        }
        ClientIdentifierPrefix::OpenIdFederation
        | ClientIdentifierPrefix::DecentralizedIdentifier
        | ClientIdentifierPrefix::X509SanDns
        | ClientIdentifierPrefix::X509Hash => {}
        ClientIdentifierPrefix::VerifierAttestation => {
            let Some(attestation) = evidence.verifier_attestation.as_ref() else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidVerifierAttestation,
                ));
            };
            validate_verifier_attestation_binding(request, attestation)?;
        }
    }
    validate_response_endpoint_binding(
        request,
        client_id,
        evidence.x509_certificate_binding.as_ref(),
    )?;

    let Some(exp) = request.exp else {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    };
    if exp <= now_unix {
        return Err(WalletError::new(WalletErrorReason::RequestObjectExpired));
    }

    if request.nonce.is_empty() {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }

    if request.iat.is_some_and(|iat| iat > now_unix) {
        return Err(WalletError::new(
            WalletErrorReason::RequestObjectIssuedInFuture,
        ));
    }

    validate_client_metadata_reference_binding(
        request,
        evidence.client_metadata_reference.as_ref(),
        now_unix,
    )?;

    if let Some(origin) = expected_origin {
        let Some(expected_origins) = request.expected_origins.as_ref() else {
            return Err(WalletError::new(WalletErrorReason::ExpectedOriginMismatch));
        };
        if !expected_origins.iter().any(|expected| expected == origin) {
            return Err(WalletError::new(WalletErrorReason::ExpectedOriginMismatch));
        }
    }

    Ok(())
}

/// Enforce that a transport-level `client_id` matches signed Request Object claims.
pub fn validate_transport_client_id_binding(
    expected_client_id: Option<&str>,
    request: &AuthorizationRequestObject,
) -> Result<(), WalletError> {
    let Some(expected) = expected_client_id else {
        return Ok(());
    };
    let Some(actual) = request.client_id.as_ref() else {
        return Err(WalletError::new(
            WalletErrorReason::TransportClientIdentifierMismatch,
        ));
    };
    if actual.to_wire_value() != expected {
        return Err(WalletError::new(
            WalletErrorReason::TransportClientIdentifierMismatch,
        ));
    }
    Ok(())
}

/// Enforce that POST `request_uri` wallet_nonce is echoed by the signed Request Object.
pub fn validate_transport_wallet_nonce_binding(
    expected_wallet_nonce: Option<&str>,
    request: &AuthorizationRequestObject,
) -> Result<(), WalletError> {
    match (expected_wallet_nonce, request.wallet_nonce.as_deref()) {
        (Some(expected), Some(actual)) if constant_time_str_eq(expected, actual) => Ok(()),
        (Some(_), Some(_)) | (Some(_), None) => Err(WalletError::new(
            WalletErrorReason::TransportWalletNonceMismatch,
        )),
        (None, Some(_)) => Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce)),
        (None, None) => Ok(()),
    }
}

impl From<WalletError> for ProblemDetails {
    fn from(error: WalletError) -> Self {
        let kind = match error.reason() {
            WalletErrorReason::InvalidClientIdentifierPrefix => {
                ProblemKind::InvalidClientIdentifier
            }
            WalletErrorReason::ConflictingRequestObjectParameters
            | WalletErrorReason::DuplicateAuthorizationRequestParameter
            | WalletErrorReason::InvalidAuthorizationRequestTransport
            | WalletErrorReason::MissingWalletNonce
            | WalletErrorReason::ResponseEndpointClientIdentifierMismatch
            | WalletErrorReason::RequestObjectTooLarge
            | WalletErrorReason::TransportClientIdentifierMismatch
            | WalletErrorReason::TransportWalletNonceMismatch
            | WalletErrorReason::UnexpectedWalletNonce
            | WalletErrorReason::UnsupportedRequestUriMethod => ProblemKind::InvalidRequest,
            WalletErrorReason::ExpectedOriginMismatch
            | WalletErrorReason::InvalidMetadataReference
            | WalletErrorReason::InvalidRequestObject
            | WalletErrorReason::InvalidVerifierAttestation
            | WalletErrorReason::RequestObjectExpired
            | WalletErrorReason::RequestObjectIssuedInFuture => ProblemKind::InvalidRequestObject,
            WalletErrorReason::UnsupportedFeature => ProblemKind::UnsupportedFeature,
            WalletErrorReason::ZkDerivationFailed => ProblemKind::WalletUnavailable,
        };
        Self::from_kind(kind)
    }
}

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_types::{
        AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
    };
    use serde_json::Map as JsonMap;

    use crate::jar::{
        validate_wallet_request_object, validate_wallet_request_object_with_evidence,
        validate_wallet_request_object_with_trust, verify_request_transport,
        RequestObjectSignatureVerifier, WalletRequestTrustEvidence,
    };
    use crate::{AuthorizationRequestTransport, WalletError, WalletErrorReason};
    use crate::{
        VerifiedClientMetadataReference, VerifiedVerifierAttestation,
        VerifiedX509CertificateBinding,
    };

    fn signed_dc_api_request() -> AuthorizationRequestObject {
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
            iss: Some("client".to_owned()),
            aud: Some(vec!["wallet".to_owned()]),
            iat: Some(10),
            exp: Some(20),
        }
    }

    struct FixtureVerifier {
        request: AuthorizationRequestObject,
    }

    impl RequestObjectSignatureVerifier for FixtureVerifier {
        fn verify_request_object(
            &self,
            _jwt: &str,
            _now_unix: u64,
        ) -> Result<AuthorizationRequestObject, WalletError> {
            Ok(self.request.clone())
        }
    }

    #[test]
    fn rejects_unbound_origin() {
        let err = validate_wallet_request_object(
            &signed_dc_api_request(),
            Some("https://attacker.example"),
            11,
        )
        .expect_err("origin mismatch is rejected");

        assert_eq!(err.reason(), WalletErrorReason::ExpectedOriginMismatch);
    }

    #[test]
    fn rejects_transport_client_id_mismatch() {
        let err = verify_request_transport(
            &FixtureVerifier {
                request: signed_dc_api_request(),
            },
            AuthorizationRequestTransport::RequestJwt {
                jwt: "header.payload.signature".to_owned(),
                expected_client_id: Some("x509_san_dns:other.example".to_owned()),
                expected_wallet_nonce: None,
            },
            Some("https://rp.example"),
            11,
        )
        .expect_err("transport client_id mismatch is rejected");

        assert_eq!(
            err.reason(),
            WalletErrorReason::TransportClientIdentifierMismatch
        );
    }

    #[test]
    fn accepts_post_wallet_nonce_echo() {
        let mut request = signed_dc_api_request();
        request.wallet_nonce = Some("wallet-nonce".to_owned());

        verify_request_transport(
            &FixtureVerifier { request },
            AuthorizationRequestTransport::RequestJwt {
                jwt: "header.payload.signature".to_owned(),
                expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
                expected_wallet_nonce: Some("wallet-nonce".to_owned()),
            },
            Some("https://rp.example"),
            11,
        )
        .expect("wallet_nonce echo is accepted");
    }

    #[test]
    fn rejects_post_wallet_nonce_mismatch() {
        let mut request = signed_dc_api_request();
        request.wallet_nonce = Some("other".to_owned());

        let err = verify_request_transport(
            &FixtureVerifier { request },
            AuthorizationRequestTransport::RequestJwt {
                jwt: "header.payload.signature".to_owned(),
                expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
                expected_wallet_nonce: Some("wallet-nonce".to_owned()),
            },
            Some("https://rp.example"),
            11,
        )
        .expect_err("wallet_nonce mismatch is rejected");

        assert_eq!(
            err.reason(),
            WalletErrorReason::TransportWalletNonceMismatch
        );
    }

    #[test]
    fn rejects_unexpected_request_object_wallet_nonce() {
        let mut request = signed_dc_api_request();
        request.wallet_nonce = Some("unexpected".to_owned());

        let err = verify_request_transport(
            &FixtureVerifier { request },
            AuthorizationRequestTransport::RequestJwt {
                jwt: "header.payload.signature".to_owned(),
                expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
                expected_wallet_nonce: None,
            },
            Some("https://rp.example"),
            11,
        )
        .expect_err("wallet_nonce without POST binding is rejected");

        assert_eq!(err.reason(), WalletErrorReason::UnexpectedWalletNonce);
    }

    #[test]
    fn rejects_expired_request_object() {
        let mut request = signed_dc_api_request();
        request.exp = Some(10);

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("expired request object is rejected");

        assert_eq!(err.reason(), WalletErrorReason::RequestObjectExpired);
    }

    #[test]
    fn rejects_request_object_issued_in_future() {
        let mut request = signed_dc_api_request();
        request.iat = Some(12);

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("future iat is rejected");

        assert_eq!(err.reason(), WalletErrorReason::RequestObjectIssuedInFuture);
    }

    #[test]
    fn rejects_request_object_without_nonce() {
        let mut request = signed_dc_api_request();
        request.nonce.clear();

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("nonce is required for holder binding");

        assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
    }

    #[test]
    fn rejects_unsigned_client_identifier_prefix() {
        let mut request = signed_dc_api_request();
        request.client_id =
            Some(ClientIdentifier::parse("verifier.example").expect("test client id is valid"));

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("unprefixed signed client id is rejected");

        assert_eq!(
            err.reason(),
            WalletErrorReason::InvalidClientIdentifierPrefix
        );
    }

    #[test]
    fn accepts_trust_bound_signed_client_identifier_prefixes() {
        let prefixes = [
            "openid_federation:https://verifier.example",
            "decentralized_identifier:did:example:verifier",
            "x509_san_dns:verifier.example",
            "x509_hash:abcd",
        ];

        for client_id in prefixes {
            let mut request = signed_dc_api_request();
            request.client_id =
                Some(ClientIdentifier::parse(client_id).expect("test client id is valid"));

            validate_wallet_request_object(&request, Some("https://rp.example"), 11)
                .expect("final signed client identifier prefix is accepted");
        }
    }

    #[test]
    fn accepts_x509_san_dns_response_uri_host_binding() {
        let mut request = signed_dc_api_request();
        request.response_uri = Some("https://verifier.example:8443/response".to_owned());

        validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect("x509_san_dns endpoint host binding is accepted");
    }

    #[test]
    fn rejects_x509_san_dns_response_uri_host_mismatch() {
        let mut request = signed_dc_api_request();
        request.response_uri = Some("https://attacker.example/response".to_owned());

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("wallet rejects response endpoint not bound to client_id DNS name");

        assert_eq!(
            err.reason(),
            WalletErrorReason::ResponseEndpointClientIdentifierMismatch
        );
    }

    #[test]
    fn rejects_x509_hash_response_uri_without_certificate_binding() {
        let mut request = signed_dc_api_request();
        request.client_id =
            Some(ClientIdentifier::parse("x509_hash:abcd").expect("test client id is valid"));
        request.response_uri = Some("https://verifier.example/response".to_owned());

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("x509_hash endpoint requires verified certificate DNS evidence");

        assert_eq!(
            err.reason(),
            WalletErrorReason::ResponseEndpointClientIdentifierMismatch
        );
    }

    #[test]
    fn accepts_x509_hash_response_uri_with_certificate_binding() {
        let mut request = signed_dc_api_request();
        request.client_id =
            Some(ClientIdentifier::parse("x509_hash:abcd").expect("test client id is valid"));
        request.response_uri = Some("https://verifier.example/response".to_owned());
        let evidence = WalletRequestTrustEvidence {
            verifier_attestation: None,
            client_metadata_reference: None,
            x509_certificate_binding: Some(
                VerifiedX509CertificateBinding::new(vec!["verifier.example".to_owned()])
                    .expect("test certificate binding is valid"),
            ),
        };

        validate_wallet_request_object_with_evidence(
            &request,
            Some("https://rp.example"),
            11,
            &evidence,
        )
        .expect("x509_hash endpoint host can be bound to verified certificate SAN");
    }

    #[test]
    fn rejects_redirect_uri_prefix_for_signed_request_object() {
        let mut request = signed_dc_api_request();
        request.client_id = Some(
            ClientIdentifier::parse("redirect_uri:https://verifier.example/cb")
                .expect("test client id is valid"),
        );

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("redirect_uri prefix is not valid for signed request objects");

        assert_eq!(
            err.reason(),
            WalletErrorReason::InvalidClientIdentifierPrefix
        );
    }

    #[test]
    fn rejects_verifier_attestation_prefix_without_verified_attestation() {
        let mut request = signed_dc_api_request();
        request.client_id = Some(
            ClientIdentifier::parse("verifier_attestation:verifier.example")
                .expect("test client id is valid"),
        );

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("verifier_attestation prefix requires verified evidence");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn accepts_verifier_attestation_prefix_with_verified_attestation() {
        let mut request = signed_dc_api_request();
        request.client_id = Some(
            ClientIdentifier::parse("verifier_attestation:verifier.example")
                .expect("test client id is valid"),
        );
        request.redirect_uri = Some("https://verifier.example/cb".to_owned());
        let attestation = VerifiedVerifierAttestation::new(
            "verifier.example".to_owned(),
            Some(vec!["https://verifier.example/cb".to_owned()]),
        )
        .expect("test attestation is valid");

        validate_wallet_request_object_with_trust(
            &request,
            Some("https://rp.example"),
            11,
            Some(&attestation),
        )
        .expect("verified verifier attestation is accepted");
    }

    #[test]
    fn rejects_client_metadata_uri_without_verified_evidence() {
        let mut request = signed_dc_api_request();
        request.client_metadata_uri = Some("https://verifier.example/metadata.json".to_owned());

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("metadata reference requires verified evidence");

        assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
    }

    #[test]
    fn accepts_client_metadata_uri_with_fresh_verified_evidence() {
        let mut request = signed_dc_api_request();
        request.client_metadata_uri = Some("https://verifier.example/metadata.json".to_owned());
        let metadata = reallyme_openid4vp_types::ClientMetadata {
            raw: serde_json::Value::Object(JsonMap::new()),
        };
        let evidence = WalletRequestTrustEvidence {
            verifier_attestation: None,
            client_metadata_reference: Some(
                VerifiedClientMetadataReference::new(
                    "https://verifier.example/metadata.json".to_owned(),
                    metadata,
                    20,
                )
                .expect("test metadata evidence is valid"),
            ),
            x509_certificate_binding: None,
        };

        validate_wallet_request_object_with_evidence(
            &request,
            Some("https://rp.example"),
            11,
            &evidence,
        )
        .expect("fresh metadata evidence is accepted");
    }

    #[test]
    fn rejects_origin_client_identifier_prefix_for_signed_request_object() {
        let mut request = signed_dc_api_request();
        request.client_id = Some(
            ClientIdentifier::parse("origin:https://rp.example").expect("test client id is valid"),
        );

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("origin prefix is reserved for unsigned DC API processing");

        assert_eq!(
            err.reason(),
            WalletErrorReason::InvalidClientIdentifierPrefix
        );
    }

    #[test]
    fn rejects_missing_expected_origin_binding() {
        let mut request = signed_dc_api_request();
        request.expected_origins = None;

        let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect_err("expected_origins is required for origin-bound requests");

        assert_eq!(err.reason(), WalletErrorReason::ExpectedOriginMismatch);
    }
}
