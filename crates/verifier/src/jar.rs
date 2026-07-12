// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

pub use reallyme_openid4vp_types::REQUEST_OBJECT_MEDIA_TYPE;
use reallyme_openid4vp_types::{
    classify_request_object_jwt, AuthorizationRequestObject, RequestObjectJwtKind,
};

use crate::{VerifierError, VerifierErrorReason};

/// Compact serialized JWT Request Object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactJwt(String);

impl CompactJwt {
    /// Construct a compact JWT after minimal structural validation.
    pub fn new(value: String) -> Result<Self, VerifierError> {
        let kind = classify_request_object_jwt(&value)
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRequestObject))?;
        if kind != RequestObjectJwtKind::Signed {
            return Err(VerifierError::new(
                VerifierErrorReason::InvalidRequestObject,
            ));
        }
        Ok(Self(value))
    }

    /// Return the compact JWT string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Signing boundary for RFC 9101 Request Objects.
///
/// Implementations belong in adapters backed by `reallyme-crypto` JOSE/COSE
/// primitives and injected key material. The protocol crate keeps this trait
/// network-free and side-effect-free so Request Object assembly stays auditable.
pub trait RequestObjectSigner: Send + Sync {
    /// Sign an OpenID4VP Authorization Request Object as a compact JWT.
    fn sign_request_object(
        &self,
        request: &AuthorizationRequestObject,
    ) -> Result<CompactJwt, VerifierError>;
}

/// Request Object claim validation policy derived from RFC 9101 processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JarPolicy {
    /// Require an issuer claim.
    pub require_issuer: bool,
    /// Require issuer to equal the final-prefixed client identifier.
    pub require_issuer_matches_client_id: bool,
    /// Require an audience claim.
    pub require_audience: bool,
    /// Require an issued-at claim.
    pub require_issued_at: bool,
    /// Require an expiration claim.
    pub require_expiration: bool,
    /// Maximum accepted Request Object lifetime, in seconds.
    pub max_lifetime_secs: Option<u64>,
    /// Accepted clock skew for issued-at values in the future.
    pub issued_at_future_skew_secs: u64,
}

impl Default for JarPolicy {
    fn default() -> Self {
        const DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS: u64 = 300;
        const DEFAULT_IAT_FUTURE_SKEW_SECS: u64 = 60;
        Self {
            require_issuer: true,
            require_issuer_matches_client_id: true,
            require_audience: true,
            require_issued_at: true,
            require_expiration: true,
            max_lifetime_secs: Some(DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS),
            issued_at_future_skew_secs: DEFAULT_IAT_FUTURE_SKEW_SECS,
        }
    }
}

/// Build and sign a Request Object through an injected signer.
pub fn build_signed_request_object(
    signer: &impl RequestObjectSigner,
    request: &AuthorizationRequestObject,
) -> Result<CompactJwt, VerifierError> {
    validate_jar_claims_for_signing(request, JarPolicy::default())?;
    signer.sign_request_object(request)
}

/// Validate static Request Object claims before signing when no verifier clock is needed.
pub fn validate_jar_claims_for_signing(
    request: &AuthorizationRequestObject,
    policy: JarPolicy,
) -> Result<(), VerifierError> {
    validate_jar_claims_without_clock(request, policy).map(|_| ())
}

/// Validate RFC 9101 Request Object temporal and identity claims.
///
/// Signature verification, JWT header algorithm policy, and `kid` to client
/// binding are intentionally delegated to `RequestObjectSigner` and
/// `RequestObjectVerifier` implementations backed by the JOSE stack.
pub fn validate_jar_claims(
    request: &AuthorizationRequestObject,
    now_unix: u64,
    policy: JarPolicy,
) -> Result<(), VerifierError> {
    let temporal = validate_jar_claims_without_clock(request, policy)?;
    if now_unix == 0 {
        return Err(VerifierError::new(VerifierErrorReason::ClockUnavailable));
    }

    let Some(exp) = temporal.expiration_unix else {
        return Ok(());
    };

    if exp <= now_unix {
        return Err(VerifierError::new(
            VerifierErrorReason::RequestObjectExpired,
        ));
    }

    if let Some(iat) = temporal.issued_at_unix {
        let Some(max_iat) = now_unix.checked_add(policy.issued_at_future_skew_secs) else {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        };
        if iat > max_iat {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct JarTemporalClaims {
    expiration_unix: Option<u64>,
    issued_at_unix: Option<u64>,
}

fn validate_jar_claims_without_clock(
    request: &AuthorizationRequestObject,
    policy: JarPolicy,
) -> Result<JarTemporalClaims, VerifierError> {
    if policy.require_issuer && request.iss.as_deref().is_none_or(str::is_empty) {
        return Err(VerifierError::new(VerifierErrorReason::MissingIssuer));
    }

    if policy.require_audience && request.aud.as_ref().is_none_or(Vec::is_empty) {
        return Err(VerifierError::new(VerifierErrorReason::MissingAudience));
    }

    let Some(client_id) = request.client_id.as_ref() else {
        return Err(VerifierError::new(
            VerifierErrorReason::MissingClientIdentifier,
        ));
    };

    if request.nonce.is_empty() {
        return Err(VerifierError::new(VerifierErrorReason::MissingNonce));
    }

    if policy.require_issuer_matches_client_id {
        let Some(issuer) = request.iss.as_deref() else {
            return Err(VerifierError::new(VerifierErrorReason::MissingIssuer));
        };
        if issuer != client_id.to_wire_value() {
            return Err(VerifierError::new(
                VerifierErrorReason::IssuerClientIdentifierMismatch,
            ));
        }
    }

    if policy.require_issued_at && request.iat.is_none() {
        return Err(VerifierError::new(VerifierErrorReason::MissingIssuedAt));
    }

    let Some(exp) = request.exp else {
        if policy.require_expiration {
            return Err(VerifierError::new(VerifierErrorReason::MissingExpiration));
        }
        return Ok(JarTemporalClaims {
            expiration_unix: None,
            issued_at_unix: request.iat,
        });
    };

    let iat = request.iat;

    if let Some(iat) = iat {
        if exp < iat {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        }
    }

    if let Some(max_lifetime_secs) = policy.max_lifetime_secs {
        let Some(iat) = iat else {
            return Ok(JarTemporalClaims {
                expiration_unix: Some(exp),
                issued_at_unix: None,
            });
        };
        let Some(lifetime) = exp.checked_sub(iat) else {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        };
        if lifetime > max_lifetime_secs {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectLifetimeTooLong,
            ));
        }
    }

    Ok(JarTemporalClaims {
        expiration_unix: Some(exp),
        issued_at_unix: iat,
    })
}

impl From<VerifierError> for reallyme_openid4vp_types::ProblemDetails {
    fn from(error: VerifierError) -> Self {
        let kind = match error.reason() {
            VerifierErrorReason::MissingIssuer
            | VerifierErrorReason::MissingAudience
            | VerifierErrorReason::MissingClientIdentifier
            | VerifierErrorReason::MissingExpiration
            | VerifierErrorReason::MissingIssuedAt
            | VerifierErrorReason::MissingNonce
            | VerifierErrorReason::ClockUnavailable
            | VerifierErrorReason::IssuerClientIdentifierMismatch
            | VerifierErrorReason::RequestObjectExpired
            | VerifierErrorReason::RequestObjectIssuedInFuture
            | VerifierErrorReason::RequestObjectLifetimeTooLong
            | VerifierErrorReason::InvalidRequestUri
            | VerifierErrorReason::InvalidRequestObject => {
                reallyme_openid4vp_types::ProblemKind::InvalidRequestObject
            }
            VerifierErrorReason::BindingExpired => {
                reallyme_openid4vp_types::ProblemKind::BindingExpired
            }
            VerifierErrorReason::SessionNotFound => {
                reallyme_openid4vp_types::ProblemKind::SessionNotFound
            }
            VerifierErrorReason::SessionMismatch => {
                reallyme_openid4vp_types::ProblemKind::SessionMismatch
            }
            VerifierErrorReason::EmptyPresentationList
            | VerifierErrorReason::EmptyVpToken
            | VerifierErrorReason::InvalidBinding
            | VerifierErrorReason::InvalidZkPresentation
            | VerifierErrorReason::VpTokenCardinalityMismatch
            | VerifierErrorReason::VpTokenQueryMismatch => {
                reallyme_openid4vp_types::ProblemKind::InvalidRequest
            }
            VerifierErrorReason::UnsupportedFormat => {
                reallyme_openid4vp_types::ProblemKind::UnsupportedFeature
            }
            VerifierErrorReason::HolderBindingAudienceMismatch
            | VerifierErrorReason::HolderBindingExpired
            | VerifierErrorReason::HolderBindingNonceMismatch
            | VerifierErrorReason::MissingHolderBindingClaim => {
                reallyme_openid4vp_types::ProblemKind::InvalidRequest
            }
        };
        Self::from_kind(kind)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientIdentifier, ResponseType};
    use serde_json::Map as JsonMap;

    use crate::jar::{validate_jar_claims, CompactJwt, JarPolicy};
    use crate::VerifierErrorReason;

    fn request(exp: u64, iat: u64) -> AuthorizationRequestObject {
        AuthorizationRequestObject {
            client_id: Some(
                ClientIdentifier::parse("x509_san_dns:verifier.example")
                    .expect("test client id is valid"),
            ),
            response_type: ResponseType::VpToken,
            response_mode: None,
            response_uri: None,
            redirect_uri: None,
            nonce: "nonce".to_owned(),
            wallet_nonce: None,
            state: None,
            dcql_query: DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: QueryId::parse("pid").expect("test query id is valid"),
                    format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
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
            expected_origins: None,
            iss: Some("x509_san_dns:verifier.example".to_owned()),
            aud: Some(vec!["wallet".to_owned()]),
            iat: Some(iat),
            exp: Some(exp),
        }
    }

    #[test]
    fn compact_jwt_rejects_malformed_request_object() {
        let err = CompactJwt::new("header.payload".to_owned())
            .expect_err("signed Request Object must be compact JWS");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestObject);
    }

    #[test]
    fn compact_jwt_rejects_encrypted_request_object() {
        let err = CompactJwt::new("eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn".to_owned())
            .expect_err("signer output must be compact JWS, not JWE");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestObject);
    }

    #[test]
    fn rejects_expired_request_object() {
        let err = validate_jar_claims(&request(10, 1), 11, JarPolicy::default())
            .expect_err("expired request object is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::RequestObjectExpired);
    }

    #[test]
    fn rejects_zero_clock_for_temporal_validation() {
        let err = validate_jar_claims(&request(20, 10), 0, JarPolicy::default())
            .expect_err("zero clock is not a temporal validation bypass");

        assert_eq!(err.reason(), VerifierErrorReason::ClockUnavailable);
    }

    #[test]
    fn rejects_issuer_client_id_mismatch() {
        let mut request = request(20, 10);
        request.iss = Some("x509_san_dns:other.example".to_owned());

        let err = validate_jar_claims(&request, 11, JarPolicy::default())
            .expect_err("issuer must match client_id");

        assert_eq!(
            err.reason(),
            VerifierErrorReason::IssuerClientIdentifierMismatch
        );
    }

    #[test]
    fn rejects_missing_audience() {
        let mut request = request(20, 10);
        request.aud = None;

        let err = validate_jar_claims(&request, 11, JarPolicy::default())
            .expect_err("audience is required by default policy");

        assert_eq!(err.reason(), VerifierErrorReason::MissingAudience);
    }

    #[test]
    fn rejects_missing_client_identifier() {
        let mut request = request(20, 10);
        request.client_id = None;

        let err = validate_jar_claims(&request, 11, JarPolicy::default())
            .expect_err("client_id is required");

        assert_eq!(err.reason(), VerifierErrorReason::MissingClientIdentifier);
    }

    #[test]
    fn rejects_missing_nonce() {
        let mut request = request(20, 10);
        request.nonce.clear();

        let err = validate_jar_claims(&request, 11, JarPolicy::default())
            .expect_err("nonce is required for holder binding");

        assert_eq!(err.reason(), VerifierErrorReason::MissingNonce);
    }

    #[test]
    fn rejects_missing_issued_at() {
        let mut request = request(20, 10);
        request.iat = None;

        let err = validate_jar_claims(&request, 11, JarPolicy::default())
            .expect_err("iat is required by default policy");

        assert_eq!(err.reason(), VerifierErrorReason::MissingIssuedAt);
    }

    #[test]
    fn rejects_issued_at_too_far_in_future() {
        let mut request = request(120, 100);

        let err = validate_jar_claims(&request, 11, JarPolicy::default())
            .expect_err("future iat beyond skew is rejected");

        assert_eq!(
            err.reason(),
            VerifierErrorReason::RequestObjectIssuedInFuture
        );

        request.iat = Some(71);
        validate_jar_claims(&request, 11, JarPolicy::default())
            .expect("iat within default skew is accepted");
    }

    #[test]
    fn rejects_expiration_before_issued_at() {
        let err = validate_jar_claims(&request(20, 30), 11, JarPolicy::default())
            .expect_err("exp before iat is rejected");

        assert_eq!(
            err.reason(),
            VerifierErrorReason::RequestObjectIssuedInFuture
        );
    }

    #[test]
    fn rejects_lifetime_longer_than_policy() {
        let err = validate_jar_claims(&request(400, 10), 11, JarPolicy::default())
            .expect_err("request object lifetime is bounded");

        assert_eq!(
            err.reason(),
            VerifierErrorReason::RequestObjectLifetimeTooLong
        );
    }
}
