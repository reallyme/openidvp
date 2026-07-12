// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::AuthorizationRequestObject;

use crate::{WalletError, WalletErrorReason};

/// Wallet-trusted verifier attestation evidence extracted from the Request Object.
///
/// Signature verification, `typ=verifier-attestation+jwt`, `iss` trust,
/// temporal validation, and `cnf.jwk` proof-of-possession binding are owned by
/// the injected Request Object verifier. This value is the protocol-level
/// summary the wallet core needs after that trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedVerifierAttestation {
    /// Attestation `sub` claim. This is the unprefixed verifier identifier.
    pub subject: String,
    /// Optional attestation `redirect_uris` claim.
    pub redirect_uris: Option<Vec<String>>,
}

impl VerifiedVerifierAttestation {
    /// Build verified attestation evidence after structural validation.
    pub fn new(subject: String, redirect_uris: Option<Vec<String>>) -> Result<Self, WalletError> {
        if subject.is_empty() {
            return Err(WalletError::new(
                WalletErrorReason::InvalidVerifierAttestation,
            ));
        }
        if let Some(values) = redirect_uris.as_ref() {
            if values.is_empty() || values.iter().any(String::is_empty) {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidVerifierAttestation,
                ));
            }
        }
        Ok(Self {
            subject,
            redirect_uris,
        })
    }
}

/// Validate request claims against previously verified verifier attestation evidence.
pub fn validate_verifier_attestation_binding(
    request: &AuthorizationRequestObject,
    attestation: &VerifiedVerifierAttestation,
) -> Result<(), WalletError> {
    let Some(client_id) = request.client_id.as_ref() else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidClientIdentifierPrefix,
        ));
    };
    if client_id.identifier != attestation.subject {
        return Err(WalletError::new(
            WalletErrorReason::InvalidVerifierAttestation,
        ));
    }
    if let Some(redirect_uris) = attestation.redirect_uris.as_ref() {
        let Some(redirect_uri) = request.redirect_uri.as_deref() else {
            return Err(WalletError::new(
                WalletErrorReason::InvalidVerifierAttestation,
            ));
        };
        if !redirect_uris.iter().any(|allowed| allowed == redirect_uri) {
            return Err(WalletError::new(
                WalletErrorReason::InvalidVerifierAttestation,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientIdentifier, ResponseType};
    use serde_json::Map as JsonMap;

    use crate::verifier_attestation::{
        validate_verifier_attestation_binding, VerifiedVerifierAttestation,
    };
    use crate::WalletErrorReason;

    fn request() -> AuthorizationRequestObject {
        AuthorizationRequestObject {
            client_id: Some(
                ClientIdentifier::parse("verifier_attestation:verifier.example")
                    .expect("test client id is valid"),
            ),
            response_type: ResponseType::VpToken,
            response_mode: None,
            response_uri: None,
            redirect_uri: Some("https://verifier.example/cb".to_owned()),
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
            iss: Some("verifier_attestation:verifier.example".to_owned()),
            aud: Some(vec!["wallet".to_owned()]),
            iat: Some(10),
            exp: Some(20),
        }
    }

    #[test]
    fn accepts_matching_verifier_attestation_binding() {
        let attestation = VerifiedVerifierAttestation::new(
            "verifier.example".to_owned(),
            Some(vec!["https://verifier.example/cb".to_owned()]),
        )
        .expect("test attestation is valid");

        validate_verifier_attestation_binding(&request(), &attestation)
            .expect("matching attestation is valid");
    }

    #[test]
    fn rejects_verifier_attestation_subject_mismatch() {
        let attestation = VerifiedVerifierAttestation::new("other.example".to_owned(), None)
            .expect("test attestation is valid");

        let err = validate_verifier_attestation_binding(&request(), &attestation)
            .expect_err("subject mismatch is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn rejects_verifier_attestation_redirect_uri_mismatch() {
        let attestation = VerifiedVerifierAttestation::new(
            "verifier.example".to_owned(),
            Some(vec!["https://verifier.example/other".to_owned()]),
        )
        .expect("test attestation is valid");

        let err = validate_verifier_attestation_binding(&request(), &attestation)
            .expect_err("redirect_uri mismatch is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn rejects_empty_verifier_attestation_subject() {
        let err = VerifiedVerifierAttestation::new(String::new(), None)
            .expect_err("empty attestation subject is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn rejects_empty_verifier_attestation_redirect_uri_list() {
        let err = VerifiedVerifierAttestation::new("verifier.example".to_owned(), Some(vec![]))
            .expect_err("empty redirect_uri list is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn rejects_empty_verifier_attestation_redirect_uri_value() {
        let err = VerifiedVerifierAttestation::new(
            "verifier.example".to_owned(),
            Some(vec![String::new()]),
        )
        .expect_err("empty redirect_uri value is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn rejects_missing_request_redirect_uri_when_attestation_restricts_redirects() {
        let attestation = VerifiedVerifierAttestation::new(
            "verifier.example".to_owned(),
            Some(vec!["https://verifier.example/cb".to_owned()]),
        )
        .expect("test attestation is valid");
        let mut request = request();
        request.redirect_uri = None;

        let err = validate_verifier_attestation_binding(&request, &attestation)
            .expect_err("missing redirect_uri is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
    }

    #[test]
    fn accepts_missing_request_redirect_uri_without_attestation_redirect_restrictions() {
        let attestation = VerifiedVerifierAttestation::new("verifier.example".to_owned(), None)
            .expect("test attestation is valid");
        let mut request = request();
        request.redirect_uri = None;

        validate_verifier_attestation_binding(&request, &attestation)
            .expect("unrestricted attestation does not require redirect_uri");
    }
}
