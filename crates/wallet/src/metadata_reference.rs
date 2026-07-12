// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientMetadata};

use crate::{WalletError, WalletErrorReason};

/// Fresh, trusted verifier metadata resolved outside the pure wallet parser.
///
/// OpenID4VP 1.0 final carries verifier metadata inline in `client_metadata`.
/// Some deployments experiment with metadata-by-reference. This evidence type
/// lets identity-sdk or a service host inject a cache/trust decision without
/// teaching wallet request parsing to fetch network resources.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedClientMetadataReference {
    /// Exact metadata URI from the Request Object extension.
    pub uri: String,
    /// Metadata JSON obtained after host trust policy and cache validation.
    pub metadata: ClientMetadata,
    /// Absolute Unix timestamp after which this evidence is stale.
    pub expires_at_unix: u64,
}

impl VerifiedClientMetadataReference {
    /// Build verified metadata-reference evidence after structural checks.
    pub fn new(
        uri: String,
        metadata: ClientMetadata,
        expires_at_unix: u64,
    ) -> Result<Self, WalletError> {
        if uri.is_empty() || expires_at_unix == 0 {
            return Err(WalletError::new(
                WalletErrorReason::InvalidMetadataReference,
            ));
        }
        Ok(Self {
            uri,
            metadata,
            expires_at_unix,
        })
    }
}

/// Validate metadata-by-reference evidence against a Request Object.
pub fn validate_client_metadata_reference_binding(
    request: &AuthorizationRequestObject,
    evidence: Option<&VerifiedClientMetadataReference>,
    now_unix: u64,
) -> Result<(), WalletError> {
    let Some(uri) = request.client_metadata_uri.as_deref() else {
        return Ok(());
    };

    if request.client_metadata.is_some() {
        return Err(WalletError::new(
            WalletErrorReason::InvalidMetadataReference,
        ));
    }

    let Some(reference) = evidence else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidMetadataReference,
        ));
    };
    if reference.uri != uri || reference.expires_at_unix <= now_unix {
        return Err(WalletError::new(
            WalletErrorReason::InvalidMetadataReference,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_types::{
        AuthorizationRequestObject, ClientIdentifier, ClientMetadata, ResponseType,
    };
    use serde_json::{Map as JsonMap, Value as JsonValue};

    use crate::metadata_reference::{
        validate_client_metadata_reference_binding, VerifiedClientMetadataReference,
    };
    use crate::WalletErrorReason;

    fn metadata() -> ClientMetadata {
        ClientMetadata {
            raw: JsonValue::Object(JsonMap::new()),
        }
    }

    fn request() -> AuthorizationRequestObject {
        AuthorizationRequestObject {
            client_id: Some(
                ClientIdentifier::parse("x509_san_dns:verifier.example")
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
            client_metadata_uri: Some("https://verifier.example/metadata.json".to_owned()),
            expected_origins: None,
            iss: Some("x509_san_dns:verifier.example".to_owned()),
            aud: Some(vec!["wallet".to_owned()]),
            iat: Some(10),
            exp: Some(20),
        }
    }

    #[test]
    fn accepts_fresh_matching_metadata_reference() {
        let evidence = VerifiedClientMetadataReference::new(
            "https://verifier.example/metadata.json".to_owned(),
            metadata(),
            20,
        )
        .expect("test evidence is valid");

        validate_client_metadata_reference_binding(&request(), Some(&evidence), 10)
            .expect("fresh metadata evidence is accepted");
    }

    #[test]
    fn rejects_metadata_reference_without_verified_evidence() {
        let err = validate_client_metadata_reference_binding(&request(), None, 10)
            .expect_err("metadata reference requires verified evidence");

        assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
    }

    #[test]
    fn rejects_stale_metadata_reference_evidence() {
        let evidence = VerifiedClientMetadataReference::new(
            "https://verifier.example/metadata.json".to_owned(),
            metadata(),
            10,
        )
        .expect("test evidence is valid");

        let err = validate_client_metadata_reference_binding(&request(), Some(&evidence), 10)
            .expect_err("stale metadata evidence is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
    }

    #[test]
    fn rejects_conflicting_inline_and_referenced_metadata() {
        let mut request = request();
        request.client_metadata = Some(metadata());
        let evidence = VerifiedClientMetadataReference::new(
            "https://verifier.example/metadata.json".to_owned(),
            metadata(),
            20,
        )
        .expect("test evidence is valid");

        let err = validate_client_metadata_reference_binding(&request, Some(&evidence), 10)
            .expect_err("ambiguous metadata source is rejected");

        assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
    }
}
