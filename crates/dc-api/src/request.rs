// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{AuthorizationRequestObject, ResponseMode};
use serde::{Deserialize, Serialize};

use crate::{DcApiError, DcApiErrorReason};

/// OpenID4VP protocol identifier prefix used in Digital Credentials API requests.
pub const OPENID4VP_PROTOCOL_PREFIX: &str = "openid4vp-v1-";

/// OpenID4VP request kind encoded into the Digital Credentials API protocol id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DcApiRequestKind {
    /// Unsigned OpenID4VP request using `response_mode=dc_api`.
    Unsigned,
    /// Signed OpenID4VP Request Object using `response_mode=dc_api.jwt`.
    Signed,
    /// Multisigned request kind reserved by the OpenID4VP DC API appendix.
    Multisigned,
}

impl DcApiRequestKind {
    /// Return the protocol suffix.
    pub const fn as_suffix(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Signed => "signed",
            Self::Multisigned => "multisigned",
        }
    }
}

/// Digital Credentials API protocol identifier for OpenID4VP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcApiProtocol {
    /// OpenID4VP protocol version used by the W3C DC API binding.
    pub version: u8,
    /// Signedness and Request Object representation.
    pub kind: DcApiRequestKind,
}

impl DcApiProtocol {
    /// Construct the current OpenID4VP v1 protocol identifier.
    pub const fn v1(kind: DcApiRequestKind) -> Self {
        Self { version: 1, kind }
    }

    /// Return the protocol identifier string sent to the browser API.
    pub fn as_protocol_id(self) -> String {
        let mut protocol = OPENID4VP_PROTOCOL_PREFIX.to_owned();
        protocol.push_str(self.kind.as_suffix());
        protocol
    }
}

/// OpenID4VP request data carried in one Digital Credentials API entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DigitalCredentialGetRequestData {
    /// Expanded unsigned OpenID4VP parameters.
    Unsigned(Box<AuthorizationRequestObject>),
    /// Compact Request Object JWS carried as `{"request": "<jwt>"}`.
    Signed {
        /// Compact Request Object JWT.
        request: String,
    },
}

/// One `DigitalCredentialGetRequest` entry for OpenID4VP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DigitalCredentialGetRequest {
    /// Protocol identifier, such as `openid4vp-v1-signed`.
    pub protocol: String,
    /// OpenID4VP request data for the selected protocol.
    pub data: DigitalCredentialGetRequestData,
}

impl DigitalCredentialGetRequest {
    /// Build an unsigned OpenID4VP Digital Credentials API request entry.
    pub fn new(
        protocol: DcApiProtocol,
        data: AuthorizationRequestObject,
    ) -> Result<Self, DcApiError> {
        if protocol.version != 1 {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
        validate_dc_api_unsigned_request(protocol.kind, &data)?;
        Ok(Self {
            protocol: protocol.as_protocol_id(),
            data: DigitalCredentialGetRequestData::Unsigned(Box::new(data)),
        })
    }

    /// Build a signed OpenID4VP Digital Credentials API request entry.
    pub fn new_signed_request_object(
        protocol: DcApiProtocol,
        request: String,
    ) -> Result<Self, DcApiError> {
        if protocol.version != 1 {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
        if protocol.kind != DcApiRequestKind::Signed || request.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
        Ok(Self {
            protocol: protocol.as_protocol_id(),
            data: DigitalCredentialGetRequestData::Signed { request },
        })
    }
}

fn validate_dc_api_unsigned_request(
    kind: DcApiRequestKind,
    data: &AuthorizationRequestObject,
) -> Result<(), DcApiError> {
    match kind {
        DcApiRequestKind::Unsigned => {
            if data.client_id.is_some()
                || !matches!(
                    data.response_mode,
                    Some(ResponseMode::DcApi | ResponseMode::DcApiJwt)
                )
            {
                return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
            }
        }
        DcApiRequestKind::Signed | DcApiRequestKind::Multisigned => {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
    }
    Ok(())
}

/// Browser `CredentialRequestOptions.digital` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DigitalCredentialRequestOptions {
    /// Non-empty set of protocol requests.
    pub requests: Vec<DigitalCredentialGetRequest>,
}

impl DigitalCredentialRequestOptions {
    /// Construct request options for the browser Digital Credentials API.
    pub fn new(requests: Vec<DigitalCredentialGetRequest>) -> Result<Self, DcApiError> {
        if requests.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::EmptyRequestSet));
        }
        Ok(Self { requests })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
    use reallyme_openid4vp_types::{
        AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
    };
    use serde_json::Map as JsonMap;

    use crate::request::{
        DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest,
        DigitalCredentialRequestOptions,
    };
    use crate::DcApiErrorReason;

    fn request(response_mode: ResponseMode) -> AuthorizationRequestObject {
        AuthorizationRequestObject {
            client_id: None,
            response_type: ResponseType::VpToken,
            response_mode: Some(response_mode),
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
            expected_origins: None,
            iss: None,
            aud: None,
            iat: None,
            exp: None,
        }
    }

    #[test]
    fn accepts_unsigned_dc_api_request_without_client_id() {
        let request = request(ResponseMode::DcApi);

        let entry = DigitalCredentialGetRequest::new(
            DcApiProtocol::v1(DcApiRequestKind::Unsigned),
            request,
        )
        .expect("unsigned DC API request is valid");

        assert_eq!(entry.protocol, "openid4vp-v1-unsigned");
    }

    #[test]
    fn rejects_unsigned_dc_api_request_with_client_id() {
        let mut request = request(ResponseMode::DcApi);
        request.client_id = Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        );

        let err = DigitalCredentialGetRequest::new(
            DcApiProtocol::v1(DcApiRequestKind::Unsigned),
            request,
        )
        .expect_err("unsigned DC API request must not carry client_id");

        assert_eq!(err.reason(), DcApiErrorReason::InvalidProtocol);
    }

    #[test]
    fn accepts_unsigned_dc_api_request_with_encrypted_response_mode() {
        let request = request(ResponseMode::DcApiJwt);

        let entry = DigitalCredentialGetRequest::new(
            DcApiProtocol::v1(DcApiRequestKind::Unsigned),
            request,
        )
        .expect("unsigned DC API request may request encrypted response");

        assert_eq!(entry.protocol, "openid4vp-v1-unsigned");
    }

    #[test]
    fn accepts_signed_dc_api_request_object_data_shape() {
        let entry = DigitalCredentialGetRequest::new_signed_request_object(
            DcApiProtocol::v1(DcApiRequestKind::Signed),
            "header.payload.signature".to_owned(),
        )
        .expect("signed DC API request object is valid");
        let value = serde_json::to_value(&entry).expect("DC API request serializes");

        assert_eq!(entry.protocol, "openid4vp-v1-signed");
        assert_eq!(value["data"]["request"], "header.payload.signature");
    }

    #[test]
    fn rejects_expanded_data_for_signed_dc_api_request() {
        let err = DigitalCredentialGetRequest::new(
            DcApiProtocol::v1(DcApiRequestKind::Signed),
            request(ResponseMode::DcApiJwt),
        )
        .expect_err("signed DC API request uses data.request");

        assert_eq!(err.reason(), DcApiErrorReason::InvalidProtocol);
    }

    #[test]
    fn rejects_unsupported_protocol_version() {
        let err = DigitalCredentialGetRequest::new(
            DcApiProtocol {
                version: 2,
                kind: DcApiRequestKind::Unsigned,
            },
            request(ResponseMode::DcApi),
        )
        .expect_err("only v1 protocol identifiers are supported");

        assert_eq!(err.reason(), DcApiErrorReason::InvalidProtocol);
    }

    #[test]
    fn rejects_empty_request_options() {
        let err = DigitalCredentialRequestOptions::new(Vec::new())
            .expect_err("browser request set must be non-empty");

        assert_eq!(err.reason(), DcApiErrorReason::EmptyRequestSet);
    }
}
