// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_dcql::DcqlQuery;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{ClientIdentifier, ClientMetadata, TransactionData};

/// Request Object retrieval method for `request_uri`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestUriMethod {
    /// Retrieve the Request Object with HTTP GET.
    #[serde(rename = "get")]
    Get,
    /// Retrieve the Request Object with HTTP POST.
    #[serde(rename = "post")]
    Post,
}

/// OpenID4VP response type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// `vp_token`.
    #[serde(rename = "vp_token")]
    VpToken,
    /// `vp_token id_token` when combined with SIOPv2.
    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,
}

/// OpenID4VP response mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// OAuth fragment response.
    #[serde(rename = "fragment")]
    Fragment,
    /// OAuth form post response.
    #[serde(rename = "form_post")]
    FormPost,
    /// OpenID4VP direct POST response.
    #[serde(rename = "direct_post")]
    DirectPost,
    /// OpenID4VP encrypted direct POST response.
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
    /// Digital Credentials API response.
    #[serde(rename = "dc_api")]
    DcApi,
    /// Digital Credentials API encrypted response.
    #[serde(rename = "dc_api.jwt")]
    DcApiJwt,
}

/// OpenID4VP Authorization Request Object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRequestObject {
    /// Full final-spec Client Identifier including any prefix.
    ///
    /// Signed requests require this value. Unsigned Digital Credentials API
    /// requests omit it and rely on browser-origin binding instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<ClientIdentifier>,
    /// OAuth response type.
    pub response_type: ResponseType,
    /// OAuth/OpenID4VP response mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<ResponseMode>,
    /// Verifier response endpoint for `direct_post` and `direct_post.jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,
    /// Redirect URI for front-channel responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Request nonce used for holder binding and replay prevention.
    pub nonce: String,
    /// Wallet nonce echoed by POST `request_uri` responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_nonce: Option<String>,
    /// OIDC state value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Final-spec DCQL query.
    pub dcql_query: DcqlQuery,
    /// Native transaction data request field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<TransactionData>>,
    /// Verifier metadata carried inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,
    /// Unsupported metadata-by-reference extension supplied by some ecosystems.
    ///
    /// OpenID4VP 1.0 final does not define `client_metadata_uri`. Wallet-side
    /// validation rejects this field unless the host injects fresh, trusted
    /// metadata evidence for the exact URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_metadata_uri: Option<String>,
    /// Origins authorized to invoke a signed Digital Credentials API request.
    ///
    /// OpenID4VP final treats `expected_origins` as required for signed
    /// Digital Credentials API requests. Transport adapters populate and
    /// enforce this with browser origin data; unsigned DC API requests omit
    /// `client_id` and do not use this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_origins: Option<Vec<String>>,
    /// Request Object issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Request Object audience.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_audience",
        skip_serializing_if = "Option::is_none"
    )]
    pub aud: Option<Vec<String>>,
    /// Issued-at time in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Expiration time in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

fn deserialize_optional_audience<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    match Option::<Audience>::deserialize(deserializer)? {
        Some(Audience::One(value)) => Ok(Some(vec![value])),
        Some(Audience::Many(values)) => Ok(Some(values)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::{RequestUriMethod, ResponseMode, ResponseType};

    #[test]
    fn request_enums_use_final_wire_values() {
        let response_type =
            serde_json::to_value(ResponseType::VpToken).expect("response type serializes");
        let response_mode =
            serde_json::to_value(ResponseMode::DirectPostJwt).expect("response mode serializes");
        let request_uri_method =
            serde_json::to_value(RequestUriMethod::Post).expect("method serializes");

        assert_eq!(response_type, "vp_token");
        assert_eq!(response_mode, "direct_post.jwt");
        assert_eq!(request_uri_method, "post");

        let dc_api: ResponseMode =
            serde_json::from_str("\"dc_api.jwt\"").expect("response mode parses");
        assert_eq!(dc_api, ResponseMode::DcApiJwt);
    }

    #[test]
    fn request_object_accepts_scalar_audience() {
        let json = serde_json::json!({
            "response_type": "vp_token",
            "nonce": "nonce",
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {}
                }]
            },
            "aud": "wallet"
        });

        let request: super::AuthorizationRequestObject =
            serde_json::from_value(json).expect("scalar aud deserializes");

        assert_eq!(request.aud, Some(vec!["wallet".to_owned()]));
    }
}
