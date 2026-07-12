// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use reallyme_openid4vp_dcql::QueryId;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::zeroize_json::zeroize_json_value;
use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason, TransactionDataHashAlgorithm};

/// Presentation value carried in a `vp_token` entry.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PresentationValue {
    /// Compact string presentation such as an SD-JWT VC presentation.
    Compact(String),
    /// JSON presentation value for formats with JSON-native responses.
    ///
    /// This is intentionally raw protocol JSON: OpenID4VP permits format-
    /// specific `vp_token` entries, and SDK/FFI layers must validate this value
    /// at their own external boundary before projecting it into platform types.
    Json(JsonValue),
}

impl fmt::Debug for PresentationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compact(value) => formatter
                .debug_struct("Compact")
                .field("byte_len", &value.len())
                .field("value", &"<redacted>")
                .finish(),
            Self::Json(_) => formatter
                .debug_struct("Json")
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

impl Zeroize for PresentationValue {
    fn zeroize(&mut self) {
        match self {
            Self::Compact(value) => value.zeroize(),
            Self::Json(value) => zeroize_json_value(value),
        }
    }
}

impl Drop for PresentationValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationValue {}

/// Final OpenID4VP `vp_token` shape keyed by DCQL Credential Query id.
pub type VpToken = BTreeMap<QueryId, Vec<PresentationValue>>;

/// OpenID4VP Authorization Response.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// DCQL-keyed VP Token object.
    pub vp_token: VpToken,
    /// OIDC state echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Base64url-encoded transaction-data hashes bound by holder presentations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes: Option<Vec<String>>,
    /// Algorithm used for `transaction_data_hashes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<TransactionDataHashAlgorithm>,
}

impl fmt::Debug for AuthorizationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationResponse")
            .field("query_count", &self.vp_token.len())
            .field("vp_token", &"<redacted>")
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .field(
                "transaction_data_hash_count",
                &self.transaction_data_hashes.as_ref().map(Vec::len),
            )
            .field(
                "transaction_data_hashes_alg",
                &self.transaction_data_hashes_alg,
            )
            .finish()
    }
}

impl Zeroize for AuthorizationResponse {
    fn zeroize(&mut self) {
        for presentations in self.vp_token.values_mut() {
            presentations.zeroize();
        }
        self.state.zeroize();
        self.transaction_data_hashes.zeroize();
    }
}

impl Drop for AuthorizationResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationResponse {}

impl AuthorizationResponse {
    /// Build a response for one DCQL Credential Query id.
    pub fn single(
        query_id: QueryId,
        presentations: Vec<PresentationValue>,
        state: Option<String>,
    ) -> Result<Self, OpenId4vpTypeError> {
        if presentations.is_empty() {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyPresentationList,
            ));
        }
        let mut vp_token = BTreeMap::new();
        vp_token.insert(query_id, presentations);
        Ok(Self {
            vp_token,
            state,
            transaction_data_hashes: None,
            transaction_data_hashes_alg: None,
        })
    }

    /// Attach transaction-data hash response binding.
    pub fn with_transaction_data_hashes(
        mut self,
        hashes: Vec<String>,
        algorithm: TransactionDataHashAlgorithm,
    ) -> Result<Self, OpenId4vpTypeError> {
        if hashes.is_empty() || hashes.iter().any(String::is_empty) {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyCollection,
            ));
        }
        self.transaction_data_hashes = Some(hashes);
        self.transaction_data_hashes_alg = Some(algorithm);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::QueryId;

    use crate::response::{AuthorizationResponse, PresentationValue};

    #[test]
    fn serializes_vp_token_as_dcql_keyed_object() {
        let response = AuthorizationResponse::single(
            QueryId::parse("my_credential").expect("test query id is valid"),
            vec![PresentationValue::Compact("eyJhbGci".to_owned())],
            None,
        )
        .expect("test response is valid");

        let json = serde_json::to_value(response).expect("response serializes");
        assert_eq!(json["vp_token"]["my_credential"][0], "eyJhbGci");
    }

    #[test]
    fn serializes_transaction_data_hashes_alg() {
        let response = AuthorizationResponse::single(
            QueryId::parse("my_credential").expect("test query id is valid"),
            vec![PresentationValue::Compact("eyJhbGci".to_owned())],
            None,
        )
        .expect("test response is valid")
        .with_transaction_data_hashes(
            vec!["abc".to_owned()],
            crate::TransactionDataHashAlgorithm::Sha256,
        )
        .expect("transaction data hashes attach");

        let json = serde_json::to_value(response).expect("response serializes");

        assert_eq!(json["transaction_data_hashes"][0], "abc");
        assert_eq!(json["transaction_data_hashes_alg"], "sha-256");
    }
}
