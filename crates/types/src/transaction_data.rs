// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::zeroize_json::zeroize_json_value;
use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};

/// Maximum JSON nesting canonicalized by this crate's transaction-data helper.
pub const MAX_TRANSACTION_DATA_JSON_DEPTH: usize = 128;

/// Transaction data object from OpenID4VP 1.0 final.
#[derive(Clone, PartialEq)]
pub struct TransactionData {
    /// Application or profile-defined transaction type.
    pub transaction_type: String,
    /// Credential ids this transaction data applies to.
    pub credential_ids: Vec<String>,
    /// Profile-specific transaction data payload.
    pub payload: JsonValue,
}

impl fmt::Debug for TransactionData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionData")
            .field("transaction_type", &self.transaction_type)
            .field("credential_id_count", &self.credential_ids.len())
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl Zeroize for TransactionData {
    fn zeroize(&mut self) {
        self.transaction_type.zeroize();
        self.credential_ids.zeroize();
        zeroize_json_value(&mut self.payload);
    }
}

impl Drop for TransactionData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TransactionData {}

impl Serialize for TransactionData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = encoded_transaction_data_string(self)
            .map_err(|_| serde::ser::Error::custom("invalid transaction data"))?;
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for TransactionData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        decode_transaction_data_string(&encoded)
            .map_err(|_| serde::de::Error::custom("invalid transaction data"))
    }
}

/// Transaction data hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionDataHashAlgorithm {
    /// SHA-256.
    #[serde(rename = "sha-256")]
    Sha256,
}

/// Fixed-size transaction data digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionDataHash {
    /// Hash algorithm.
    pub algorithm: TransactionDataHashAlgorithm,
    /// Digest bytes.
    pub digest: [u8; 32],
}

impl TransactionDataHash {
    /// Compute SHA-256 over caller-provided canonical transaction data bytes.
    pub fn sha256(canonical_transaction_data: &[u8]) -> Result<Self, OpenId4vpTypeError> {
        if canonical_transaction_data.is_empty() {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyValue,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(canonical_transaction_data);
        let digest = hasher.finalize().into();
        Ok(Self {
            algorithm: TransactionDataHashAlgorithm::Sha256,
            digest,
        })
    }

    /// Compute SHA-256 over the exact received final-spec transaction data string.
    ///
    /// OpenID4VP hashes the base64url-encoded `transaction_data` member, not
    /// the decoded JSON object. This method validates the encoded value before
    /// hashing so callers can keep wire-level interop without accepting
    /// malformed transaction data.
    pub fn sha256_received_transaction_data_string(
        encoded: &str,
    ) -> Result<Self, OpenId4vpTypeError> {
        decode_transaction_data_string(encoded)?;
        Self::sha256(encoded.as_bytes())
    }

    /// Compute SHA-256 over this crate's deterministic transaction data encoding.
    ///
    /// Prefer [`Self::sha256_received_transaction_data_string`] when verifying
    /// data received over the wire. This helper is for locally constructed
    /// transaction data where no original encoded string exists.
    pub fn sha256_transaction_data(
        transaction_data: &TransactionData,
    ) -> Result<Self, OpenId4vpTypeError> {
        let encoded = encoded_transaction_data_string(transaction_data)?;
        Self::sha256(encoded.as_bytes())
    }
}

/// Encode a transaction data object as the final-spec base64url string.
pub fn encoded_transaction_data_string(
    transaction_data: &TransactionData,
) -> Result<String, OpenId4vpTypeError> {
    let canonical = canonical_transaction_data_bytes(transaction_data)?;
    Ok(bytes_to_base64url(&canonical))
}

/// Decode one final-spec base64url transaction data string.
pub fn decode_transaction_data_string(
    encoded: &str,
) -> Result<TransactionData, OpenId4vpTypeError> {
    if encoded.is_empty() {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::EmptyValue,
        ));
    }
    let bytes = base64url_to_bytes(encoded)
        .map_err(|_| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?;
    let object: JsonMap<String, JsonValue> = serde_json::from_slice(&bytes)
        .map_err(|_| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?;
    transaction_data_from_object(object)
}

/// Build deterministic JSON bytes for OpenID4VP transaction data hashing.
pub fn canonical_transaction_data_bytes(
    transaction_data: &TransactionData,
) -> Result<Vec<u8>, OpenId4vpTypeError> {
    validate_transaction_data(transaction_data)?;
    let json = transaction_data_object_value(transaction_data);
    let canonical = canonicalize_json_checked(&json)?;
    serde_json::to_vec(&canonical)
        .map_err(|_| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::SerializationFailed))
}

fn transaction_data_object_value(transaction_data: &TransactionData) -> JsonValue {
    let mut map = JsonMap::new();
    map.insert(
        "type".to_owned(),
        JsonValue::String(transaction_data.transaction_type.clone()),
    );
    map.insert(
        "credential_ids".to_owned(),
        JsonValue::Array(
            transaction_data
                .credential_ids
                .iter()
                .cloned()
                .map(JsonValue::String)
                .collect(),
        ),
    );
    match &transaction_data.payload {
        JsonValue::Object(payload) => {
            for (key, value) in payload {
                if key != "type" && key != "credential_ids" {
                    map.insert(key.clone(), value.clone());
                }
            }
        }
        payload => {
            map.insert("payload".to_owned(), payload.clone());
        }
    }
    JsonValue::Object(map)
}

fn transaction_data_from_object(
    mut object: JsonMap<String, JsonValue>,
) -> Result<TransactionData, OpenId4vpTypeError> {
    let transaction_type = object
        .remove("type")
        .and_then(|value| match value {
            JsonValue::String(value) => Some(value),
            _ => None,
        })
        .ok_or_else(|| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?;
    let credential_ids = object
        .remove("credential_ids")
        .and_then(|value| match value {
            JsonValue::Array(values) => Some(values),
            _ => None,
        })
        .ok_or_else(|| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?
        .into_iter()
        .map(|value| match value {
            JsonValue::String(value) => Ok(value),
            _ => Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::InvalidEncoding,
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let legacy_payload_only = object.len() == 1 && object.contains_key("payload");
    let payload = if legacy_payload_only {
        object
            .remove("payload")
            .ok_or_else(|| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?
    } else {
        JsonValue::Object(object)
    };
    let transaction_data = TransactionData {
        transaction_type,
        credential_ids,
        payload,
    };
    validate_transaction_data(&transaction_data)?;
    Ok(transaction_data)
}

fn validate_transaction_data(transaction_data: &TransactionData) -> Result<(), OpenId4vpTypeError> {
    if transaction_data.transaction_type.is_empty()
        || transaction_data.credential_ids.is_empty()
        || transaction_data.credential_ids.iter().any(String::is_empty)
    {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::EmptyValue,
        ));
    }
    Ok(())
}

/// Deterministically normalize JSON by sorting object keys recursively.
///
/// This ports the useful meproto hashing helper without carrying forward the
/// removed Presentation Exchange engine. It is intentionally modest rather than
/// a full JCS implementation; callers that need profile-specific canonical
/// numeric formatting should inject canonical bytes directly into
/// `TransactionDataHash::sha256`.
///
/// Values deeper than [`MAX_TRANSACTION_DATA_JSON_DEPTH`] canonicalize to JSON
/// null in this infallible helper. Hashing APIs use the checked path and reject
/// over-deep input instead.
pub fn canonicalize_json(value: &JsonValue) -> JsonValue {
    canonicalize_json_with_depth(value, 0).unwrap_or(JsonValue::Null)
}

fn canonicalize_json_checked(value: &JsonValue) -> Result<JsonValue, OpenId4vpTypeError> {
    canonicalize_json_with_depth(value, 0)
}

fn canonicalize_json_with_depth(
    value: &JsonValue,
    depth: usize,
) -> Result<JsonValue, OpenId4vpTypeError> {
    if depth > MAX_TRANSACTION_DATA_JSON_DEPTH {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::JsonDepthExceeded,
        ));
    }
    match value {
        JsonValue::Array(values) => Ok(JsonValue::Array(
            values
                .iter()
                .map(|value| canonicalize_json_with_depth(value, next_depth(depth)?))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        JsonValue::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            let mut out = JsonMap::new();
            for key in keys {
                if let Some(value) = map.get(key) {
                    out.insert(
                        key.clone(),
                        canonicalize_json_with_depth(value, next_depth(depth)?)?,
                    );
                }
            }
            Ok(JsonValue::Object(out))
        }
        other => Ok(other.clone()),
    }
}

fn next_depth(depth: usize) -> Result<usize, OpenId4vpTypeError> {
    depth
        .checked_add(1)
        .ok_or_else(|| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::JsonDepthExceeded))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use serde_json::json;

    use crate::transaction_data::{
        canonical_transaction_data_bytes, canonicalize_json, decode_transaction_data_string,
        encoded_transaction_data_string, TransactionData, TransactionDataHash,
        TransactionDataHashAlgorithm, MAX_TRANSACTION_DATA_JSON_DEPTH,
    };
    use crate::OpenId4vpTypeErrorReason;

    #[test]
    fn canonicalizes_nested_json_keys_for_hashing() {
        let left = canonicalize_json(&json!({"b": 2, "a": {"d": 4, "c": 3}}));
        let right = canonicalize_json(&json!({"a": {"c": 3, "d": 4}, "b": 2}));

        let left_bytes = serde_json::to_vec(&left).expect("canonical JSON serializes");
        let right_bytes = serde_json::to_vec(&right).expect("canonical JSON serializes");
        assert_eq!(left_bytes, right_bytes);
    }

    #[test]
    fn hashes_transaction_data_from_canonical_json() {
        let transaction_data = TransactionData {
            transaction_type: "payment".to_owned(),
            credential_ids: vec!["pid".to_owned()],
            payload: json!({"amount": "10.00", "currency": "EUR"}),
        };

        let hash = TransactionDataHash::sha256_transaction_data(&transaction_data)
            .expect("transaction data hashes");

        assert_eq!(hash.algorithm, TransactionDataHashAlgorithm::Sha256);
        assert_eq!(hash.digest.len(), 32);
    }

    #[test]
    fn hashes_received_transaction_data_string_without_recanonicalizing() {
        let encoded = reallyme_codec::base64url::bytes_to_base64url(
            br#"{
              "payload": {"currency": "EUR", "amount": "10.00"},
              "credential_ids": ["pid"],
              "type": "payment"
            }"#,
        );

        let received_hash = TransactionDataHash::sha256_received_transaction_data_string(&encoded)
            .expect("received transaction data hashes");
        let direct_hash =
            TransactionDataHash::sha256(encoded.as_bytes()).expect("encoded string hashes");
        let decoded = decode_transaction_data_string(&encoded).expect("transaction data decodes");
        let local_hash = TransactionDataHash::sha256_transaction_data(&decoded)
            .expect("locally constructed transaction data hashes");

        assert_eq!(received_hash, direct_hash);
        assert_ne!(received_hash, local_hash);
    }

    #[test]
    fn serializes_transaction_data_as_base64url_string() {
        let transaction_data = TransactionData {
            transaction_type: "payment".to_owned(),
            credential_ids: vec!["pid".to_owned()],
            payload: json!({"amount": "10.00"}),
        };

        let encoded =
            encoded_transaction_data_string(&transaction_data).expect("transaction data encodes");
        let json = serde_json::to_value(&transaction_data).expect("transaction data serializes");
        let decoded = decode_transaction_data_string(&encoded).expect("transaction data decodes");

        assert_eq!(json, json!(encoded));
        assert_eq!(decoded, transaction_data);
    }

    #[test]
    fn decodes_spec_shaped_transaction_data_object() {
        let encoded = reallyme_codec::base64url::bytes_to_base64url(
            br#"{"type":"payment","credential_ids":["pid"],"amount":"10.00","currency":"EUR"}"#,
        );

        let decoded =
            decode_transaction_data_string(&encoded).expect("spec-shaped transaction data decodes");

        assert_eq!(decoded.transaction_type, "payment");
        assert_eq!(decoded.credential_ids, vec!["pid"]);
        assert_eq!(
            decoded.payload,
            json!({"amount": "10.00", "currency": "EUR"})
        );
    }

    #[test]
    fn rejects_empty_transaction_data_credential_ids() {
        let encoded = reallyme_codec::base64url::bytes_to_base64url(
            br#"{"type":"payment","credential_ids":[],"amount":"10.00"}"#,
        );

        let err = decode_transaction_data_string(&encoded)
            .expect_err("credential_ids is required and non-empty");

        assert_eq!(err.reason(), OpenId4vpTypeErrorReason::EmptyValue);
    }

    #[test]
    fn rejects_over_deep_transaction_data_json() {
        let mut payload = json!(null);
        for _ in 0..=MAX_TRANSACTION_DATA_JSON_DEPTH {
            payload = json!([payload]);
        }
        let transaction_data = TransactionData {
            transaction_type: "payment".to_owned(),
            credential_ids: vec!["pid".to_owned()],
            payload,
        };

        let err = canonical_transaction_data_bytes(&transaction_data)
            .expect_err("transaction data canonicalization has its own depth guard");

        assert_eq!(err.reason(), OpenId4vpTypeErrorReason::JsonDepthExceeded);
    }
}
