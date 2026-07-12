// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use core::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{DcqlError, DcqlErrorReason};

/// Maximum query identifier length accepted by this implementation.
pub const MAX_QUERY_ID_BYTES: usize = 128;

/// Strong identifier for DCQL Credential Queries and claim entries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryId(String);

impl QueryId {
    /// Parse and validate a DCQL identifier.
    pub fn parse(value: &str) -> Result<Self, DcqlError> {
        if value.is_empty() || value.len() > MAX_QUERY_ID_BYTES {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(DcqlError::new(DcqlErrorReason::InvalidIdentifier));
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for QueryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for QueryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|_| D::Error::custom("invalid DCQL identifier"))
    }
}

/// Strong credential format identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialFormat(String);

impl CredentialFormat {
    /// IETF SD-JWT VC format identifier used by OpenID4VP final.
    pub const DC_SD_JWT: &'static str = "dc+sd-jwt";
    /// ISO mdoc format identifier used by OpenID4VP final.
    pub const MSO_MDOC: &'static str = "mso_mdoc";
    /// W3C JWT VC JSON format identifier.
    pub const JWT_VC_JSON: &'static str = "jwt_vc_json";
    /// W3C Linked Data Proof VP format identifier.
    pub const LDP_VP: &'static str = "ldp_vp";

    /// Construct a credential format identifier.
    pub fn new(value: String) -> Result<Self, DcqlError> {
        if value.is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
        Ok(Self(value))
    }

    /// Return the format identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A full DCQL query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// Non-empty list of requested credentials.
    pub credentials: Vec<CredentialQuery>,
    /// Optional credential set constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl DcqlQuery {
    /// Decode and validate a DCQL query from JSON bytes.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, DcqlError> {
        let query: Self = serde_json::from_slice(bytes)
            .map_err(|_| DcqlError::new(DcqlErrorReason::InvalidJson))?;
        crate::validate_query(&query)?;
        Ok(query)
    }
}

/// Credential Query object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// Identifier used as the key in the `vp_token` response object.
    pub id: QueryId,
    /// Requested credential format.
    pub format: CredentialFormat,
    /// Whether more than one matching credential may be returned.
    #[serde(default)]
    pub multiple: bool,
    /// Format-specific metadata constraints.
    pub meta: JsonMap<String, JsonValue>,
    /// Optional trusted authority hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthorityQuery>>,
    /// Whether a cryptographic holder binding proof is required.
    #[serde(default = "default_require_cryptographic_holder_binding")]
    pub require_cryptographic_holder_binding: bool,
    /// Optional requested claim constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,
    /// Optional claim-set alternatives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<ClaimSet>>,
}

const fn default_require_cryptographic_holder_binding() -> bool {
    true
}

/// Trusted Authorities Query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedAuthorityQuery {
    /// Trust authority type, such as `aki`, `etsi_tl`, or `openid_federation`.
    #[serde(rename = "type")]
    pub authority_type: String,
    /// Type-specific accepted values.
    pub values: Vec<String>,
}

/// Claims Query object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimQuery {
    /// Optional claim identifier. Required when referenced by `claim_sets`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<QueryId>,
    /// Claims path pointer.
    pub path: ClaimsPath,
    /// Optional exact value constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<ClaimValue>>,
}

/// A list of claim identifiers forming one acceptable claims option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimSet(pub Vec<QueryId>);

/// Claims path pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimsPath(pub Vec<ClaimsPathComponent>);

impl ClaimsPath {
    /// Return path components.
    pub fn components(&self) -> &[ClaimsPathComponent] {
        &self.0
    }
}

/// Claims path component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimsPathComponent {
    /// Select an object member by name.
    Name(String),
    /// Select one array element by zero-based index.
    Index(u64),
    /// Select all elements of the current array selection.
    All,
}

impl Serialize for ClaimsPathComponent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Name(name) => serializer.serialize_str(name),
            Self::Index(index) => serializer.serialize_u64(*index),
            Self::All => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for ClaimsPathComponent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ClaimsPathComponentVisitor)
    }
}

struct ClaimsPathComponentVisitor;

impl<'de> Visitor<'de> for ClaimsPathComponentVisitor {
    type Value = ClaimsPathComponent;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string, null, or non-negative integer")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(ClaimsPathComponent::Name(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(ClaimsPathComponent::Name(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(ClaimsPathComponent::Index(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(ClaimsPathComponent::All)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(ClaimsPathComponent::All)
    }
}

/// Claim values supported by DCQL value matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    /// String claim value.
    String(String),
    /// Integer claim value.
    Integer(i64),
    /// Boolean claim value.
    Boolean(bool),
}

impl ClaimValue {
    /// Compare this DCQL claim value with a JSON credential value.
    pub fn matches_json(&self, value: &JsonValue) -> bool {
        match (self, value) {
            (Self::String(expected), JsonValue::String(actual)) => expected == actual,
            (Self::Integer(expected), JsonValue::Number(actual)) => {
                actual.as_i64() == Some(*expected)
            }
            (Self::Boolean(expected), JsonValue::Bool(actual)) => expected == actual,
            _ => false,
        }
    }
}

/// Credential Set Query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// Alternative sets of Credential Query ids.
    pub options: Vec<Vec<QueryId>>,
    /// Whether the credential set is mandatory.
    #[serde(default = "default_credential_set_required")]
    pub required: bool,
}

const fn default_credential_set_required() -> bool {
    true
}
