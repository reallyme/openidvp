// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::{Map as JsonMap, Value as JsonValue};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::zeroize_json::zeroize_json_value;
use crate::{
    process_json_claims_path, validate_query, ClaimQuery, CredentialFormat, DcqlError,
    DcqlErrorReason, DcqlQuery, QueryId,
};

/// Wallet credential candidate supplied to the DCQL engine.
#[derive(Clone)]
pub struct CredentialCandidate {
    /// Wallet-local opaque credential id.
    pub id: EvaluationCredential,
    /// Credential format.
    pub format: CredentialFormat,
    /// Format metadata available before presentation.
    pub meta: JsonMap<String, JsonValue>,
    /// JSON claim view used for DCQL claim path processing.
    pub claims: JsonValue,
    /// Whether the credential can produce a cryptographic holder-binding proof.
    pub cryptographic_holder_binding: bool,
}

impl fmt::Debug for CredentialCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialCandidate")
            .field("id", &self.id)
            .field("format", &self.format)
            .field("meta", &"<redacted>")
            .field("claims", &"<redacted>")
            .field(
                "cryptographic_holder_binding",
                &self.cryptographic_holder_binding,
            )
            .finish()
    }
}

impl Zeroize for CredentialCandidate {
    fn zeroize(&mut self) {
        self.id.zeroize();
        let meta = core::mem::take(&mut self.meta);
        for (mut key, mut value) in meta {
            key.zeroize();
            zeroize_json_value(&mut value);
        }
        zeroize_json_value(&mut self.claims);
    }
}

impl Drop for CredentialCandidate {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialCandidate {}

/// Opaque wallet-local credential identifier in evaluation results.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvaluationCredential(String);

impl fmt::Debug for EvaluationCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvaluationCredential")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for EvaluationCredential {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for EvaluationCredential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EvaluationCredential {}

impl EvaluationCredential {
    /// Construct an evaluation credential id.
    pub fn new(value: String) -> Result<Self, DcqlError> {
        if value.is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
        Ok(Self(value))
    }

    /// Return the wallet-local id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Result of evaluating a DCQL query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// Credential query matches.
    pub matches: Vec<CredentialMatch>,
}

/// Credentials that satisfy one Credential Query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMatch {
    /// DCQL Credential Query id.
    pub query_id: QueryId,
    /// Wallet-local credential ids satisfying the query.
    pub credential_ids: Vec<EvaluationCredential>,
    /// Selected claim ids for this query, when the query used claim identifiers.
    pub selected_claim_ids: Vec<QueryId>,
}

/// Evaluate a validated DCQL query against wallet credential candidates.
pub fn evaluate_query(
    query: &DcqlQuery,
    candidates: &[CredentialCandidate],
) -> Result<Evaluation, DcqlError> {
    validate_query(query)?;

    let mut all_matches = Vec::with_capacity(query.credentials.len());
    for credential_query in &query.credentials {
        let mut credential_ids = Vec::new();
        let mut selected_claim_ids = Vec::new();
        for candidate in candidates {
            if let Some(candidate_claim_ids) =
                credential_matches_query(credential_query, candidate)?
            {
                credential_ids.push(candidate.id.clone());
                if selected_claim_ids.is_empty() {
                    selected_claim_ids.extend(candidate_claim_ids);
                }
                if !credential_query.multiple {
                    break;
                }
            }
        }
        all_matches.push(CredentialMatch {
            query_id: credential_query.id.clone(),
            credential_ids,
            selected_claim_ids,
        });
    }

    enforce_credential_sets(query, &all_matches)?;
    Ok(Evaluation {
        matches: all_matches,
    })
}

fn credential_matches_query(
    query: &crate::CredentialQuery,
    candidate: &CredentialCandidate,
) -> Result<Option<Vec<QueryId>>, DcqlError> {
    if query.format != candidate.format {
        return Ok(None);
    }
    if query.require_cryptographic_holder_binding && !candidate.cryptographic_holder_binding {
        return Ok(None);
    }
    if !meta_matches(&query.format, &query.meta, &candidate.meta) {
        return Ok(None);
    }

    let Some(claims) = query.claims.as_ref() else {
        return Ok(Some(Vec::new()));
    };

    let Some(claim_sets) = query.claim_sets.as_ref() else {
        let mut matching_claim_ids = Vec::new();
        for claim in claims {
            if !claim_matches_candidate(claim, &candidate.claims)? {
                return Ok(None);
            }
            if let Some(id) = claim.id.as_ref() {
                matching_claim_ids.push(id.clone());
            }
        }
        return Ok(Some(matching_claim_ids));
    };

    let mut claim_matches = BTreeMap::new();
    for claim in claims {
        let Some(id) = claim.id.as_ref() else {
            continue;
        };
        claim_matches.insert(
            id.as_str(),
            claim_matches_candidate(claim, &candidate.claims)?,
        );
    }

    for claim_set in claim_sets {
        let mut matching_claim_ids = Vec::with_capacity(claim_set.0.len());
        let mut set_matches = true;
        for claim_id in &claim_set.0 {
            let Some(matches) = claim_matches.get(claim_id.as_str()) else {
                return Err(DcqlError::new(DcqlErrorReason::UnknownReference));
            };

            if !matches {
                set_matches = false;
                break;
            }
            matching_claim_ids.push(claim_id.clone());
        }
        if set_matches {
            return Ok(Some(matching_claim_ids));
        }
    }

    Ok(None)
}

fn meta_matches(
    format: &CredentialFormat,
    expected: &JsonMap<String, JsonValue>,
    actual: &JsonMap<String, JsonValue>,
) -> bool {
    match format.as_str() {
        CredentialFormat::DC_SD_JWT => vct_values_match(expected, actual),
        CredentialFormat::MSO_MDOC => {
            let Some(expected_doctype) = expected.get("doctype_value").and_then(JsonValue::as_str)
            else {
                return false;
            };
            actual.get("doctype_value").and_then(JsonValue::as_str) == Some(expected_doctype)
        }
        _ => expected
            .iter()
            .all(|(key, value)| actual.get(key) == Some(value)),
    }
}

fn vct_values_match(
    expected: &JsonMap<String, JsonValue>,
    actual: &JsonMap<String, JsonValue>,
) -> bool {
    let Some(allowed) = json_string_array(expected.get("vct_values")) else {
        return false;
    };
    if allowed.is_empty() {
        return false;
    }
    if let Some(candidate_vct) = actual.get("vct").and_then(JsonValue::as_str) {
        return allowed.contains(&candidate_vct);
    }
    let Some(candidate_values) = json_string_array(actual.get("vct_values")) else {
        return false;
    };
    candidate_values
        .iter()
        .any(|candidate| allowed.iter().any(|allowed| allowed == candidate))
}

fn json_string_array(value: Option<&JsonValue>) -> Option<Vec<&str>> {
    let array = value?.as_array()?;
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let value = item.as_str()?;
        out.push(value);
    }
    Some(out)
}

fn claim_matches_candidate(
    claim: &ClaimQuery,
    credential_claims: &JsonValue,
) -> Result<bool, DcqlError> {
    let values = match process_json_claims_path(credential_claims, &claim.path) {
        Ok(values) => values,
        Err(error) if error.reason() == DcqlErrorReason::ClaimsPathMismatch => return Ok(false),
        Err(error) => return Err(error),
    };

    let Some(expected_values) = claim.values.as_ref() else {
        return Ok(true);
    };

    Ok(values.values().iter().copied().any(|actual| {
        expected_values
            .iter()
            .any(|expected| expected.matches_json(actual))
    }))
}

fn enforce_credential_sets(
    query: &DcqlQuery,
    matches: &[CredentialMatch],
) -> Result<(), DcqlError> {
    let matched_query_ids = matches
        .iter()
        .filter(|item| !item.credential_ids.is_empty())
        .map(|item| item.query_id.as_str())
        .collect::<BTreeSet<_>>();

    let Some(credential_sets) = query.credential_sets.as_ref() else {
        if matched_query_ids.len() == query.credentials.len() {
            return Ok(());
        }
        return Err(DcqlError::new(
            DcqlErrorReason::UnsatisfiedRequiredCredential,
        ));
    };

    for credential_set in credential_sets {
        if !credential_set.required {
            continue;
        }
        let satisfied = credential_set.options.iter().any(|option| {
            option
                .iter()
                .all(|query_id| matched_query_ids.contains(query_id.as_str()))
        });
        if !satisfied {
            return Err(DcqlError::new(
                DcqlErrorReason::UnsatisfiedRequiredCredential,
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use serde_json::json;

    use crate::evaluate::{evaluate_query, CredentialCandidate, EvaluationCredential, JsonMap};
    use crate::model::{CredentialFormat, DcqlQuery};
    use crate::DcqlErrorReason;

    fn sd_jwt_format() -> CredentialFormat {
        CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()).expect("test format is valid")
    }

    fn candidate() -> CredentialCandidate {
        CredentialCandidate {
            id: EvaluationCredential::new("cred-1".to_owned()).expect("test id is valid"),
            format: sd_jwt_format(),
            meta: JsonMap::from_iter([(
                "vct_values".to_owned(),
                json!(["https://credentials.example.com/identity_credential"]),
            )]),
            claims: json!({
                "first_name": "Ada",
                "last_name": "Lovelace",
                "age_over_18": true,
                "address": {
                    "postal_code": "SW1A"
                }
            }),
            cryptographic_holder_binding: true,
        }
    }

    #[test]
    fn evaluates_required_query_with_selected_claims() {
        let query = DcqlQuery::from_json_slice(
            br#"{
              "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                  "vct_values": ["https://credentials.example.com/identity_credential"]
                },
                "claims": [
                  {"id": "given", "path": ["first_name"], "values": ["Ada"]},
                  {"id": "family", "path": ["last_name"]}
                ]
              }]
            }"#,
        )
        .expect("test query is valid");

        let evaluation = evaluate_query(&query, &[candidate()]).expect("query is satisfiable");

        assert_eq!(evaluation.matches.len(), 1);
        assert_eq!(evaluation.matches[0].query_id.as_str(), "pid");
        assert_eq!(evaluation.matches[0].credential_ids[0].as_str(), "cred-1");
    }

    #[test]
    fn claim_sets_select_verifier_preferred_satisfied_option() {
        let query = DcqlQuery::from_json_slice(
            br#"{
              "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                  "vct_values": ["https://credentials.example.com/identity_credential"]
                },
                "claims": [
                  {"id": "given", "path": ["first_name"]},
                  {"id": "postal", "path": ["address", "postal_code"]},
                  {"id": "adult", "path": ["age_over_18"], "values": [true]}
                ],
                "claim_sets": [
                  ["given", "postal"],
                  ["adult"]
                ]
              }]
            }"#,
        )
        .expect("test query is valid");

        let evaluation = evaluate_query(&query, &[candidate()]).expect("query is satisfiable");
        let selected = &evaluation.matches[0].selected_claim_ids;

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].as_str(), "given");
        assert_eq!(selected[1].as_str(), "postal");
    }

    #[test]
    fn rejects_duplicate_query_ids() {
        let error = DcqlQuery::from_json_slice(
            br#"{
              "credentials": [
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}},
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}}
              ]
            }"#,
        )
        .expect_err("duplicate ids must be rejected");

        assert_eq!(error.reason(), DcqlErrorReason::DuplicateIdentifier);
    }

    #[test]
    fn enforces_required_credential_sets() {
        let query = DcqlQuery::from_json_slice(
            br#"{
              "credentials": [
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}},
                {"id": "address", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/address_credential"]}}
              ],
              "credential_sets": [{
                "options": [["pid", "address"]]
              }]
            }"#,
        )
        .expect("test query is structurally valid");

        let error = evaluate_query(&query, &[candidate()])
            .expect_err("required credential set must not be partially satisfiable");

        assert_eq!(
            error.reason(),
            DcqlErrorReason::UnsatisfiedRequiredCredential
        );
    }
}
