// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{CredentialFormat, DcqlError, DcqlErrorReason, DcqlQuery, QueryId};

/// Maximum credential queries accepted in one DCQL request.
pub const MAX_CREDENTIAL_QUERIES: usize = 128;
/// Maximum claim queries accepted for one credential query.
pub const MAX_CLAIMS_PER_CREDENTIAL: usize = 256;
/// Maximum claims path components accepted for one claim query.
pub const MAX_CLAIMS_PATH_COMPONENTS: usize = 32;
/// Maximum claim-set alternatives accepted for one credential query.
pub const MAX_CLAIM_SETS_PER_CREDENTIAL: usize = 256;
/// Maximum total claim ids referenced by claim-set alternatives.
pub const MAX_CLAIM_SET_REFERENCES_PER_CREDENTIAL: usize = 1024;
/// Maximum credential-set constraints accepted in one DCQL request.
pub const MAX_CREDENTIAL_SETS: usize = 128;
/// Maximum options accepted in one credential-set constraint.
pub const MAX_CREDENTIAL_SET_OPTIONS: usize = 256;
/// Maximum total credential query ids referenced by one credential-set constraint.
pub const MAX_CREDENTIAL_SET_REFERENCES: usize = 1024;

/// Validate a parsed DCQL query.
pub fn validate_query(query: &DcqlQuery) -> Result<(), DcqlError> {
    if query.credentials.is_empty() {
        return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
    }
    if query.credentials.len() > MAX_CREDENTIAL_QUERIES {
        return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
    }

    let mut credential_ids = BTreeSet::new();
    for credential in &query.credentials {
        if !credential_ids.insert(credential.id.as_str()) {
            return Err(DcqlError::new(DcqlErrorReason::DuplicateIdentifier));
        }
        if credential.format.as_str().is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
        validate_meta(&credential.format, &credential.meta)?;
        validate_trusted_authorities(credential.trusted_authorities.as_deref())?;
        validate_claims(
            credential.claims.as_deref(),
            credential.claim_sets.as_deref(),
        )?;
    }

    validate_credential_sets(query, &credential_ids)?;
    Ok(())
}

fn validate_trusted_authorities(
    authorities: Option<&[crate::TrustedAuthorityQuery]>,
) -> Result<(), DcqlError> {
    let Some(authorities) = authorities else {
        return Ok(());
    };
    if authorities.is_empty() {
        return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
    }
    for authority in authorities {
        if authority.authority_type.is_empty() || authority.values.is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
        if authority.values.iter().any(String::is_empty) {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
    }
    Ok(())
}

fn validate_claims(
    claims: Option<&[crate::ClaimQuery]>,
    claim_sets: Option<&[crate::ClaimSet]>,
) -> Result<(), DcqlError> {
    if matches!(claims, Some(items) if items.is_empty()) {
        return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
    }
    if matches!(claims, Some(items) if items.len() > MAX_CLAIMS_PER_CREDENTIAL) {
        return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
    }
    if matches!(claim_sets, Some(items) if items.is_empty()) {
        return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
    }
    if matches!(claim_sets, Some(items) if items.len() > MAX_CLAIM_SETS_PER_CREDENTIAL) {
        return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
    }
    if claim_sets.is_some() && claims.is_none() {
        return Err(DcqlError::new(DcqlErrorReason::ClaimSetsWithoutClaims));
    }

    let mut claim_ids = BTreeSet::new();
    if let Some(claims) = claims {
        for claim in claims {
            if claim.path.components().is_empty() {
                return Err(DcqlError::new(DcqlErrorReason::InvalidClaimsPath));
            }
            if claim.path.components().len() > MAX_CLAIMS_PATH_COMPONENTS {
                return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
            }
            if matches!(claim.values.as_ref(), Some(values) if values.is_empty()) {
                return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
            }
            if let Some(id) = claim.id.as_ref() {
                if !claim_ids.insert(id.as_str()) {
                    return Err(DcqlError::new(DcqlErrorReason::DuplicateIdentifier));
                }
            }
        }
    }

    if let Some(claim_sets) = claim_sets {
        let mut reference_count = 0usize;
        for claim_set in claim_sets {
            if claim_set.0.is_empty() {
                return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
            }
            reference_count = reference_count
                .checked_add(claim_set.0.len())
                .ok_or(DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
            if reference_count > MAX_CLAIM_SET_REFERENCES_PER_CREDENTIAL {
                return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
            }
            for id in &claim_set.0 {
                if !claim_ids.contains(id.as_str()) {
                    return Err(DcqlError::new(DcqlErrorReason::UnknownReference));
                }
            }
        }
    }

    Ok(())
}

fn validate_meta(
    format: &CredentialFormat,
    meta: &JsonMap<String, JsonValue>,
) -> Result<(), DcqlError> {
    match format.as_str() {
        CredentialFormat::DC_SD_JWT => {
            if string_array(meta.get("vct_values")).is_none_or(|values| values.is_empty()) {
                return Err(DcqlError::new(DcqlErrorReason::InvalidCredentialMetadata));
            }
        }
        CredentialFormat::MSO_MDOC
            if meta
                .get("doctype_value")
                .and_then(JsonValue::as_str)
                .is_none() =>
        {
            return Err(DcqlError::new(DcqlErrorReason::InvalidCredentialMetadata));
        }
        CredentialFormat::MSO_MDOC => {}
        _ => {}
    }
    Ok(())
}

fn string_array(value: Option<&JsonValue>) -> Option<Vec<&str>> {
    value.and_then(JsonValue::as_array).map(|values| {
        values
            .iter()
            .filter_map(JsonValue::as_str)
            .collect::<Vec<_>>()
    })
}

fn validate_credential_sets(
    query: &DcqlQuery,
    credential_ids: &BTreeSet<&str>,
) -> Result<(), DcqlError> {
    let Some(credential_sets) = query.credential_sets.as_ref() else {
        return Ok(());
    };
    if credential_sets.is_empty() {
        return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
    }
    if credential_sets.len() > MAX_CREDENTIAL_SETS {
        return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
    }
    for credential_set in credential_sets {
        if credential_set.options.is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
        if credential_set.options.len() > MAX_CREDENTIAL_SET_OPTIONS {
            return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
        }
        let mut reference_count = 0usize;
        for option in &credential_set.options {
            reference_count = reference_count
                .checked_add(option.len())
                .ok_or(DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
            if reference_count > MAX_CREDENTIAL_SET_REFERENCES {
                return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
            }
            validate_credential_set_option(option, credential_ids)?;
        }
    }
    Ok(())
}

fn validate_credential_set_option(
    option: &[QueryId],
    credential_ids: &BTreeSet<&str>,
) -> Result<(), DcqlError> {
    if option.is_empty() {
        return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
    }
    for id in option {
        if !credential_ids.contains(id.as_str()) {
            return Err(DcqlError::new(DcqlErrorReason::UnknownReference));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{ClaimQuery, ClaimsPath, ClaimsPathComponent, CredentialQuery, CredentialSetQuery};

    use super::*;

    #[test]
    fn rejects_over_deep_claim_path() -> Result<(), DcqlError> {
        let mut query = valid_query()?;
        query.credentials[0].claims = Some(vec![ClaimQuery {
            id: None,
            path: ClaimsPath(vec![
                ClaimsPathComponent::Name("nested".to_owned());
                MAX_CLAIMS_PATH_COMPONENTS + 1
            ]),
            values: None,
        }]);

        assert_eq!(
            validate_query(&query).map_err(DcqlError::reason),
            Err(DcqlErrorReason::QueryTooLarge)
        );
        Ok(())
    }

    #[test]
    fn rejects_too_many_credential_sets() -> Result<(), DcqlError> {
        let mut query = valid_query()?;
        query.credential_sets = Some(vec![credential_set()?; MAX_CREDENTIAL_SETS + 1]);

        assert_eq!(
            validate_query(&query).map_err(DcqlError::reason),
            Err(DcqlErrorReason::QueryTooLarge)
        );
        Ok(())
    }

    #[test]
    fn rejects_too_many_credential_set_references() -> Result<(), DcqlError> {
        let mut query = valid_query()?;
        query.credential_sets = Some(vec![CredentialSetQuery {
            options: vec![vec![QueryId::parse("pid")?]; MAX_CREDENTIAL_SET_REFERENCES + 1],
            required: true,
        }]);

        assert_eq!(
            validate_query(&query).map_err(DcqlError::reason),
            Err(DcqlErrorReason::QueryTooLarge)
        );
        Ok(())
    }

    fn valid_query() -> Result<DcqlQuery, DcqlError> {
        Ok(DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid")?,
                format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())?,
                multiple: false,
                meta: JsonMap::from_iter([(
                    "vct_values".to_owned(),
                    json!(["https://credentials.example.com/identity_credential"]),
                )]),
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        })
    }

    fn credential_set() -> Result<CredentialSetQuery, DcqlError> {
        Ok(CredentialSetQuery {
            options: vec![vec![QueryId::parse("pid")?]],
            required: true,
        })
    }
}
