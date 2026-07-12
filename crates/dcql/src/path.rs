// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value as JsonValue;

use crate::{ClaimsPath, ClaimsPathComponent, DcqlError, DcqlErrorReason};

/// JSON values selected by a claims path pointer.
#[derive(Debug, Clone)]
pub struct ProcessedClaimValues<'a> {
    values: Vec<&'a JsonValue>,
}

impl<'a> ProcessedClaimValues<'a> {
    /// Return selected JSON values.
    pub fn values(&self) -> &[&'a JsonValue] {
        &self.values
    }
}

/// Process a DCQL claims path pointer against a JSON credential.
pub fn process_json_claims_path<'a>(
    credential: &'a JsonValue,
    path: &ClaimsPath,
) -> Result<ProcessedClaimValues<'a>, DcqlError> {
    if path.components().is_empty() {
        return Err(DcqlError::new(DcqlErrorReason::InvalidClaimsPath));
    }

    let mut values = vec![credential];

    for component in path.components() {
        apply_path_component(component, &mut values)?;
        if values.is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
        }
    }

    Ok(ProcessedClaimValues { values })
}

fn apply_path_component(
    component: &ClaimsPathComponent,
    values: &mut Vec<&JsonValue>,
) -> Result<(), DcqlError> {
    let mut selected = Vec::with_capacity(values.len());
    for value in values.iter().copied() {
        match component {
            ClaimsPathComponent::Name(name) => {
                let JsonValue::Object(object) = value else {
                    return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
                };
                if let Some(next) = object.get(name) {
                    selected.push(next);
                }
            }
            ClaimsPathComponent::Index(index) => {
                let JsonValue::Array(array) = value else {
                    return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
                };
                let index = usize::try_from(*index)
                    .map_err(|_| DcqlError::new(DcqlErrorReason::InvalidClaimsPath))?;
                if let Some(next) = array.get(index) {
                    selected.push(next);
                }
            }
            ClaimsPathComponent::All => {
                let JsonValue::Array(array) = value else {
                    return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
                };
                selected.extend(array.iter());
            }
        }
    }
    values.clear();
    values.extend(selected);
    Ok(())
}
