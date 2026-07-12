// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::JSON_MEDIA_TYPE;
use serde_json::{json, Value as JsonValue};

use crate::{AuthorizationRequestLaunch, RuntimeError, RuntimeErrorReason, RuntimeHttpResponse};

/// Build the JSON response body consumed by the OIDF verifier flow driver.
pub fn authorization_request_launch_response(
    launch: &AuthorizationRequestLaunch,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let parameters: Vec<JsonValue> = launch
        .parameters
        .iter()
        .map(|parameter| {
            json!({
                "name": parameter.name.as_str(),
                "value": parameter.value,
            })
        })
        .collect();
    let body = json!({
        "authorization_endpoint": launch.authorization_endpoint,
        "parameters": parameters,
    });
    let encoded = serde_json::to_vec(&body)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::LaunchEncodingFailed))?;
    Ok(
        RuntimeHttpResponse::with_body(200, JSON_MEDIA_TYPE, encoded)
            .with_cache_control("no-store"),
    )
}
