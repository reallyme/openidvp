// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::REQUEST_OBJECT_MEDIA_TYPE;

use crate::compare_secret::constant_time_str_eq;
use crate::define_http_message::{RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse};
use crate::parse_form_urlencoded::{parse_form_urlencoded, required_unique_field};
use crate::{RuntimeError, RuntimeErrorReason};

const FORM_URLENCODED_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
const NO_STORE_CACHE_CONTROL: &str = "no-store";
const WALLET_NONCE_FIELD: &str = "wallet_nonce";

/// Serve a hosted RFC 9101 Request Object for OpenID4VP `request_uri`.
pub fn serve_request_object_http(
    request: &RuntimeHttpRequest,
    request_object_jwt: &str,
    expected_wallet_nonce: Option<&str>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    validate_accept_header(request.accept.as_deref(), REQUEST_OBJECT_MEDIA_TYPE)?;
    match request.method {
        RuntimeHttpMethod::Get => {
            if !request.body.is_empty() {
                return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
            }
        }
        RuntimeHttpMethod::Post => {
            validate_content_type(request.content_type.as_deref(), FORM_URLENCODED_MEDIA_TYPE)?;
            let pairs = parse_form_urlencoded(&request.body)?;
            let wallet_nonce = required_unique_field(&pairs, WALLET_NONCE_FIELD)?;
            if let Some(expected) = expected_wallet_nonce {
                if !constant_time_str_eq(&wallet_nonce, expected) {
                    return Err(RuntimeError::new(RuntimeErrorReason::WalletNonceMismatch));
                }
            }
        }
    }

    if request_object_jwt.is_empty() {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }

    Ok(RuntimeHttpResponse::with_body(
        200,
        REQUEST_OBJECT_MEDIA_TYPE,
        request_object_jwt.as_bytes().to_vec(),
    )
    .with_cache_control(NO_STORE_CACHE_CONTROL))
}

pub(crate) fn validate_content_type(
    actual: Option<&str>,
    expected: &str,
) -> Result<(), RuntimeError> {
    let Some(actual) = actual else {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidContentType));
    };
    let media_type = match actual.split(';').next() {
        Some(value) => value.trim(),
        None => "",
    };
    if media_type.eq_ignore_ascii_case(expected) {
        return Ok(());
    }
    Err(RuntimeError::new(RuntimeErrorReason::InvalidContentType))
}

pub(crate) fn validate_accept_header(
    actual: Option<&str>,
    produced: &str,
) -> Result<(), RuntimeError> {
    let Some(actual) = actual else {
        return Ok(());
    };
    for item in actual.split(',') {
        let media_range = match item.split(';').next() {
            Some(value) => value.trim(),
            None => "",
        };
        if media_range == "*/*" || media_range == "application/*" {
            return Ok(());
        }
        if media_range.eq_ignore_ascii_case(produced) {
            return Ok(());
        }
    }
    Err(RuntimeError::new(RuntimeErrorReason::InvalidAcceptHeader))
}

pub(crate) const fn form_urlencoded_media_type() -> &'static str {
    FORM_URLENCODED_MEDIA_TYPE
}
