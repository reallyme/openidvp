// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{RequestUriMethod, REQUEST_OBJECT_MEDIA_TYPE};

use crate::{HttpAdapterError, HttpAdapterErrorReason};

/// Content type for `request_uri_method=post` wallet nonce submissions.
pub const REQUEST_URI_POST_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

const WALLET_NONCE_FORM_KEY: &str = "wallet_nonce=";

/// HTTP request details needed to resolve an OpenID4VP `request_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUriHttpRequest {
    /// Value to send in the HTTP `Accept` header.
    pub accept: &'static str,
    /// Value to send in the HTTP `Content-Type` header for POST requests.
    pub content_type: Option<&'static str>,
    /// Request body for POST requests.
    pub body: Vec<u8>,
}

/// Build the HTTP headers/body for resolving a `request_uri` transport.
///
/// OpenID4VP keeps network I/O outside protocol crates. This helper gives
/// adapters one canonical place for the media type and wallet-generated
/// `wallet_nonce` form encoding required by the request_uri POST profile.
pub fn build_request_uri_http_request(
    method: RequestUriMethod,
    wallet_nonce: Option<&str>,
) -> Result<RequestUriHttpRequest, HttpAdapterError> {
    match method {
        RequestUriMethod::Get => Ok(RequestUriHttpRequest {
            accept: REQUEST_OBJECT_MEDIA_TYPE,
            content_type: None,
            body: Vec::new(),
        }),
        RequestUriMethod::Post => {
            let Some(nonce) = wallet_nonce else {
                return Err(HttpAdapterError::new(
                    HttpAdapterErrorReason::MissingWalletNonce,
                ));
            };
            if nonce.is_empty() {
                return Err(HttpAdapterError::new(
                    HttpAdapterErrorReason::MissingWalletNonce,
                ));
            }
            Ok(RequestUriHttpRequest {
                accept: REQUEST_OBJECT_MEDIA_TYPE,
                content_type: Some(REQUEST_URI_POST_CONTENT_TYPE),
                body: form_encode_wallet_nonce(nonce).into_bytes(),
            })
        }
    }
}

fn form_encode_wallet_nonce(wallet_nonce: &str) -> String {
    let mut body = String::from(WALLET_NONCE_FORM_KEY);
    for byte in wallet_nonce.bytes() {
        if is_unreserved(byte) {
            body.push(char::from(byte));
            continue;
        }
        body.push('%');
        body.push(hex_char(byte >> 4));
        body.push(hex_char(byte & 0x0f));
    }
    body
}

const fn is_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

const fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + (nibble - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_types::{RequestUriMethod, REQUEST_OBJECT_MEDIA_TYPE};

    use crate::build_request_uri_http_request::{
        build_request_uri_http_request, REQUEST_URI_POST_CONTENT_TYPE,
    };
    use crate::HttpAdapterErrorReason;

    #[test]
    fn builds_get_request_uri_http_request() {
        let request = build_request_uri_http_request(RequestUriMethod::Get, None)
            .expect("GET request_uri metadata builds");

        assert_eq!(request.accept, REQUEST_OBJECT_MEDIA_TYPE);
        assert_eq!(request.content_type, None);
        assert!(request.body.is_empty());
    }

    #[test]
    fn builds_post_request_uri_http_request_with_encoded_wallet_nonce() {
        let request = build_request_uri_http_request(
            RequestUriMethod::Post,
            Some("nonce with spaces+symbols"),
        )
        .expect("POST request_uri metadata builds");

        assert_eq!(request.accept, REQUEST_OBJECT_MEDIA_TYPE);
        assert_eq!(request.content_type, Some(REQUEST_URI_POST_CONTENT_TYPE));
        assert_eq!(
            request.body,
            b"wallet_nonce=nonce%20with%20spaces%2Bsymbols"
        );
    }

    #[test]
    fn rejects_post_request_uri_http_request_without_wallet_nonce() {
        let err = build_request_uri_http_request(RequestUriMethod::Post, None)
            .expect_err("POST request_uri requires wallet_nonce");

        assert_eq!(err.reason(), HttpAdapterErrorReason::MissingWalletNonce);
    }
}
