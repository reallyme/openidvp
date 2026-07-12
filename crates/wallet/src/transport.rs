// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use reallyme_openid4vp_types::{classify_request_object_jwt, RequestUriMethod};

use crate::{WalletError, WalletErrorReason};

const LEGACY_CLIENT_ID_SCHEME_FIELD: &str = "client_id_scheme";

/// Wallet authorization request transport classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationRequestTransport {
    /// Request Object supplied by value through the `request` parameter.
    RequestJwt {
        /// Compact Request Object JWT.
        jwt: String,
        /// Expected client id supplied alongside `request`.
        expected_client_id: Option<String>,
        /// Wallet-generated nonce that the resolved Request Object must echo.
        expected_wallet_nonce: Option<String>,
    },
    /// Request Object supplied by reference through the `request_uri` parameter.
    RequestUri {
        /// URI to resolve outside the pure wallet parser.
        uri: String,
        /// Retrieval method.
        method: RequestUriMethod,
        /// Wallet nonce required for POST retrieval.
        wallet_nonce: Option<String>,
        /// Expected client id supplied alongside `request_uri`.
        expected_client_id: Option<String>,
    },
    /// Inline query parameters.
    InlineParams {
        /// Parsed query parameters.
        params: BTreeMap<String, String>,
    },
}

/// Policy for pure transport parsing and pre-verification size checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTransportPolicy {
    /// Maximum accepted compact Request Object JWT size in bytes.
    pub max_request_jwt_bytes: usize,
    /// Maximum accepted authorization request URI/query string length.
    pub max_authorization_request_bytes: usize,
    /// Maximum accepted authorization request parameter count.
    pub max_authorization_request_parameters: usize,
    /// Reject inline parameters when signed Request Objects are required.
    pub require_signed_request_object: bool,
}

impl Default for RequestTransportPolicy {
    fn default() -> Self {
        const DEFAULT_MAX_REQUEST_JWT_BYTES: usize = 64 * 1024;
        const DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES: usize = 16 * 1024;
        const DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS: usize = 64;
        Self {
            max_request_jwt_bytes: DEFAULT_MAX_REQUEST_JWT_BYTES,
            max_authorization_request_bytes: DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES,
            max_authorization_request_parameters: DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS,
            require_signed_request_object: true,
        }
    }
}

/// Parse an OpenID4VP authorization request into a transport classification.
///
/// This ports the good meproto boundary: parsing is pure and network-free,
/// while `request_uri` resolution is delegated to transport adapters. The
/// parser accepts full URIs or raw query strings.
pub fn parse_authorization_request_transport(
    input: &str,
    policy: RequestTransportPolicy,
) -> Result<AuthorizationRequestTransport, WalletError> {
    let params = parse_input_to_params(input, policy)?;
    classify_transport(params, policy)
}

fn parse_input_to_params(
    input: &str,
    policy: RequestTransportPolicy,
) -> Result<BTreeMap<String, String>, WalletError> {
    let trimmed = input.trim();
    if trimmed.len() > policy.max_authorization_request_bytes {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    }
    let query = match trimmed.find('?') {
        Some(index) => {
            let Some(start) = index.checked_add(1) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            &trimmed[start..]
        }
        None => trimmed,
    };
    parse_querystring(query, policy.max_authorization_request_parameters)
}

fn parse_querystring(
    query: &str,
    max_parameters: usize,
) -> Result<BTreeMap<String, String>, WalletError> {
    let mut out = BTreeMap::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if out.len() >= max_parameters {
            return Err(WalletError::new(
                WalletErrorReason::InvalidAuthorizationRequestTransport,
            ));
        }

        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;

        if !key.is_empty() && out.insert(key, value).is_some() {
            return Err(WalletError::new(
                WalletErrorReason::DuplicateAuthorizationRequestParameter,
            ));
        }
    }

    Ok(out)
}

fn percent_decode(input: &str) -> Result<String, WalletError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(first_index) = index.checked_add(1) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            let Some(second_index) = index.checked_add(2) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            if second_index >= bytes.len() {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            }
            let Some(high) = hex_val(bytes[first_index]) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            let Some(low) = hex_val(bytes[second_index]) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            out.push((high << 4) | low);
            let Some(next_index) = index.checked_add(3) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            index = next_index;
            continue;
        }

        out.push(bytes[index]);
        let Some(next_index) = index.checked_add(1) else {
            return Err(WalletError::new(
                WalletErrorReason::InvalidAuthorizationRequestTransport,
            ));
        };
        index = next_index;
    }

    String::from_utf8(out)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidAuthorizationRequestTransport))
}

const fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + (byte - b'a')),
        b'A'..=b'F' => Some(10 + (byte - b'A')),
        _ => None,
    }
}

fn classify_transport(
    params: BTreeMap<String, String>,
    policy: RequestTransportPolicy,
) -> Result<AuthorizationRequestTransport, WalletError> {
    if params.contains_key(LEGACY_CLIENT_ID_SCHEME_FIELD) {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    }

    let expected_client_id = params
        .get("client_id")
        .filter(|value| !value.is_empty())
        .cloned();
    let request = params.get("request").cloned();
    let request_uri = params.get("request_uri").cloned();
    let wallet_nonce = params.get("wallet_nonce").cloned();

    if request.is_some() && request_uri.is_some() {
        return Err(WalletError::new(
            WalletErrorReason::ConflictingRequestObjectParameters,
        ));
    }

    if let Some(jwt) = request {
        if wallet_nonce.is_some() {
            return Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce));
        }
        if jwt.len() > policy.max_request_jwt_bytes {
            return Err(WalletError::new(WalletErrorReason::RequestObjectTooLarge));
        }
        classify_request_object_jwt(&jwt)
            .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
        return Ok(AuthorizationRequestTransport::RequestJwt {
            jwt,
            expected_client_id,
            expected_wallet_nonce: None,
        });
    }

    if let Some(uri) = request_uri {
        let method =
            parse_request_uri_method(params.get("request_uri_method").map(String::as_str))?;
        if wallet_nonce.is_some() {
            return Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce));
        }
        if method == RequestUriMethod::Post {
            return Ok(AuthorizationRequestTransport::RequestUri {
                uri,
                method,
                wallet_nonce: None,
                expected_client_id,
            });
        }

        return Ok(AuthorizationRequestTransport::RequestUri {
            uri,
            method,
            wallet_nonce: None,
            expected_client_id,
        });
    }

    if wallet_nonce.is_some() {
        return Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce));
    }

    if policy.require_signed_request_object {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    }

    Ok(AuthorizationRequestTransport::InlineParams { params })
}

fn parse_request_uri_method(method: Option<&str>) -> Result<RequestUriMethod, WalletError> {
    match method {
        None | Some("get") => Ok(RequestUriMethod::Get),
        Some("post") => Ok(RequestUriMethod::Post),
        Some(_) => Err(WalletError::new(
            WalletErrorReason::UnsupportedRequestUriMethod,
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_types::RequestUriMethod;

    use crate::transport::{
        parse_authorization_request_transport, AuthorizationRequestTransport,
        RequestTransportPolicy,
    };
    use crate::WalletErrorReason;

    const VALID_COMPACT_JWS: &str = "c2lnbmVk.cmVxdWVzdA.and0";
    const VALID_COMPACT_JWE: &str = "eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn";

    #[test]
    fn classifies_post_request_uri_without_verifier_supplied_wallet_nonce() {
        let transport = parse_authorization_request_transport(
            "client_id=x509_san_dns%3Averifier.example&request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt&request_uri_method=post",
            RequestTransportPolicy::default(),
        )
        .expect("transport parses");

        assert_eq!(
            transport,
            AuthorizationRequestTransport::RequestUri {
                uri: "https://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Post,
                wallet_nonce: None,
                expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
            }
        );
    }

    #[test]
    fn rejects_verifier_supplied_wallet_nonce_for_post_request_uri() {
        let err = parse_authorization_request_transport(
            "request_uri=https://verifier.example/request.jwt&request_uri_method=post&wallet_nonce=abc",
            RequestTransportPolicy::default(),
        )
        .expect_err("wallet_nonce is generated by the wallet request-uri POST");

        assert_eq!(err.reason(), WalletErrorReason::UnexpectedWalletNonce);
    }

    #[test]
    fn rejects_wallet_nonce_for_get_request_uri() {
        let err = parse_authorization_request_transport(
            "request_uri=https://verifier.example/request.jwt&wallet_nonce=abc",
            RequestTransportPolicy::default(),
        )
        .expect_err("wallet_nonce is invalid for GET retrieval");

        assert_eq!(err.reason(), WalletErrorReason::UnexpectedWalletNonce);
    }

    #[test]
    fn rejects_conflicting_request_and_request_uri() {
        let query =
            format!("request={VALID_COMPACT_JWS}&request_uri=https://verifier.example/request.jwt");
        let err = parse_authorization_request_transport(&query, RequestTransportPolicy::default())
            .expect_err("request and request_uri are mutually exclusive");

        assert_eq!(
            err.reason(),
            WalletErrorReason::ConflictingRequestObjectParameters
        );
    }

    #[test]
    fn rejects_duplicate_authorization_request_parameters() {
        let query = format!("request={VALID_COMPACT_JWS}&request=other.header.payload");
        let err = parse_authorization_request_transport(&query, RequestTransportPolicy::default())
            .expect_err("duplicate request parameters are ambiguous");

        assert_eq!(
            err.reason(),
            WalletErrorReason::DuplicateAuthorizationRequestParameter
        );
    }

    #[test]
    fn rejects_uppercase_request_uri_method() {
        let err = parse_authorization_request_transport(
            "request_uri=https://verifier.example/request.jwt&request_uri_method=POST&wallet_nonce=abc",
            RequestTransportPolicy::default(),
        )
        .expect_err("request_uri_method is case-sensitive");

        assert_eq!(err.reason(), WalletErrorReason::UnsupportedRequestUriMethod);
    }

    #[test]
    fn rejects_legacy_client_id_scheme_parameter() {
        let err = parse_authorization_request_transport(
            "client_id=x509_san_dns%3Averifier.example&client_id_scheme=x509_san_dns&request_uri=https://verifier.example/request.jwt",
            RequestTransportPolicy::default(),
        )
        .expect_err("legacy client_id_scheme is rejected");

        assert_eq!(
            err.reason(),
            WalletErrorReason::InvalidAuthorizationRequestTransport
        );
    }

    #[test]
    fn rejects_malformed_percent_encoding() {
        let err = parse_authorization_request_transport(
            "request_uri=https%3A%2F%2Fverifier.example%2Grequest.jwt",
            RequestTransportPolicy::default(),
        )
        .expect_err("malformed percent encoding is rejected");

        assert_eq!(
            err.reason(),
            WalletErrorReason::InvalidAuthorizationRequestTransport
        );
    }

    #[test]
    fn rejects_oversized_request_object_by_value() {
        let policy = RequestTransportPolicy {
            max_request_jwt_bytes: 4,
            require_signed_request_object: true,
            ..RequestTransportPolicy::default()
        };

        let err = parse_authorization_request_transport("request=12345", policy)
            .expect_err("oversized request object is rejected before verification");

        assert_eq!(err.reason(), WalletErrorReason::RequestObjectTooLarge);
    }

    #[test]
    fn classifies_signed_request_object_by_value() {
        let query =
            format!("client_id=x509_san_dns%3Averifier.example&request={VALID_COMPACT_JWS}");
        let transport =
            parse_authorization_request_transport(&query, RequestTransportPolicy::default())
                .expect("signed by-value request object parses");

        assert_eq!(
            transport,
            AuthorizationRequestTransport::RequestJwt {
                jwt: VALID_COMPACT_JWS.to_owned(),
                expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
                expected_wallet_nonce: None,
            }
        );
    }

    #[test]
    fn classifies_encrypted_request_object_by_value() {
        let query = format!("request={VALID_COMPACT_JWE}");
        let transport =
            parse_authorization_request_transport(&query, RequestTransportPolicy::default())
                .expect("encrypted by-value request object parses");

        assert_eq!(
            transport,
            AuthorizationRequestTransport::RequestJwt {
                jwt: VALID_COMPACT_JWE.to_owned(),
                expected_client_id: None,
                expected_wallet_nonce: None,
            }
        );
    }

    #[test]
    fn rejects_malformed_request_object_by_value() {
        let err = parse_authorization_request_transport(
            "request=header.payload",
            RequestTransportPolicy::default(),
        )
        .expect_err("malformed Request Object is rejected before JOSE verification");

        assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
    }

    #[test]
    fn rejects_inline_params_when_signed_request_required() {
        let err = parse_authorization_request_transport(
            "client_id=x509_san_dns%3Averifier.example&nonce=abc",
            RequestTransportPolicy::default(),
        )
        .expect_err("strict policy rejects inline params");

        assert_eq!(
            err.reason(),
            WalletErrorReason::InvalidAuthorizationRequestTransport
        );
    }
}
