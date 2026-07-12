// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use reallyme_openid4vp_types::classify_request_object_jwt;
use reallyme_openid4vp_wallet::AuthorizationRequestTransport;

use crate::build_request_uri_http_request::{
    build_request_uri_http_request, RequestUriHttpRequest,
};
use crate::error::{HttpAdapterError, HttpAdapterErrorReason};

/// HTTP response containing a Request Object JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestObjectHttpResponse {
    /// Compact Request Object JWT.
    pub jwt: String,
}

/// Transport boundary for resolving `request_uri`.
pub trait RequestUriFetcher: Send + Sync {
    /// Fetch a Request Object JWT without embedding network I/O in protocol crates.
    fn fetch_request_object(
        &self,
        uri: &str,
        request: &RequestUriHttpRequest,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError>;
}

/// HTTP transport resolution policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUriResolutionPolicy {
    /// Require HTTPS `request_uri` values.
    pub allow_https_only: bool,
    /// Maximum accepted compact Request Object JWT size in bytes.
    pub max_request_jwt_bytes: usize,
    /// Wallet-generated nonce to POST when `request_uri_method=post`.
    pub post_wallet_nonce: Option<String>,
}

impl Default for RequestUriResolutionPolicy {
    fn default() -> Self {
        const DEFAULT_MAX_REQUEST_JWT_BYTES: usize = 64 * 1024;
        Self {
            allow_https_only: true,
            max_request_jwt_bytes: DEFAULT_MAX_REQUEST_JWT_BYTES,
            post_wallet_nonce: None,
        }
    }
}

/// Resolve a parsed `request_uri` transport into a by-value Request Object JWT.
pub fn resolve_request_uri_transport(
    transport: AuthorizationRequestTransport,
    fetcher: &impl RequestUriFetcher,
    policy: RequestUriResolutionPolicy,
) -> Result<AuthorizationRequestTransport, HttpAdapterError> {
    let AuthorizationRequestTransport::RequestUri {
        uri,
        method,
        wallet_nonce,
        expected_client_id,
    } = transport
    else {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriRequired,
        ));
    };

    if policy.allow_https_only && !uri.starts_with("https://") {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriMustBeHttps,
        ));
    }
    validate_request_uri_authority(&uri)?;

    let expected_wallet_nonce = wallet_nonce.or(policy.post_wallet_nonce);
    let request = build_request_uri_http_request(method, expected_wallet_nonce.as_deref())?;
    let response = fetcher.fetch_request_object(&uri, &request)?;

    if response.jwt.is_empty() {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::InvalidRequestObjectEncoding,
        ));
    }

    if response.jwt.len() > policy.max_request_jwt_bytes {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestObjectTooLarge,
        ));
    }

    classify_request_object_jwt(&response.jwt)
        .map_err(|_| HttpAdapterError::new(HttpAdapterErrorReason::InvalidRequestObjectEncoding))?;

    Ok(AuthorizationRequestTransport::RequestJwt {
        jwt: response.jwt,
        expected_client_id,
        expected_wallet_nonce,
    })
}

fn validate_request_uri_authority(uri: &str) -> Result<(), HttpAdapterError> {
    const HTTPS_PREFIX: &str = "https://";
    if uri.contains('#') {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    let Some(rest) = uri.strip_prefix(HTTPS_PREFIX) else {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriMustBeHttps,
        ));
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.contains(char::is_whitespace) {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    let host = request_uri_host(authority)?;
    if host.is_empty() {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        reject_unsafe_ip(ip)?;
    }
    Ok(())
}

fn request_uri_host(authority: &str) -> Result<&str, HttpAdapterError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(HttpAdapterError::new(
                HttpAdapterErrorReason::UnsafeRequestUri,
            ));
        };
        let host = &rest[..end];
        let port = &rest[end + 1..];
        if !port.is_empty() && !valid_port_suffix(port) {
            return Err(HttpAdapterError::new(
                HttpAdapterErrorReason::UnsafeRequestUri,
            ));
        }
        return Ok(host);
    }

    if authority.contains('[') || authority.contains(']') {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return Ok(authority);
    };
    if host.contains(':') {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().is_err()
    {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    Ok(host)
}

fn valid_port_suffix(port: &str) -> bool {
    let Some(port) = port.strip_prefix(':') else {
        return false;
    };
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn reject_unsafe_ip(ip: IpAddr) -> Result<(), HttpAdapterError> {
    match ip {
        IpAddr::V4(ip) => reject_unsafe_ipv4(ip),
        IpAddr::V6(ip) => reject_unsafe_ipv6(ip),
    }
}

fn reject_unsafe_ipv4(ip: Ipv4Addr) -> Result<(), HttpAdapterError> {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
    {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    Ok(())
}

fn reject_unsafe_ipv6(ip: Ipv6Addr) -> Result<(), HttpAdapterError> {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
    {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_types::{RequestUriMethod, REQUEST_OBJECT_MEDIA_TYPE};
    use reallyme_openid4vp_wallet::AuthorizationRequestTransport;

    use crate::build_request_uri_http_request::REQUEST_URI_POST_CONTENT_TYPE;
    use crate::error::{HttpAdapterError, HttpAdapterErrorReason};
    use crate::resolve_request_uri::{
        resolve_request_uri_transport, RequestObjectHttpResponse, RequestUriFetcher,
        RequestUriHttpRequest, RequestUriResolutionPolicy,
    };

    const VALID_COMPACT_JWS: &str = "c2lnbmVk.cmVxdWVzdA.and0";
    const VALID_COMPACT_JWE: &str = "eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn";

    struct FixtureFetcher;

    impl RequestUriFetcher for FixtureFetcher {
        fn fetch_request_object(
            &self,
            uri: &str,
            request: &RequestUriHttpRequest,
        ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
            if uri == "https://verifier.example/request.jwt"
                && request.accept == REQUEST_OBJECT_MEDIA_TYPE
                && request.content_type == Some(REQUEST_URI_POST_CONTENT_TYPE)
                && request.body == b"wallet_nonce=nonce"
            {
                return Ok(RequestObjectHttpResponse {
                    jwt: VALID_COMPACT_JWS.to_owned(),
                });
            }
            Err(HttpAdapterError::new(
                HttpAdapterErrorReason::RequestUriFetchFailed,
            ))
        }
    }

    #[test]
    fn resolves_request_uri_transport_to_request_jwt() {
        let resolved = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Post,
                wallet_nonce: Some("nonce".to_owned()),
                expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
            },
            &FixtureFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect("fixture request_uri resolves");

        assert_eq!(
            resolved,
            AuthorizationRequestTransport::RequestJwt {
                jwt: VALID_COMPACT_JWS.to_owned(),
                expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
                expected_wallet_nonce: Some("nonce".to_owned()),
            }
        );
    }

    #[test]
    fn rejects_non_https_request_uri_by_default() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "http://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &FixtureFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("non-HTTPS request_uri is rejected");

        assert_eq!(err.reason(), HttpAdapterErrorReason::RequestUriMustBeHttps);
    }

    #[test]
    fn rejects_loopback_request_uri_before_fetch() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://127.0.0.1/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &FixtureFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("loopback request_uri is rejected");

        assert_eq!(err.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
    }

    #[test]
    fn rejects_metadata_ip_request_uri_before_fetch() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://169.254.169.254/latest/meta-data".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &FixtureFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("metadata IP request_uri is rejected");

        assert_eq!(err.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
    }

    #[test]
    fn rejects_localhost_request_uri_before_fetch() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://localhost/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &FixtureFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("localhost request_uri is rejected");

        assert_eq!(err.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
    }

    #[test]
    fn rejects_non_request_uri_transport() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestJwt {
                jwt: VALID_COMPACT_JWS.to_owned(),
                expected_client_id: None,
                expected_wallet_nonce: None,
            },
            &FixtureFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("resolver only accepts request_uri transport");

        assert_eq!(err.reason(), HttpAdapterErrorReason::RequestUriRequired);
    }

    struct EmptyJwtFetcher;

    impl RequestUriFetcher for EmptyJwtFetcher {
        fn fetch_request_object(
            &self,
            _uri: &str,
            _request: &RequestUriHttpRequest,
        ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
            Ok(RequestObjectHttpResponse { jwt: String::new() })
        }
    }

    #[test]
    fn rejects_empty_fetched_request_object() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &EmptyJwtFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("empty fetched request object is rejected");

        assert_eq!(
            err.reason(),
            HttpAdapterErrorReason::InvalidRequestObjectEncoding
        );
    }

    struct MalformedJwtFetcher;

    impl RequestUriFetcher for MalformedJwtFetcher {
        fn fetch_request_object(
            &self,
            _uri: &str,
            _request: &RequestUriHttpRequest,
        ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
            Ok(RequestObjectHttpResponse {
                jwt: "header.payload".to_owned(),
            })
        }
    }

    #[test]
    fn rejects_malformed_fetched_request_object() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &MalformedJwtFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("fetched Request Object must be compact JWS or JWE");

        assert_eq!(
            err.reason(),
            HttpAdapterErrorReason::InvalidRequestObjectEncoding
        );
    }

    struct EncryptedJwtFetcher;

    impl RequestUriFetcher for EncryptedJwtFetcher {
        fn fetch_request_object(
            &self,
            _uri: &str,
            _request: &RequestUriHttpRequest,
        ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
            Ok(RequestObjectHttpResponse {
                jwt: VALID_COMPACT_JWE.to_owned(),
            })
        }
    }

    #[test]
    fn resolves_encrypted_request_uri_transport_to_request_jwt() {
        let resolved = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &EncryptedJwtFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect("encrypted fetched Request Object is accepted before JOSE");

        assert_eq!(
            resolved,
            AuthorizationRequestTransport::RequestJwt {
                jwt: VALID_COMPACT_JWE.to_owned(),
                expected_client_id: None,
                expected_wallet_nonce: None,
            }
        );
    }

    struct LargeJwtFetcher;

    impl RequestUriFetcher for LargeJwtFetcher {
        fn fetch_request_object(
            &self,
            _uri: &str,
            _request: &RequestUriHttpRequest,
        ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
            Ok(RequestObjectHttpResponse {
                jwt: VALID_COMPACT_JWS.to_owned(),
            })
        }
    }

    #[test]
    fn rejects_oversized_fetched_request_object() {
        let err = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &LargeJwtFetcher,
            RequestUriResolutionPolicy {
                allow_https_only: true,
                max_request_jwt_bytes: 4,
                ..RequestUriResolutionPolicy::default()
            },
        )
        .expect_err("oversized fetched request object is rejected");

        assert_eq!(err.reason(), HttpAdapterErrorReason::RequestObjectTooLarge);
    }
}
