// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{ClientIdentifier, ClientIdentifierPrefix};
use serde::{Deserialize, Serialize};

use crate::{VerifierError, VerifierErrorReason};

const HTTPS_SCHEME: &str = "https://";

/// Request binding material used to validate an authorization response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBinding {
    /// Parsed Client Identifier.
    pub client_id: ClientIdentifier,
    /// Nonce from the Authorization Request.
    pub nonce: String,
    /// Response URI used for direct post modes.
    pub response_uri: Option<String>,
    /// Redirect URI used for front-channel modes.
    pub redirect_uri: Option<String>,
    /// Expiry time in Unix seconds.
    pub expiry_unix: u64,
    /// SHA-256 transaction-data hash expected in presentation public inputs.
    pub transaction_data_hash: Option<[u8; 32]>,
}

/// Validate request binding freshness and required endpoints.
pub fn validate_request_binding(
    binding: &RequestBinding,
    now_unix: u64,
) -> Result<(), VerifierError> {
    if binding.nonce.is_empty() {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    if binding.response_uri.is_none() && binding.redirect_uri.is_none() {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    if let Some(response_uri) = binding.response_uri.as_deref() {
        validate_endpoint_uri(response_uri)?;
    }
    if let Some(redirect_uri) = binding.redirect_uri.as_deref() {
        validate_endpoint_uri(redirect_uri)?;
    }
    validate_endpoint_client_identifier_binding(binding)?;
    if binding.expiry_unix == 0 || now_unix > binding.expiry_unix {
        return Err(VerifierError::new(VerifierErrorReason::BindingExpired));
    }
    Ok(())
}

fn validate_endpoint_uri(uri: &str) -> Result<(), VerifierError> {
    if uri.is_empty() {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    if uri
        .as_bytes()
        .iter()
        .any(|byte| byte.is_ascii_control() || *byte == b' ')
    {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    }
    let Some(scheme) = uri.get(..HTTPS_SCHEME.len()) else {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    };
    if !scheme.eq_ignore_ascii_case(HTTPS_SCHEME) {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    }
    if uri.contains('#') {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    }
    let Some(after_scheme) = uri.get(HTTPS_SCHEME.len()..) else {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    };
    let authority_end = authority_end(after_scheme);
    let Some(authority) = after_scheme.get(..authority_end) else {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    }
    Ok(())
}

fn validate_endpoint_client_identifier_binding(
    binding: &RequestBinding,
) -> Result<(), VerifierError> {
    match binding.client_id.prefix {
        ClientIdentifierPrefix::X509SanDns => {
            let expected_host = binding.client_id.identifier.as_str();
            if let Some(response_uri) = binding.response_uri.as_deref() {
                validate_endpoint_host_matches_client_id(response_uri, expected_host)?;
            }
            if let Some(redirect_uri) = binding.redirect_uri.as_deref() {
                validate_endpoint_host_matches_client_id(redirect_uri, expected_host)?;
            }
        }
        ClientIdentifierPrefix::X509Hash => {
            // The certificate hash prefix binds through host-validated TLS
            // certificate material supplied by the runtime/JWS verifier. This
            // layer validates endpoint shape but cannot reconstruct that
            // certificate chain from a URI string alone.
        }
        ClientIdentifierPrefix::None
        | ClientIdentifierPrefix::RedirectUri
        | ClientIdentifierPrefix::OpenIdFederation
        | ClientIdentifierPrefix::DecentralizedIdentifier
        | ClientIdentifierPrefix::VerifierAttestation
        | ClientIdentifierPrefix::Origin => {}
    }
    Ok(())
}

fn validate_endpoint_host_matches_client_id(
    endpoint: &str,
    expected_host: &str,
) -> Result<(), VerifierError> {
    let host = endpoint_host(endpoint)?;
    if !host.eq_ignore_ascii_case(expected_host) {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    Ok(())
}

fn endpoint_host(uri: &str) -> Result<&str, VerifierError> {
    let Some(after_scheme) = uri.get(HTTPS_SCHEME.len()..) else {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    };
    let authority_end = authority_end(after_scheme);
    let Some(authority) = after_scheme.get(..authority_end) else {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
        };
        return Ok(&rest[..end]);
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Ok(authority);
    };
    if host.contains(':') || port.is_empty() {
        return Err(VerifierError::new(VerifierErrorReason::InvalidRequestUri));
    }
    Ok(host)
}

fn authority_end(after_scheme: &str) -> usize {
    let mut end = after_scheme.len();
    for delimiter in ['/', '?'] {
        if let Some(position) = after_scheme.find(delimiter) {
            end = end.min(position);
        }
    }
    end
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_types::ClientIdentifier;

    use crate::binding::validate_request_binding;
    use crate::{RequestBinding, VerifierErrorReason};

    fn binding() -> RequestBinding {
        RequestBinding {
            client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
            nonce: "nonce".to_owned(),
            response_uri: Some("https://verifier.example/response?session=1".to_owned()),
            redirect_uri: None,
            expiry_unix: 100,
            transaction_data_hash: None,
        }
    }

    #[test]
    fn accepts_https_response_uri_with_query() {
        validate_request_binding(&binding(), 10).expect("https response_uri is valid");
    }

    #[test]
    fn rejects_missing_response_and_redirect_uri() {
        let mut binding = binding();
        binding.response_uri = None;

        let err =
            validate_request_binding(&binding, 10).expect_err("one response endpoint is required");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidBinding);
    }

    #[test]
    fn rejects_non_https_response_uri() {
        let mut binding = binding();
        binding.response_uri = Some("http://verifier.example/response".to_owned());

        let err =
            validate_request_binding(&binding, 10).expect_err("non-HTTPS response_uri is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
    }

    #[test]
    fn rejects_response_uri_with_fragment() {
        let mut binding = binding();
        binding.response_uri = Some("https://verifier.example/response#fragment".to_owned());

        let err = validate_request_binding(&binding, 10)
            .expect_err("response_uri fragments are rejected");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
    }

    #[test]
    fn rejects_response_uri_with_userinfo() {
        let mut binding = binding();
        binding.response_uri = Some("https://user@verifier.example/response".to_owned());

        let err =
            validate_request_binding(&binding, 10).expect_err("response_uri userinfo is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
    }

    #[test]
    fn rejects_empty_response_uri_authority() {
        let mut binding = binding();
        binding.response_uri = Some("https:///response".to_owned());

        let err =
            validate_request_binding(&binding, 10).expect_err("response_uri authority is required");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
    }

    #[test]
    fn accepts_x509_san_dns_response_uri_host_with_port() {
        let mut binding = binding();
        binding.response_uri = Some("https://verifier.example:8443/response".to_owned());

        validate_request_binding(&binding, 10).expect("response_uri host matches client_id");
    }

    #[test]
    fn rejects_x509_san_dns_response_uri_host_mismatch() {
        let mut binding = binding();
        binding.response_uri = Some("https://attacker.example/response".to_owned());

        let err = validate_request_binding(&binding, 10)
            .expect_err("x509_san_dns response_uri host must match client_id");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidBinding);
    }

    #[test]
    fn rejects_x509_san_dns_redirect_uri_host_mismatch() {
        let mut binding = binding();
        binding.response_uri = None;
        binding.redirect_uri = Some("https://attacker.example/cb".to_owned());

        let err = validate_request_binding(&binding, 10)
            .expect_err("x509_san_dns redirect_uri host must match client_id");

        assert_eq!(err.reason(), VerifierErrorReason::InvalidBinding);
    }
}
