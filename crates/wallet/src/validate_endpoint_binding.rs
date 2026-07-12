// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientIdentifierPrefix,
};

use crate::{WalletError, WalletErrorReason};

const HTTPS_SCHEME: &str = "https://";

/// Validate wallet-side response endpoint binding to the verifier client identifier.
pub fn validate_response_endpoint_binding(
    request: &AuthorizationRequestObject,
    client_id: &ClientIdentifier,
    certificate_binding: Option<&VerifiedX509CertificateBinding>,
) -> Result<(), WalletError> {
    match client_id.prefix {
        ClientIdentifierPrefix::X509SanDns => {
            if let Some(response_uri) = request.response_uri.as_deref() {
                validate_endpoint_host_matches_client_identifier(
                    response_uri,
                    &client_id.identifier,
                )?;
            }
            if let Some(redirect_uri) = request.redirect_uri.as_deref() {
                validate_endpoint_host_matches_client_identifier(
                    redirect_uri,
                    &client_id.identifier,
                )?;
            }
        }
        ClientIdentifierPrefix::X509Hash => {
            if let Some(response_uri) = request.response_uri.as_deref() {
                validate_endpoint_host_matches_certificate_binding(
                    response_uri,
                    certificate_binding,
                )?;
            }
            if let Some(redirect_uri) = request.redirect_uri.as_deref() {
                validate_endpoint_host_matches_certificate_binding(
                    redirect_uri,
                    certificate_binding,
                )?;
            }
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

/// Host-supplied DNS Subject Alternative Name evidence for an `x509_hash` client id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedX509CertificateBinding {
    dns_names: Vec<String>,
}

impl VerifiedX509CertificateBinding {
    /// Build verified certificate DNS evidence from a JOSE/TLS verifier.
    pub fn new(dns_names: Vec<String>) -> Result<Self, WalletError> {
        if dns_names.is_empty() || dns_names.iter().any(String::is_empty) {
            return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
        }
        Ok(Self { dns_names })
    }

    /// Return verified DNS Subject Alternative Names.
    #[must_use]
    pub fn dns_names(&self) -> &[String] {
        &self.dns_names
    }

    fn contains_host(&self, host: &str) -> bool {
        self.dns_names
            .iter()
            .any(|dns_name| dns_name.eq_ignore_ascii_case(host))
    }
}

fn validate_endpoint_host_matches_certificate_binding(
    endpoint: &str,
    certificate_binding: Option<&VerifiedX509CertificateBinding>,
) -> Result<(), WalletError> {
    let host = endpoint_host(endpoint)?;
    let Some(binding) = certificate_binding else {
        return Err(WalletError::new(
            WalletErrorReason::ResponseEndpointClientIdentifierMismatch,
        ));
    };
    if !binding.contains_host(host) {
        return Err(WalletError::new(
            WalletErrorReason::ResponseEndpointClientIdentifierMismatch,
        ));
    }
    Ok(())
}

fn validate_endpoint_host_matches_client_identifier(
    endpoint: &str,
    expected_host: &str,
) -> Result<(), WalletError> {
    let host = endpoint_host(endpoint)?;
    if !host.eq_ignore_ascii_case(expected_host) {
        return Err(WalletError::new(
            WalletErrorReason::ResponseEndpointClientIdentifierMismatch,
        ));
    }
    Ok(())
}

fn endpoint_host(uri: &str) -> Result<&str, WalletError> {
    let Some(after_scheme) = uri.strip_prefix(HTTPS_SCHEME) else {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    };
    let authority_end = authority_end(after_scheme);
    let Some(authority) = after_scheme.get(..authority_end) else {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
        };
        return Ok(&rest[..end]);
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Ok(authority);
    };
    if host.contains(':') || port.is_empty() || port.parse::<u16>().is_err() {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
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
