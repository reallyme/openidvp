// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SDK-facing OpenID4VP protocol policy.
//!
//! `reallyme/identity-sdk` should be able to configure OpenID4VP once and
//! pass the same audited policy down into verifier, wallet, HTTP, and platform
//! adapters. The lower crates still own their narrow policy structs; this
//! facade type prevents platform SDKs from re-encoding those defaults.

use reallyme_openid4vp_verifier::JarPolicy;
use reallyme_openid4vp_wallet::RequestTransportPolicy;

/// Maximum compact Request Object JWT bytes accepted by default.
pub const DEFAULT_MAX_REQUEST_JWT_BYTES: usize = 64 * 1024;
/// Maximum authorization request URI/query bytes accepted by default.
pub const DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES: usize = 16 * 1024;
/// Maximum authorization request parameter count accepted by default.
pub const DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS: usize = 64;

/// Maximum Request Object lifetime accepted by default, in seconds.
pub const DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS: u64 = 300;

/// Accepted future clock skew for Request Object `iat`, in seconds.
pub const DEFAULT_ISSUED_AT_FUTURE_SKEW_SECS: u64 = 60;

/// Unified OpenID4VP protocol policy for SDK and platform facades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenId4VpProtocolPolicy {
    /// Maximum accepted compact Request Object JWT size in bytes.
    pub max_request_jwt_bytes: usize,
    /// Maximum accepted front-channel Authorization Request size in bytes.
    pub max_authorization_request_bytes: usize,
    /// Maximum accepted front-channel Authorization Request parameter count.
    pub max_authorization_request_parameters: usize,
    /// Reject inline Authorization Request parameters unless a signed Request
    /// Object is present. Production wallets should leave this enabled because
    /// final OpenID4VP deployments bind verifier identity through signed JAR.
    pub require_signed_request_object: bool,
    /// Require HTTPS for `request_uri` retrieval.
    pub require_https_request_uri: bool,
    /// Require an issuer claim in Request Objects.
    pub require_request_object_issuer: bool,
    /// Require issuer to equal the final-prefixed client identifier.
    pub require_issuer_matches_client_id: bool,
    /// Require an audience claim in Request Objects.
    pub require_request_object_audience: bool,
    /// Require an issued-at claim in Request Objects.
    pub require_request_object_issued_at: bool,
    /// Require an expiration claim in Request Objects.
    pub require_request_object_expiration: bool,
    /// Maximum accepted Request Object lifetime, in seconds.
    pub max_request_object_lifetime_secs: Option<u64>,
    /// Accepted clock skew for issued-at values in the future.
    pub issued_at_future_skew_secs: u64,
}

impl OpenId4VpProtocolPolicy {
    /// Return a strict production policy suitable for identity-sdk defaults.
    pub const fn production() -> Self {
        Self {
            max_request_jwt_bytes: DEFAULT_MAX_REQUEST_JWT_BYTES,
            max_authorization_request_bytes: DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES,
            max_authorization_request_parameters: DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS,
            require_signed_request_object: true,
            require_https_request_uri: true,
            require_request_object_issuer: true,
            require_issuer_matches_client_id: true,
            require_request_object_audience: true,
            require_request_object_issued_at: true,
            require_request_object_expiration: true,
            max_request_object_lifetime_secs: Some(DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS),
            issued_at_future_skew_secs: DEFAULT_ISSUED_AT_FUTURE_SKEW_SECS,
        }
    }

    /// Return a deliberately looser policy for conformance or legacy interop.
    ///
    /// This keeps insecure knobs explicit at call sites instead of burying them
    /// in tests or SDK platform code. It still preserves size and time limits.
    pub const fn insecure_interop() -> Self {
        Self {
            max_request_jwt_bytes: DEFAULT_MAX_REQUEST_JWT_BYTES,
            max_authorization_request_bytes: DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES,
            max_authorization_request_parameters: DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS,
            require_signed_request_object: false,
            require_https_request_uri: false,
            require_request_object_issuer: false,
            require_issuer_matches_client_id: false,
            require_request_object_audience: false,
            require_request_object_issued_at: false,
            require_request_object_expiration: true,
            max_request_object_lifetime_secs: Some(DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS),
            issued_at_future_skew_secs: DEFAULT_ISSUED_AT_FUTURE_SKEW_SECS,
        }
    }

    /// Convert to the wallet transport parser policy.
    pub const fn wallet_transport_policy(self) -> RequestTransportPolicy {
        RequestTransportPolicy {
            max_request_jwt_bytes: self.max_request_jwt_bytes,
            max_authorization_request_bytes: self.max_authorization_request_bytes,
            max_authorization_request_parameters: self.max_authorization_request_parameters,
            require_signed_request_object: self.require_signed_request_object,
        }
    }

    /// Convert to the verifier Request Object claim policy.
    pub const fn jar_policy(self) -> JarPolicy {
        JarPolicy {
            require_issuer: self.require_request_object_issuer,
            require_issuer_matches_client_id: self.require_issuer_matches_client_id,
            require_audience: self.require_request_object_audience,
            require_issued_at: self.require_request_object_issued_at,
            require_expiration: self.require_request_object_expiration,
            max_lifetime_secs: self.max_request_object_lifetime_secs,
            issued_at_future_skew_secs: self.issued_at_future_skew_secs,
        }
    }

    /// Convert to the HTTP `request_uri` resolution policy.
    #[cfg(feature = "http")]
    pub const fn request_uri_resolution_policy(
        self,
    ) -> reallyme_openid4vp_http::RequestUriResolutionPolicy {
        reallyme_openid4vp_http::RequestUriResolutionPolicy {
            allow_https_only: self.require_https_request_uri,
            max_request_jwt_bytes: self.max_request_jwt_bytes,
            post_wallet_nonce: None,
        }
    }
}

impl Default for OpenId4VpProtocolPolicy {
    fn default() -> Self {
        Self::production()
    }
}

impl From<OpenId4VpProtocolPolicy> for RequestTransportPolicy {
    fn from(policy: OpenId4VpProtocolPolicy) -> Self {
        policy.wallet_transport_policy()
    }
}

impl From<OpenId4VpProtocolPolicy> for JarPolicy {
    fn from(policy: OpenId4VpProtocolPolicy) -> Self {
        policy.jar_policy()
    }
}

#[cfg(feature = "http")]
impl From<OpenId4VpProtocolPolicy> for reallyme_openid4vp_http::RequestUriResolutionPolicy {
    fn from(policy: OpenId4VpProtocolPolicy) -> Self {
        policy.request_uri_resolution_policy()
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::{
        OpenId4VpProtocolPolicy, DEFAULT_MAX_REQUEST_JWT_BYTES,
        DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS,
    };

    #[test]
    fn production_policy_maps_to_lower_crate_policies() {
        let policy = OpenId4VpProtocolPolicy::production();

        let wallet_policy = policy.wallet_transport_policy();
        assert_eq!(
            wallet_policy.max_request_jwt_bytes,
            DEFAULT_MAX_REQUEST_JWT_BYTES
        );
        assert!(wallet_policy.require_signed_request_object);

        let jar_policy = policy.jar_policy();
        assert!(jar_policy.require_issuer);
        assert!(jar_policy.require_issuer_matches_client_id);
        assert!(jar_policy.require_audience);
        assert!(jar_policy.require_issued_at);
        assert!(jar_policy.require_expiration);
        assert_eq!(
            jar_policy.max_lifetime_secs,
            Some(DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS)
        );

        #[cfg(feature = "http")]
        {
            let request_uri_policy = policy.request_uri_resolution_policy();
            assert!(request_uri_policy.allow_https_only);
            assert_eq!(
                request_uri_policy.max_request_jwt_bytes,
                DEFAULT_MAX_REQUEST_JWT_BYTES
            );
        }
    }

    #[test]
    fn insecure_interop_policy_keeps_relaxations_explicit() {
        let policy = OpenId4VpProtocolPolicy::insecure_interop();

        assert!(!policy.require_signed_request_object);
        assert!(!policy.require_https_request_uri);
        assert!(!policy.require_request_object_issuer);
        assert!(!policy.require_issuer_matches_client_id);
        assert!(!policy.require_request_object_audience);
        assert!(!policy.require_request_object_issued_at);
        assert!(policy.require_request_object_expiration);
    }
}
