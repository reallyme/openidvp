// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_dcql::CredentialFormat;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    ClientIdentifierPrefix, OpenId4vpTypeError, OpenId4vpTypeErrorReason, RequestUriMethod,
    ResponseMode,
};

/// Raw verifier metadata carried inline or resolved by client identifier rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Raw metadata JSON.
    ///
    /// OpenID4VP verifier metadata remains extension-friendly across profiles
    /// and trust mechanisms. This field is intentionally raw protocol JSON;
    /// SDK/FFI facades should schema-validate it before converting to platform
    /// models.
    pub raw: JsonValue,
}

/// JWA or profile-defined algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AlgorithmIdentifier(String);

impl AlgorithmIdentifier {
    /// Construct an algorithm identifier.
    pub fn new(value: String) -> Result<Self, OpenId4vpTypeError> {
        if value.is_empty() {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyValue,
            ));
        }
        Ok(Self(value))
    }

    /// Return the wire identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed OpenID4VP verifier metadata capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierMetadata {
    /// Response modes the verifier can receive.
    pub response_modes_supported: Vec<ResponseMode>,
    /// Client identifier prefixes the verifier can bind.
    pub client_id_prefixes_supported: Vec<ClientIdentifierPrefix>,
    /// Credential formats the verifier can request.
    pub vp_formats_supported: Vec<CredentialFormat>,
    /// Request Object signing algorithms the verifier can produce.
    pub request_object_signing_alg_values_supported: Vec<AlgorithmIdentifier>,
    /// JWE alg values accepted for encrypted authorization responses.
    pub response_encryption_alg_values_supported: Vec<AlgorithmIdentifier>,
    /// JWE enc values accepted for encrypted authorization responses.
    pub response_encryption_enc_values_supported: Vec<AlgorithmIdentifier>,
}

impl VerifierMetadata {
    /// Construct verifier metadata after validating required capability lists.
    pub fn new(
        response_modes_supported: Vec<ResponseMode>,
        client_id_prefixes_supported: Vec<ClientIdentifierPrefix>,
        vp_formats_supported: Vec<CredentialFormat>,
        request_object_signing_alg_values_supported: Vec<AlgorithmIdentifier>,
        response_encryption_alg_values_supported: Vec<AlgorithmIdentifier>,
        response_encryption_enc_values_supported: Vec<AlgorithmIdentifier>,
    ) -> Result<Self, OpenId4vpTypeError> {
        reject_empty(response_modes_supported.is_empty())?;
        reject_empty(client_id_prefixes_supported.is_empty())?;
        reject_empty(vp_formats_supported.is_empty())?;
        Ok(Self {
            response_modes_supported,
            client_id_prefixes_supported,
            vp_formats_supported,
            request_object_signing_alg_values_supported,
            response_encryption_alg_values_supported,
            response_encryption_enc_values_supported,
        })
    }

    /// Return whether this verifier supports a response mode.
    pub fn supports_response_mode(&self, mode: ResponseMode) -> bool {
        self.response_modes_supported.contains(&mode)
    }

    /// Return whether this verifier supports a client identifier prefix.
    pub fn supports_client_id_prefix(&self, prefix: ClientIdentifierPrefix) -> bool {
        self.client_id_prefixes_supported.contains(&prefix)
    }

    /// Return whether this verifier supports a credential format.
    pub fn supports_format(&self, format: &CredentialFormat) -> bool {
        self.vp_formats_supported.iter().any(|item| item == format)
    }

    /// Return whether this verifier can receive an encrypted authorization response.
    pub fn supports_response_encryption(
        &self,
        alg: &AlgorithmIdentifier,
        enc: &AlgorithmIdentifier,
    ) -> bool {
        self.response_encryption_alg_values_supported
            .iter()
            .any(|item| item == alg)
            && self
                .response_encryption_enc_values_supported
                .iter()
                .any(|item| item == enc)
    }
}

/// Typed OpenID4VP wallet metadata capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// Response modes the wallet can produce.
    pub response_modes_supported: Vec<ResponseMode>,
    /// Request URI retrieval methods the wallet can use.
    pub request_uri_methods_supported: Vec<RequestUriMethod>,
    /// Credential formats the wallet can present.
    pub vp_formats_supported: Vec<CredentialFormat>,
    /// JWE alg values the wallet can use for encrypted authorization responses.
    pub response_encryption_alg_values_supported: Vec<AlgorithmIdentifier>,
    /// JWE enc values the wallet can use for encrypted authorization responses.
    pub response_encryption_enc_values_supported: Vec<AlgorithmIdentifier>,
}

impl WalletMetadata {
    /// Construct wallet metadata after validating required capability lists.
    pub fn new(
        response_modes_supported: Vec<ResponseMode>,
        request_uri_methods_supported: Vec<RequestUriMethod>,
        vp_formats_supported: Vec<CredentialFormat>,
        response_encryption_alg_values_supported: Vec<AlgorithmIdentifier>,
        response_encryption_enc_values_supported: Vec<AlgorithmIdentifier>,
    ) -> Result<Self, OpenId4vpTypeError> {
        reject_empty(response_modes_supported.is_empty())?;
        reject_empty(request_uri_methods_supported.is_empty())?;
        reject_empty(vp_formats_supported.is_empty())?;
        Ok(Self {
            response_modes_supported,
            request_uri_methods_supported,
            vp_formats_supported,
            response_encryption_alg_values_supported,
            response_encryption_enc_values_supported,
        })
    }

    /// Return whether this wallet supports a response mode.
    pub fn supports_response_mode(&self, mode: ResponseMode) -> bool {
        self.response_modes_supported.contains(&mode)
    }

    /// Return whether this wallet supports a request URI retrieval method.
    pub fn supports_request_uri_method(&self, method: RequestUriMethod) -> bool {
        self.request_uri_methods_supported.contains(&method)
    }

    /// Return whether this wallet supports a credential format.
    pub fn supports_format(&self, format: &CredentialFormat) -> bool {
        self.vp_formats_supported.iter().any(|item| item == format)
    }

    /// Return whether this wallet can encrypt authorization responses with the suite.
    pub fn supports_response_encryption(
        &self,
        alg: &AlgorithmIdentifier,
        enc: &AlgorithmIdentifier,
    ) -> bool {
        self.response_encryption_alg_values_supported
            .iter()
            .any(|item| item == alg)
            && self
                .response_encryption_enc_values_supported
                .iter()
                .any(|item| item == enc)
    }
}

/// Return the first mutually supported response mode, honoring caller order.
pub fn negotiate_response_mode(
    preferred: &[ResponseMode],
    verifier: &VerifierMetadata,
    wallet: &WalletMetadata,
) -> Result<ResponseMode, OpenId4vpTypeError> {
    for mode in preferred {
        if verifier.supports_response_mode(*mode) && wallet.supports_response_mode(*mode) {
            return Ok(*mode);
        }
    }
    Err(OpenId4vpTypeError::new(
        OpenId4vpTypeErrorReason::UnsupportedMetadataCapability,
    ))
}

fn reject_empty(is_empty: bool) -> Result<(), OpenId4vpTypeError> {
    if is_empty {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::EmptyCollection,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_dcql::CredentialFormat;

    use crate::define_metadata::{
        negotiate_response_mode, AlgorithmIdentifier, VerifierMetadata, WalletMetadata,
    };
    use crate::{ClientIdentifierPrefix, OpenId4vpTypeErrorReason, RequestUriMethod, ResponseMode};

    fn sd_jwt_format() -> CredentialFormat {
        CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
            .expect("test credential format is valid")
    }

    fn alg(value: &str) -> AlgorithmIdentifier {
        AlgorithmIdentifier::new(value.to_owned()).expect("test alg is valid")
    }

    fn verifier_metadata() -> VerifierMetadata {
        VerifierMetadata::new(
            vec![ResponseMode::DirectPostJwt, ResponseMode::DirectPost],
            vec![ClientIdentifierPrefix::X509SanDns],
            vec![sd_jwt_format()],
            vec![alg("ES256")],
            vec![alg("ECDH-ES")],
            vec![alg("A128GCM")],
        )
        .expect("verifier metadata is valid")
    }

    fn wallet_metadata() -> WalletMetadata {
        WalletMetadata::new(
            vec![ResponseMode::DirectPost],
            vec![RequestUriMethod::Get, RequestUriMethod::Post],
            vec![sd_jwt_format()],
            vec![alg("ECDH-ES")],
            vec![alg("A128GCM")],
        )
        .expect("wallet metadata is valid")
    }

    #[test]
    fn verifier_metadata_reports_capabilities() {
        let metadata = verifier_metadata();

        assert!(metadata.supports_response_mode(ResponseMode::DirectPostJwt));
        assert!(metadata.supports_client_id_prefix(ClientIdentifierPrefix::X509SanDns));
        assert!(metadata.supports_format(&sd_jwt_format()));
        assert!(metadata.supports_response_encryption(&alg("ECDH-ES"), &alg("A128GCM")));
        assert!(!metadata.supports_response_mode(ResponseMode::Fragment));
    }

    #[test]
    fn wallet_metadata_reports_capabilities() {
        let metadata = wallet_metadata();

        assert!(metadata.supports_response_mode(ResponseMode::DirectPost));
        assert!(metadata.supports_request_uri_method(RequestUriMethod::Post));
        assert!(metadata.supports_format(&sd_jwt_format()));
        assert!(metadata.supports_response_encryption(&alg("ECDH-ES"), &alg("A128GCM")));
        assert!(!metadata.supports_response_mode(ResponseMode::Fragment));
    }

    #[test]
    fn negotiates_first_mutual_response_mode() {
        let mode = negotiate_response_mode(
            &[ResponseMode::DirectPostJwt, ResponseMode::DirectPost],
            &verifier_metadata(),
            &wallet_metadata(),
        )
        .expect("direct_post is mutually supported");

        assert_eq!(mode, ResponseMode::DirectPost);
    }

    #[test]
    fn rejects_empty_required_metadata_capabilities() {
        let err = WalletMetadata::new(
            Vec::new(),
            vec![RequestUriMethod::Post],
            vec![sd_jwt_format()],
            Vec::new(),
            Vec::new(),
        )
        .expect_err("empty response mode support is rejected");

        assert_eq!(err.reason(), OpenId4vpTypeErrorReason::EmptyCollection);
    }

    #[test]
    fn rejects_empty_algorithm_identifier() {
        let err = AlgorithmIdentifier::new(String::new())
            .expect_err("empty algorithm identifier is rejected");

        assert_eq!(err.reason(), OpenId4vpTypeErrorReason::EmptyValue);
    }
}
