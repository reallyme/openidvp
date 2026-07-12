// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::ClientIdentifier;
use sha2::{Digest, Sha256};

use crate::{DcApiError, DcApiErrorReason};

/// Length of SHA-256 digests used by ISO/IEC 18013-7 Annex B handover inputs.
pub const SHA256_DIGEST_BYTES: usize = 32;

/// Base64url encoded ISO 18013-5 `DeviceResponse` produced by `envelopes-mdoc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdocDeviceResponseB64(String);

impl MdocDeviceResponseB64 {
    /// Construct a non-empty base64url DeviceResponse wrapper.
    pub fn new(value: String) -> Result<Self, DcApiError> {
        if value.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::EmptyValue));
        }
        Ok(Self(value))
    }

    /// Return the encoded DeviceResponse value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Handover variant used when constructing the ISO 18013-7 SessionTranscript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverKind {
    /// OpenID4VP redirect/direct_post handover.
    Redirect,
    /// OpenID4VP Digital Credentials API handover.
    DigitalCredentialsApi,
}

/// Redirect/direct_post handover input from OpenID4VP Annex B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenId4VpRedirectHandover {
    /// Full final-spec client identifier.
    pub client_id: ClientIdentifier,
    /// Request nonce bound into mdoc device authentication.
    pub nonce: String,
    /// SHA-256 JWK thumbprint of the verifier response encryption key.
    pub jwk_thumbprint_sha256: [u8; SHA256_DIGEST_BYTES],
    /// Response endpoint used in the OpenID4VP flow.
    pub response_uri: String,
}

/// Digital Credentials API handover input from OpenID4VP Annex B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenId4VpDcApiHandover {
    /// Browser origin invoking `navigator.credentials.get()`.
    pub origin: String,
    /// Request nonce bound into mdoc device authentication.
    pub nonce: String,
    /// SHA-256 JWK thumbprint for `dc_api.jwt`; absent for plain `dc_api`.
    pub jwk_thumbprint_sha256: Option<[u8; SHA256_DIGEST_BYTES]>,
}

/// Union of handover inputs delegated to the mdoc CBOR encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoverDigestInput {
    /// Redirect/direct_post handover.
    Redirect(OpenId4VpRedirectHandover),
    /// Digital Credentials API handover.
    DigitalCredentialsApi(OpenId4VpDcApiHandover),
}

/// Encoded CBOR handover info produced by an mdoc-aware adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedHandoverInfo {
    bytes: Vec<u8>,
}

impl EncodedHandoverInfo {
    /// Construct non-empty encoded handover bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, DcApiError> {
        if bytes.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::HandoverEncodingFailed));
        }
        Ok(Self { bytes })
    }

    /// Return encoded handover bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Adapter boundary for ISO 18013-7 handover CBOR construction.
///
/// `dc-api` owns the OpenID4VP/DC API field selection, while `envelopes-mdoc`
/// owns the mdoc/CBOR structure. This trait is the narrow integration point so
/// this crate never reimplements ISO 18013-5 `DeviceResponse` data structures.
pub trait MdocHandoverCborEncoder: Send + Sync {
    /// Encode handover info as CBOR suitable for SessionTranscript construction.
    fn encode_handover_info(
        &self,
        input: &HandoverDigestInput,
    ) -> Result<EncodedHandoverInfo, DcApiError>;
}

/// SHA-256 digest of the encoded handover info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoverDigest {
    /// Handover variant.
    pub kind: HandoverKind,
    /// SHA-256 digest over the encoded handover info.
    pub digest: [u8; SHA256_DIGEST_BYTES],
}

/// Local status of the delegated identity mdoc envelope implementation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenId4VpMdocEnvelopeStatus {
    /// Issuer-signed mdoc issuance and verification are available.
    IssuerSignedReady,
    /// Issuer-signed mdoc and DeviceResponse presentation support are available.
    PresentationReady,
}

/// Build the redirect/direct_post handover digest for an ISO mdoc response.
pub fn build_redirect_handover_digest(
    input: OpenId4VpRedirectHandover,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<HandoverDigest, DcApiError> {
    build_handover_digest(HandoverDigestInput::Redirect(input), encoder)
}

/// Build the Digital Credentials API handover digest for an ISO mdoc response.
pub fn build_dc_api_handover_digest(
    input: OpenId4VpDcApiHandover,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<HandoverDigest, DcApiError> {
    build_handover_digest(HandoverDigestInput::DigitalCredentialsApi(input), encoder)
}

fn build_handover_digest(
    input: HandoverDigestInput,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<HandoverDigest, DcApiError> {
    let encoded = encoder.encode_handover_info(&input)?;
    let mut hasher = Sha256::new();
    hasher.update(encoded.as_bytes());
    let digest = hasher.finalize().into();
    let kind = match input {
        HandoverDigestInput::Redirect(_) => HandoverKind::Redirect,
        HandoverDigestInput::DigitalCredentialsApi(_) => HandoverKind::DigitalCredentialsApi,
    };
    Ok(HandoverDigest { kind, digest })
}

/// Report the delegated identity mdoc implementation status.
pub const fn mdoc_envelope_status() -> OpenId4VpMdocEnvelopeStatus {
    match envelopes_mdoc::mdoc_envelope_status() {
        envelopes_mdoc::MdocEnvelopeStatus::IssuerSignedReady => {
            OpenId4VpMdocEnvelopeStatus::IssuerSignedReady
        }
        envelopes_mdoc::MdocEnvelopeStatus::PresentationReady => {
            OpenId4VpMdocEnvelopeStatus::PresentationReady
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::mdoc::{
        build_dc_api_handover_digest, mdoc_envelope_status, EncodedHandoverInfo,
        HandoverDigestInput, HandoverKind, MdocHandoverCborEncoder, OpenId4VpDcApiHandover,
        OpenId4VpMdocEnvelopeStatus, SHA256_DIGEST_BYTES,
    };
    use crate::DcApiError;

    struct FixtureEncoder;

    impl MdocHandoverCborEncoder for FixtureEncoder {
        fn encode_handover_info(
            &self,
            input: &HandoverDigestInput,
        ) -> Result<EncodedHandoverInfo, DcApiError> {
            let marker = match input {
                HandoverDigestInput::Redirect(_) => vec![0x01],
                HandoverDigestInput::DigitalCredentialsApi(_) => vec![0x02],
            };
            EncodedHandoverInfo::new(marker)
        }
    }

    #[test]
    fn computes_digest_from_delegated_handover_bytes() {
        let digest = build_dc_api_handover_digest(
            OpenId4VpDcApiHandover {
                origin: "https://rp.example".to_owned(),
                nonce: "nonce".to_owned(),
                jwk_thumbprint_sha256: None,
            },
            &FixtureEncoder,
        )
        .expect("fixture handover encodes");

        assert_eq!(digest.kind, HandoverKind::DigitalCredentialsApi);
        assert_eq!(digest.digest.len(), SHA256_DIGEST_BYTES);
    }

    #[test]
    fn maps_identity_mdoc_status_to_local_status() {
        assert_eq!(
            mdoc_envelope_status(),
            OpenId4VpMdocEnvelopeStatus::PresentationReady
        );
    }
}
