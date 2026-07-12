// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ISO mdoc presentation glue for OpenID4VP.
//!
//! ISO 18013-5 `DeviceResponse` decoding and verification is delegated to
//! `reallyme-identity`'s `envelopes-mdoc` crate. This module owns only the
//! OpenID4VP-facing adapter boundary so format verification can be injected into
//! verifier flows without duplicating CBOR structures.

use envelopes_mdoc::{verify_mdoc_device_response, MdocEnvelopeError, MdocInvalidInputReason};
use thiserror::Error;

/// OpenID4VP mdoc presentation verification input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdocPresentationVerificationInput<'a> {
    /// ISO 18013-5 DeviceResponse CBOR bytes supplied as an OpenID4VP
    /// `mso_mdoc` presentation.
    pub device_response_cbor: &'a [u8],
    /// SessionTranscript CBOR bytes constructed by `crates/dc-api` for the
    /// active OpenID4VP redirect or Digital Credentials API handover.
    pub session_transcript_cbor: &'a [u8],
    /// Optional Unix timestamp for validity-window enforcement.
    pub now_unix: Option<u64>,
}

/// Issuer public-key lookup boundary for mdoc issuer authentication.
pub trait MdocIssuerPublicKeyResolver: Send + Sync {
    /// Resolve issuer public key material from issuerAuth-provided key bytes.
    fn resolve_issuer_public_key(&self, issuer_key_id: &[u8]) -> Option<Vec<u8>>;
}

/// OpenID4VP-owned result of successful mdoc presentation verification.
///
/// The identity envelope crate owns the ISO 18013-5 CBOR model and disclosed
/// claim structures. This result intentionally exposes only protocol-safe
/// verification metadata so OpenID4VP consumers do not depend on unpublished
/// envelope types through this crate's public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMdocPresentation {
    /// Number of verified documents in the DeviceResponse.
    pub document_count: usize,
    /// Verified document types in DeviceResponse order.
    pub document_types: Vec<String>,
}

/// OpenID4VP mdoc verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("OpenID4VP mdoc format error: {reason:?}")]
pub struct MdocFormatError {
    reason: MdocFormatErrorReason,
}

impl MdocFormatError {
    /// Build an mdoc format error from a stable reason.
    pub const fn new(reason: MdocFormatErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> MdocFormatErrorReason {
        self.reason
    }
}

/// Stable OpenID4VP mdoc format error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdocFormatErrorReason {
    /// DeviceResponse bytes were empty or malformed.
    InvalidDeviceResponse,
    /// IssuerAuth signature or issuer-signed digests failed verification.
    InvalidIssuerAuthentication,
    /// DeviceAuth signature failed verification.
    InvalidDeviceAuthentication,
    /// DeviceAuthentication did not bind the expected OpenID4VP SessionTranscript.
    SessionTranscriptMismatch,
    /// mdoc document type in the DeviceResponse does not match signed content.
    DocumentTypeMismatch,
    /// DeviceResponse or MobileSecurityObject was expired for the supplied time.
    Expired,
    /// The identity mdoc provider does not support the requested operation.
    UnsupportedOperation,
}

/// Verify an OpenID4VP mdoc presentation through the identity mdoc envelope.
pub fn verify_mdoc_presentation(
    input: MdocPresentationVerificationInput<'_>,
    resolver: &impl MdocIssuerPublicKeyResolver,
) -> Result<VerifiedMdocPresentation, MdocFormatError> {
    if input.device_response_cbor.is_empty() {
        return Err(MdocFormatError::new(
            MdocFormatErrorReason::InvalidDeviceResponse,
        ));
    }
    if input.session_transcript_cbor.is_empty() {
        return Err(MdocFormatError::new(
            MdocFormatErrorReason::SessionTranscriptMismatch,
        ));
    }

    let verified = verify_mdoc_device_response(
        input.device_response_cbor,
        |issuer_key_id| resolver.resolve_issuer_public_key(issuer_key_id),
        input.session_transcript_cbor,
        input.now_unix,
    )
    .map_err(map_mdoc_envelope_error)?;

    Ok(VerifiedMdocPresentation {
        document_count: verified.verified_documents.len(),
        document_types: verified
            .verified_documents
            .iter()
            .map(|document| document.doc_type.clone())
            .collect(),
    })
}

fn map_mdoc_envelope_error(error: MdocEnvelopeError) -> MdocFormatError {
    let reason = match error {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::DocTypeMismatch) => {
            MdocFormatErrorReason::DocumentTypeMismatch
        }
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidSessionTranscript)
        | MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceAuthentication)
        | MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceNameSpaces) => {
            MdocFormatErrorReason::SessionTranscriptMismatch
        }
        MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedDeviceResponse
            | MdocInvalidInputReason::UnsupportedDeviceResponseVersion
            | MdocInvalidInputReason::InvalidDeviceResponseStatus,
        )
        | MdocEnvelopeError::Cbor => MdocFormatErrorReason::InvalidDeviceResponse,
        MdocEnvelopeError::InvalidInput(_) => MdocFormatErrorReason::InvalidIssuerAuthentication,
        MdocEnvelopeError::InvalidSignature | MdocEnvelopeError::InvalidDigest => {
            MdocFormatErrorReason::InvalidIssuerAuthentication
        }
        MdocEnvelopeError::InvalidDeviceSignature => {
            MdocFormatErrorReason::InvalidDeviceAuthentication
        }
        MdocEnvelopeError::Expired => MdocFormatErrorReason::Expired,
        MdocEnvelopeError::UnsupportedOperation => MdocFormatErrorReason::UnsupportedOperation,
        MdocEnvelopeError::Signing => MdocFormatErrorReason::InvalidIssuerAuthentication,
    };
    MdocFormatError::new(reason)
}

#[cfg(test)]
mod tests {
    use crate::mdoc::{
        verify_mdoc_presentation, MdocFormatErrorReason, MdocIssuerPublicKeyResolver,
        MdocPresentationVerificationInput,
    };

    struct EmptyResolver;

    impl MdocIssuerPublicKeyResolver for EmptyResolver {
        fn resolve_issuer_public_key(&self, _issuer_key_id: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    #[test]
    fn rejects_empty_device_response_before_identity_decode() {
        let result = verify_mdoc_presentation(
            MdocPresentationVerificationInput {
                device_response_cbor: &[],
                session_transcript_cbor: &[0xa0],
                now_unix: None,
            },
            &EmptyResolver,
        );
        assert!(result.is_err(), "empty DeviceResponse is rejected");
        let Err(err) = result else {
            return;
        };

        assert_eq!(err.reason(), MdocFormatErrorReason::InvalidDeviceResponse);
    }

    #[test]
    fn rejects_empty_session_transcript_before_identity_verify() {
        let result = verify_mdoc_presentation(
            MdocPresentationVerificationInput {
                device_response_cbor: &[0xa0],
                session_transcript_cbor: &[],
                now_unix: None,
            },
            &EmptyResolver,
        );
        assert!(result.is_err(), "empty SessionTranscript is rejected");
        let Err(err) = result else {
            return;
        };

        assert_eq!(
            err.reason(),
            MdocFormatErrorReason::SessionTranscriptMismatch
        );
    }
}
