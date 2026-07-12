// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! OpenID4VP bindings for the W3C Digital Credentials API and ISO 18013-7 Annex B.
//!
//! The W3C Digital Credentials API is an Editor's Draft, so wire details here
//! are deliberately small, typed, and isolated behind this crate. OpenID4VP
//! profile and transport crates should depend on these models rather than
//! duplicating draft-specific strings.

mod error;
mod mdoc;
mod request;
mod response;

pub use error::{DcApiError, DcApiErrorReason};
pub use mdoc::{
    build_dc_api_handover_digest, build_redirect_handover_digest, mdoc_envelope_status,
    EncodedHandoverInfo, HandoverDigest, HandoverDigestInput, HandoverKind, MdocDeviceResponseB64,
    MdocHandoverCborEncoder, OpenId4VpDcApiHandover, OpenId4VpMdocEnvelopeStatus,
    OpenId4VpRedirectHandover, SHA256_DIGEST_BYTES,
};
pub use request::{
    DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest, DigitalCredentialGetRequestData,
    DigitalCredentialRequestOptions, OPENID4VP_PROTOCOL_PREFIX,
};
pub use response::{DcApiAuthorizationResponse, EncryptedDcApiAuthorizationResponse};
