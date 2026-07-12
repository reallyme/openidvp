// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wallet-side OpenID4VP request verification and response construction boundary.

mod derive_zk_presentation;
mod error;
mod jar;
mod metadata_reference;
mod prepare_consent_data;
mod transport;
mod validate_endpoint_binding;
mod verifier_attestation;
#[cfg(feature = "jose")]
mod verify_nested_request_object_with_jose;
#[cfg(feature = "jose")]
mod verify_signed_request_object_with_jose;

pub use derive_zk_presentation::derive_zk_presentation;
pub use error::{WalletError, WalletErrorReason};
pub use jar::{
    validate_transport_client_id_binding, validate_wallet_request_object,
    validate_wallet_request_object_with_evidence, validate_wallet_request_object_with_trust,
    verify_request_transport, verify_signed_request_object, RequestObjectSignatureVerifier,
    VerifiedWalletRequest, WalletRequestTrustEvidence,
};
pub use metadata_reference::{
    validate_client_metadata_reference_binding, VerifiedClientMetadataReference,
};
pub use prepare_consent_data::prepare_consent_data;
pub use transport::{
    parse_authorization_request_transport, AuthorizationRequestTransport, RequestTransportPolicy,
};
pub use validate_endpoint_binding::validate_response_endpoint_binding;
pub use validate_endpoint_binding::VerifiedX509CertificateBinding;
pub use verifier_attestation::{
    validate_verifier_attestation_binding, VerifiedVerifierAttestation,
};
#[cfg(feature = "jose")]
pub use verify_nested_request_object_with_jose::JoseNestedRequestObjectVerifier;
#[cfg(feature = "jose")]
pub use verify_signed_request_object_with_jose::{
    JoseRequestObjectVerificationKey, JoseRequestObjectVerificationKeyResolver,
    JoseSignedRequestObjectVerifier,
};
