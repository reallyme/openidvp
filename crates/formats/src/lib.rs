// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Format-specific presentation glue for SD-JWT VC, mdoc, and W3C VC.

pub mod mdoc;
mod prove_zk_presentation;
mod report_zk_error;

/// OpenID4VP final SD-JWT VC format identifier.
pub const FORMAT_DC_SD_JWT: &str = reallyme_openid4vp_dcql::CredentialFormat::DC_SD_JWT;

/// OpenID4VP final ISO mdoc format identifier.
pub const FORMAT_MSO_MDOC: &str = reallyme_openid4vp_dcql::CredentialFormat::MSO_MDOC;

/// ReallyMe ZK presentation format marker.
pub const FORMAT_REALLYME_ZK: &str = prove_zk_presentation::ZK_PRESENTATION_TYPE;

pub use prove_zk_presentation::{
    build_zk_session_binding, hash_openid4vp_audience, hash_openid4vp_nonce,
    is_zk_presentation_value, parse_zk_presentation_value, prove_zk_presentation,
    verify_zk_presentation, DerivedClaimStatement, ZkPresentation, ZkPresentationBinding,
    ZkPresentationCircuitRef, ZkPresentationProveRequest, ZK_PRESENTATION_TYPE,
};
pub use report_zk_error::{ZkFormatError, ZkFormatErrorReason};
