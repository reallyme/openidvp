// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_dcql::CredentialFormat;
use reallyme_openid4vp_types::ResponseMode;

/// High Assurance Interoperability Profile identifier.
pub const PROFILE_HAIP: &str = "haip";

/// High Assurance Interoperability Profile version implemented by this crate.
///
/// Sourced from the shared cross-protocol profile identity so issuance
/// (OpenID4VCI) and presentation (OpenID4VP) never disagree on the HAIP version.
pub const PROFILE_HAIP_VERSION: &str = reallyme_profiles::HAIP_VERSION;

/// A well-known OpenID4VP presentation profile.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenId4VpProfile {
    /// HAIP: OpenID4VC High Assurance Interoperability Profile.
    Haip,
}

impl OpenId4VpProfile {
    /// Return true when the profile is part of the eIDAS high-assurance path.
    #[must_use]
    pub const fn is_eidas_relevant(self) -> bool {
        match self {
            Self::Haip => true,
        }
    }
}

/// Returns the OpenID4VP profile identity for HAIP.
#[must_use]
pub const fn haip_profile_identity() -> OpenId4VpProfile {
    OpenId4VpProfile::Haip
}

/// HAIP presentation flow supported by the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaipPresentationFlow {
    /// Browser redirect/direct_post OpenID4VP presentation.
    Redirect,
    /// W3C Digital Credentials API presentation.
    DigitalCredentialsApi,
}

/// Credential format required by HAIP presentation interoperability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaipCredentialFormat {
    /// IETF SD-JWT VC.
    SdJwtVc,
    /// ISO 18013-5 mdoc.
    Mdoc,
}

impl HaipCredentialFormat {
    /// Return the OpenID4VP/DCQL credential format identifier.
    pub const fn dcql_format(self) -> &'static str {
        match self {
            Self::SdJwtVc => CredentialFormat::DC_SD_JWT,
            Self::Mdoc => CredentialFormat::MSO_MDOC,
        }
    }
}

/// HAIP presentation profile capabilities for OpenID4VP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaipPresentationProfile {
    /// Profile identifier.
    pub profile: &'static str,
    /// Profile version.
    pub version: &'static str,
    /// Presentation flows supported by this crate boundary.
    pub flows: &'static [HaipPresentationFlow],
    /// Credential formats at least one of which each flow must support.
    pub credential_formats: &'static [HaipCredentialFormat],
    /// OpenID4VP response modes allowed by these flows.
    pub response_modes: &'static [ResponseMode],
}

/// HAIP-supported presentation flows.
pub const HAIP_PRESENTATION_FLOWS: &[HaipPresentationFlow] = &[
    HaipPresentationFlow::Redirect,
    HaipPresentationFlow::DigitalCredentialsApi,
];

/// HAIP credential formats profiled for presentation.
pub const HAIP_CREDENTIAL_FORMATS: &[HaipCredentialFormat] =
    &[HaipCredentialFormat::SdJwtVc, HaipCredentialFormat::Mdoc];

/// HAIP OpenID4VP response modes covered by this repo.
pub const HAIP_RESPONSE_MODES: &[ResponseMode] = &[
    ResponseMode::DirectPost,
    ResponseMode::DirectPostJwt,
    ResponseMode::DcApi,
    ResponseMode::DcApiJwt,
];

/// Return the HAIP presentation profile capabilities.
pub const fn haip_presentation_profile() -> HaipPresentationProfile {
    HaipPresentationProfile {
        profile: PROFILE_HAIP,
        version: PROFILE_HAIP_VERSION,
        flows: HAIP_PRESENTATION_FLOWS,
        credential_formats: HAIP_CREDENTIAL_FORMATS,
        response_modes: HAIP_RESPONSE_MODES,
    }
}

#[cfg(test)]
mod tests {
    use reallyme_openid4vp_types::ResponseMode;

    use crate::describe_haip::{
        haip_presentation_profile, HaipCredentialFormat, HaipPresentationFlow,
    };

    #[test]
    fn haip_shares_cross_protocol_identity() {
        use crate::describe_haip::{haip_profile_identity, PROFILE_HAIP_VERSION};

        assert_eq!(PROFILE_HAIP_VERSION, reallyme_profiles::HAIP_VERSION);
        assert!(haip_profile_identity().is_eidas_relevant());
        assert_eq!(
            reallyme_profiles::Profile::Haip.short_name(),
            reallyme_profiles::HAIP_SHORT_NAME
        );
    }

    #[test]
    fn haip_profile_includes_dc_api_and_mdoc() {
        let profile = haip_presentation_profile();

        assert!(profile
            .flows
            .contains(&HaipPresentationFlow::DigitalCredentialsApi));
        assert!(profile
            .credential_formats
            .contains(&HaipCredentialFormat::Mdoc));
        assert!(profile.response_modes.contains(&ResponseMode::DcApiJwt));
    }
}
