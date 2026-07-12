// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Compile-time checks for generated ConnectRPC OpenID4VP services.

#![cfg(feature = "connect")]

use reallyme_openid4vp_proto::generated::connect::openid4vp::v1::{
    OpenId4VpDcApiServiceRegisterMarker, OpenId4VpVerifierServiceRegisterMarker,
    OpenId4VpWalletServiceRegisterMarker, OPEN_ID4_VP_DC_API_SERVICE_SERVICE_NAME,
    OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME, OPEN_ID4_VP_WALLET_SERVICE_SERVICE_NAME,
};

#[test]
fn generated_connect_services_are_exposed() {
    assert_eq!(
        OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME,
        "openid4vp.v1.OpenId4VpVerifierService"
    );
    assert_eq!(
        OPEN_ID4_VP_WALLET_SERVICE_SERVICE_NAME,
        "openid4vp.v1.OpenId4VpWalletService"
    );
    assert_eq!(
        OPEN_ID4_VP_DC_API_SERVICE_SERVICE_NAME,
        "openid4vp.v1.OpenId4VpDcApiService"
    );

    let _verifier = OpenId4VpVerifierServiceRegisterMarker;
    let _wallet = OpenId4VpWalletServiceRegisterMarker;
    let _dc_api = OpenId4VpDcApiServiceRegisterMarker;
}
