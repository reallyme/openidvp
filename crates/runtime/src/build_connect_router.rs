// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use connectrpc::Router;
use reallyme_openid4vp_proto::generated::connect::openid4vp::v1::{
    OpenId4VpDcApiServiceExt, OpenId4VpVerifierServiceExt,
};

use crate::VerifierRuntimeService;

/// Build a Connect router with the OpenID4VP verifier service registered.
pub fn build_verifier_connect_router(service: Arc<VerifierRuntimeService>) -> Router {
    let router = OpenId4VpVerifierServiceExt::register(Arc::clone(&service), Router::new());
    OpenId4VpDcApiServiceExt::register(service, router)
}
