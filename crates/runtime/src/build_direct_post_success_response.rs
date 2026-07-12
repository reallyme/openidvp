// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_types::JSON_MEDIA_TYPE;

use crate::RuntimeHttpResponse;

/// Build the OpenID4VP response-endpoint success body.
pub(crate) fn direct_post_success_response() -> RuntimeHttpResponse {
    RuntimeHttpResponse::with_body(200, JSON_MEDIA_TYPE, b"{}".to_vec())
        .with_cache_control("no-store")
}
