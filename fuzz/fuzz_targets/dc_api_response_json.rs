// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_dc_api::{DcApiAuthorizationResponse, EncryptedDcApiAuthorizationResponse};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<DcApiAuthorizationResponse>(data);
    let _ = serde_json::from_slice::<EncryptedDcApiAuthorizationResponse>(data);
});
