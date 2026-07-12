// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Public facade for ReallyMe OpenID4VP crates.

#[path = "configure_policy.rs"]
pub mod policy;

#[cfg(feature = "dc-api")]
pub use reallyme_openid4vp_dc_api as dc_api;
pub use reallyme_openid4vp_dcql as dcql;
#[cfg(feature = "formats")]
pub use reallyme_openid4vp_formats as formats;
#[cfg(feature = "http")]
pub use reallyme_openid4vp_http as http;
#[cfg(feature = "profiles")]
pub use reallyme_openid4vp_profiles as profiles;
#[cfg(feature = "proto")]
pub use reallyme_openid4vp_proto as proto;
#[cfg(feature = "proto")]
pub use reallyme_openid4vp_proto_codec as proto_codec;
#[cfg(feature = "runtime")]
pub use reallyme_openid4vp_runtime as runtime;
pub use reallyme_openid4vp_types as types;
pub use reallyme_openid4vp_verifier as verifier;
pub use reallyme_openid4vp_wallet as wallet;
