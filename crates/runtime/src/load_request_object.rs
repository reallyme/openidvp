// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{RuntimeError, RuntimeErrorReason};

/// Hosted Request Object material loaded by the runtime host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedRequestObject {
    /// Compact signed Request Object JWT.
    pub request_object_jwt: String,
    /// Wallet nonce expected for `request_uri_method=post`.
    pub wallet_nonce: Option<String>,
}

impl HostedRequestObject {
    /// Construct hosted Request Object material.
    pub fn new(
        request_object_jwt: String,
        wallet_nonce: Option<String>,
    ) -> Result<Self, RuntimeError> {
        if request_object_jwt.is_empty() {
            return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
        }
        if wallet_nonce.as_deref().is_some_and(str::is_empty) {
            return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
        }
        Ok(Self {
            request_object_jwt,
            wallet_nonce,
        })
    }
}

/// Storage boundary for hosted Request Objects.
pub trait RequestObjectStore: Send + Sync {
    /// Load a hosted Request Object by an adapter-defined lookup key.
    fn load_request_object(&self, key: &str) -> Result<HostedRequestObject, RuntimeError>;
}
