// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use reallyme_openid4vp_verifier::{
    HolderBindingVerifier, RequestObjectSigner, ZkPolicyRequirements,
};
use reallyme_zk_api::ZkVerifier;

use crate::AuthorizationResponseJwtDecryptor;

/// Runtime dependencies for the Connect verifier service.
#[derive(Clone)]
pub struct VerifierRuntimeConfig {
    /// Optional signer for RFC 9101 Request Object responses.
    pub signer: Option<Arc<dyn RequestObjectSigner + Send + Sync>>,
    /// Optional decryptor for encrypted `direct_post.jwt` responses.
    pub response_jwt_decryptor: Option<Arc<dyn AuthorizationResponseJwtDecryptor>>,
    /// Optional ZK verifier. ZK responses fail closed when this is absent.
    pub zk_verifier: Option<Arc<dyn ZkVerifier>>,
    /// Optional holder-binding verifier. Non-ZK presentations fail closed when absent.
    pub holder_binding_verifier: Option<Arc<dyn HolderBindingVerifier>>,
    /// Policy for accepted ZK circuit semantics.
    pub zk_policy: ZkPolicyRequirements,
}

impl VerifierRuntimeConfig {
    /// Build a config with no optional crypto backends.
    pub fn new() -> Self {
        Self {
            signer: None,
            response_jwt_decryptor: None,
            zk_verifier: None,
            holder_binding_verifier: None,
            zk_policy: ZkPolicyRequirements::default(),
        }
    }

    /// Attach a Request Object signer.
    #[must_use]
    pub fn with_signer(mut self, signer: Arc<dyn RequestObjectSigner + Send + Sync>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Attach an encrypted Authorization Response decryptor.
    #[must_use]
    pub fn with_response_jwt_decryptor(
        mut self,
        decryptor: Arc<dyn AuthorizationResponseJwtDecryptor>,
    ) -> Self {
        self.response_jwt_decryptor = Some(decryptor);
        self
    }

    /// Attach a ZK verifier.
    #[must_use]
    pub fn with_zk_verifier(mut self, verifier: Arc<dyn ZkVerifier>) -> Self {
        self.zk_verifier = Some(verifier);
        self
    }

    /// Attach a holder-binding verifier for SD-JWT, mdoc, and other envelope formats.
    #[must_use]
    pub fn with_holder_binding_verifier(
        mut self,
        verifier: Arc<dyn HolderBindingVerifier>,
    ) -> Self {
        self.holder_binding_verifier = Some(verifier);
        self
    }

    /// Attach explicit ZK policy requirements.
    #[must_use]
    pub fn with_zk_policy(mut self, policy: ZkPolicyRequirements) -> Self {
        self.zk_policy = policy;
        self
    }
}

impl Default for VerifierRuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Connect verifier service implementation backed by protocol crates.
pub struct VerifierRuntimeService {
    config: VerifierRuntimeConfig,
}

impl VerifierRuntimeService {
    /// Construct the runtime verifier service.
    pub fn new(config: VerifierRuntimeConfig) -> Self {
        Self { config }
    }

    pub(crate) fn signer(&self) -> Option<&(dyn RequestObjectSigner + Send + Sync)> {
        self.config.signer.as_deref()
    }

    pub(crate) fn response_jwt_decryptor(&self) -> Option<&dyn AuthorizationResponseJwtDecryptor> {
        self.config.response_jwt_decryptor.as_deref()
    }

    pub(crate) fn zk_verifier(&self) -> Option<&dyn ZkVerifier> {
        self.config.zk_verifier.as_deref()
    }

    pub(crate) fn holder_binding_verifier(&self) -> Option<&dyn HolderBindingVerifier> {
        self.config.holder_binding_verifier.as_deref()
    }

    pub(crate) const fn zk_policy(&self) -> ZkPolicyRequirements {
        self.config.zk_policy
    }
}
