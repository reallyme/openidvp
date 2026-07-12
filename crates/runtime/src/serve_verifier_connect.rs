// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use connectrpc::{Router, Server};

use crate::{
    build_verifier_connect_router, RuntimeError, RuntimeErrorReason, VerifierRuntimeService,
};

/// Build the native ConnectRPC server for the OpenID4VP verifier API.
///
/// Browser callback endpoints such as `direct_post` are intentionally not
/// mounted here. They are HTTP endpoints, not RPC methods, and should be
/// served by the host framework through [`crate::VerifierHttpRuntime`] so the
/// same validation path is used by services, SDKs, and tests.
pub fn build_verifier_connect_server(service: Arc<VerifierRuntimeService>) -> Server {
    Server::new(build_verifier_connect_router(service))
}

/// Serve the verifier Connect API until the process exits or transport fails.
pub async fn serve_verifier_connect(
    service: Arc<VerifierRuntimeService>,
    addr: SocketAddr,
) -> Result<(), RuntimeError> {
    build_verifier_connect_server(service)
        .serve(addr)
        .await
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::ConnectServerServeFailed))
}

/// Bind and serve the verifier Connect API with caller-controlled shutdown.
///
/// This is the preferred entry point for production hosts because it gives the
/// top-level service a deterministic shutdown signal for deploys and tests.
pub async fn serve_verifier_connect_with_shutdown<F>(
    service: Arc<VerifierRuntimeService>,
    addr: SocketAddr,
    shutdown: F,
) -> Result<(), RuntimeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let bound = Server::bind(addr)
        .await
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::ConnectServerBindFailed))?;
    let router: Router = build_verifier_connect_router(service);
    bound
        .serve_with_graceful_shutdown(router, shutdown)
        .await
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::ConnectServerServeFailed))
}
