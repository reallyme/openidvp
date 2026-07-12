// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Optional HTTP transport adapter traits for OpenID4VP.

mod build_request_uri_http_request;
mod error;
mod resolve_request_uri;

pub use build_request_uri_http_request::{
    build_request_uri_http_request, RequestUriHttpRequest, REQUEST_URI_POST_CONTENT_TYPE,
};
pub use error::{HttpAdapterError, HttpAdapterErrorReason};
pub use resolve_request_uri::{
    resolve_request_uri_transport, RequestObjectHttpResponse, RequestUriFetcher,
    RequestUriResolutionPolicy,
};
