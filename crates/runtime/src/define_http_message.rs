// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// HTTP method understood by the runtime endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
}

/// Framework-neutral HTTP request projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeHttpRequest {
    /// Request method.
    pub method: RuntimeHttpMethod,
    /// Raw Accept header, when present.
    pub accept: Option<String>,
    /// Raw Content-Type header, when present.
    pub content_type: Option<String>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

/// Framework-neutral HTTP response projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response Content-Type.
    pub content_type: Option<&'static str>,
    /// Cache-Control header.
    pub cache_control: Option<&'static str>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl RuntimeHttpResponse {
    /// Build an empty response.
    pub const fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: None,
            cache_control: None,
            body: Vec::new(),
        }
    }

    /// Build a response with body and content type.
    pub fn with_body(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: Some(content_type),
            cache_control: None,
            body,
        }
    }

    /// Attach a Cache-Control header value.
    #[must_use]
    pub const fn with_cache_control(mut self, value: &'static str) -> Self {
        self.cache_control = Some(value);
        self
    }
}
