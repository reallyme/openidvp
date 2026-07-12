// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

///Shorthand for `OwnedView<BuildAuthorizationRequestRequestView<'static>>`.
pub type OwnedBuildAuthorizationRequestRequestView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<BuildAuthorizationRequestResponseView<'static>>`.
pub type OwnedBuildAuthorizationRequestResponseView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ValidateAuthorizationResponseRequestView<'static>>`.
pub type OwnedValidateAuthorizationResponseRequestView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ValidateAuthorizationResponseResponseView<'static>>`.
pub type OwnedValidateAuthorizationResponseResponseView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ParseAuthorizationRequestTransportRequestView<'static>>`.
pub type OwnedParseAuthorizationRequestTransportRequestView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ParseAuthorizationRequestTransportResponseView<'static>>`.
pub type OwnedParseAuthorizationRequestTransportResponseView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<VerifyAuthorizationRequestRequestView<'static>>`.
pub type OwnedVerifyAuthorizationRequestRequestView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<VerifyAuthorizationRequestResponseView<'static>>`.
pub type OwnedVerifyAuthorizationRequestResponseView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<BuildDigitalCredentialRequestOptionsRequestView<'static>>`.
pub type OwnedBuildDigitalCredentialRequestOptionsRequestView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<BuildDigitalCredentialRequestOptionsResponseView<'static>>`.
pub type OwnedBuildDigitalCredentialRequestOptionsResponseView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<DecodeDcApiAuthorizationResponseRequestView<'static>>`.
pub type OwnedDecodeDcApiAuthorizationResponseRequestView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<DecodeDcApiAuthorizationResponseResponseView<'static>>`.
pub type OwnedDecodeDcApiAuthorizationResponseResponseView = ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseResponseView<
        'static,
    >,
>;
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestResponse,
>
for crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestResponse,
>
for ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseResponse,
>
for crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseResponse,
>
for ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportResponse,
>
for crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportResponse,
>
for ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestResponse,
>
for crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestResponse,
>
for ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsResponse,
>
for crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsResponse,
>
for ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseResponse,
>
for crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseResponse,
>
for ::buffa::view::OwnedView<
    crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
/// Full service name for this service.
pub const OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME: &str = "openid4vp.v1.OpenId4VpVerifierService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `BuildAuthorizationRequest` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const OPEN_ID4_VP_VERIFIER_SERVICE_BUILD_AUTHORIZATION_REQUEST_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/openid4vp.v1.OpenId4VpVerifierService/BuildAuthorizationRequest",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ValidateAuthorizationResponse` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const OPEN_ID4_VP_VERIFIER_SERVICE_VALIDATE_AUTHORIZATION_RESPONSE_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/openid4vp.v1.OpenId4VpVerifierService/ValidateAuthorizationResponse",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// OpenId4VpVerifierService is the Connect verifier boundary.
///
/// # Implementing handlers
///
/// Implement methods with plain `async fn`; the returned future satisfies
/// the `Send` bound automatically.
///
/// **Unary and server-streaming requests** arrive as
/// [`ServiceRequest<'_, Req>`](::connectrpc::ServiceRequest): a zero-copy
/// view of the request plus its body, valid for the duration of the call.
/// Fields are read directly (`request.name` is a `&str` into the decoded
/// buffer) and the borrow may be held across `.await` points. Anything
/// that must outlive the call — `tokio::spawn`, channels, server state,
/// or data captured by a returned response stream — takes owned data:
/// call `request.to_owned_message()` (or copy the specific fields)
/// first.
///
/// **Client-streaming and bidi requests** arrive as
/// [`InboundStream<Req>`](::connectrpc::InboundStream) — a
/// `ServiceStream` of [`StreamMessage`](::connectrpc::StreamMessage)s.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.8.0 and views enabled so the
/// backing `HasMessageView` impl exists.
///
/// The `impl Encodable<Out>` return bound accepts the owned `Out`, the
/// generated `OutView<'_>` / `OwnedOutView`,
/// [`MaybeBorrowed`](::connectrpc::MaybeBorrowed), or
/// [`PreEncoded`](::connectrpc::PreEncoded) for handlers that encode a
/// non-`'static` view internally and pass the bytes across the handler
/// boundary. View bodies are not emitted for output types mapped via
/// `extern_path` (the impl would be an orphan); return owned for
/// WKT/extern outputs.
///
/// Server-streaming and bidi-streaming methods return
/// `ServiceStream<impl Encodable<Out> + Send + use<Self>>`. The
/// `use<Self>` precise-capturing clause excludes `&self`'s lifetime and
/// the request's lifetime (unary methods use `use<'a, Self>` and may
/// borrow from `&self`), so stream items must be `'static` and cannot
/// borrow from the request. To stream view-encoded data, encode each
/// item inside the stream body and yield
/// [`PreEncoded`](::connectrpc::PreEncoded) — see its `# Streaming
/// example` doc.
#[allow(clippy::type_complexity)]
pub trait OpenId4VpVerifierService: Send + Sync + 'static {
    /// Handle the BuildAuthorizationRequest RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn build_authorization_request<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the ValidateAuthorizationResponse RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn validate_authorization_response<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
/// Prefer [`Router::add_service`](::connectrpc::Router::add_service) for
/// top-down registration; `register` remains available for compatibility
/// and cases where the service-first call shape is more convenient.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait OpenId4VpVerifierServiceExt: OpenId4VpVerifierService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: OpenId4VpVerifierService> OpenId4VpVerifierServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME,
                "BuildAuthorizationRequest",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.build_authorization_request(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(OPEN_ID4_VP_VERIFIER_SERVICE_BUILD_AUTHORIZATION_REQUEST_SPEC)
            .route_view(
                OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME,
                "ValidateAuthorizationResponse",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.validate_authorization_response(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(OPEN_ID4_VP_VERIFIER_SERVICE_VALIDATE_AUTHORIZATION_RESPONSE_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct OpenId4VpVerifierServiceRegisterMarker;
impl<
    S: OpenId4VpVerifierService,
> ::connectrpc::ServiceRegister<OpenId4VpVerifierServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as OpenId4VpVerifierServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `OpenId4VpVerifierService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = OpenId4VpVerifierServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct OpenId4VpVerifierServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: OpenId4VpVerifierService> OpenId4VpVerifierServiceServer<T> {
    /// Wrap a service implementation in a monomorphic dispatcher.
    pub fn new(service: T) -> Self {
        Self {
            inner: ::std::sync::Arc::new(service),
        }
    }
    /// Wrap an already-`Arc`'d service implementation.
    pub fn from_arc(inner: ::std::sync::Arc<T>) -> Self {
        Self { inner }
    }
}
impl<T> Clone for OpenId4VpVerifierServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: OpenId4VpVerifierService> ::connectrpc::Dispatcher
for OpenId4VpVerifierServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("openid4vp.v1.OpenId4VpVerifierService/")?;
        match method {
            "BuildAuthorizationRequest" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            OPEN_ID4_VP_VERIFIER_SERVICE_BUILD_AUTHORIZATION_REQUEST_SPEC,
                        ),
                )
            }
            "ValidateAuthorizationResponse" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            OPEN_ID4_VP_VERIFIER_SERVICE_VALIDATE_AUTHORIZATION_RESPONSE_SPEC,
                        ),
                )
            }
            _ => None,
        }
    }
    fn call_unary(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::Payload,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpVerifierService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "BuildAuthorizationRequest" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestRequest,
                    >::from_parts(&req, &body);
                    svc.build_authorization_request(ctx, req)
                        .await?
                        .encode::<
                            crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestResponse,
                        >(format)
                })
            }
            "ValidateAuthorizationResponse" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseRequest,
                    >::from_parts(&req, &body);
                    svc.validate_authorization_response(ctx, req)
                        .await?
                        .encode::<
                            crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseResponse,
                        >(format)
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_server_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::buffa::bytes::Bytes,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpVerifierService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
    fn call_client_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpVerifierService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_bidi_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpVerifierService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
}
/// Client for this service.
///
/// Generic over `T: ClientTransport`. For **gRPC** (HTTP/2), use
/// `Http2Connection` — it has honest `poll_ready` and composes with
/// `tower::balance` for multi-connection load balancing. For **Connect
/// over HTTP/1.1** (or unknown protocol), use `HttpClient`.
///
/// # Example (gRPC / HTTP/2)
///
/// ```rust,ignore
/// use connectrpc::client::{Http2Connection, ClientConfig};
/// use connectrpc::Protocol;
///
/// let uri: http::Uri = "http://localhost:8080".parse()?;
/// let conn = Http2Connection::connect_plaintext(uri.clone()).await?.shared(1024);
/// let config = ClientConfig::new(uri).with_protocol(Protocol::Grpc);
///
/// let client = OpenId4VpVerifierServiceClient::new(conn, config);
/// let response = client.build_authorization_request(request).await?;
/// ```
///
/// # Example (Connect / HTTP/1.1 or ALPN)
///
/// ```rust,ignore
/// use connectrpc::client::{HttpClient, ClientConfig};
///
/// let http = HttpClient::plaintext();  // cleartext http:// only
/// let config = ClientConfig::new("http://localhost:8080".parse()?);
///
/// let client = OpenId4VpVerifierServiceClient::new(http, config);
/// let response = client.build_authorization_request(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.build_authorization_request(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.build_authorization_request(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct OpenId4VpVerifierServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> OpenId4VpVerifierServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::connectrpc::http_body::Body>::Error: ::std::fmt::Display,
{
    /// Create a new client with the given transport and configuration.
    pub fn new(transport: T, config: ::connectrpc::client::ClientConfig) -> Self {
        Self { transport, config }
    }
    /// Get the client configuration.
    pub fn config(&self) -> &::connectrpc::client::ClientConfig {
        &self.config
    }
    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ::connectrpc::client::ClientConfig {
        &mut self.config
    }
    /// Call the BuildAuthorizationRequest RPC. Sends a request to /openid4vp.v1.OpenId4VpVerifierService/BuildAuthorizationRequest.
    pub async fn build_authorization_request(
        &self,
        request: crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.build_authorization_request_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the BuildAuthorizationRequest RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn build_authorization_request_with_options(
        &self,
        request: crate::generated::proto::openid4vp::v1::BuildAuthorizationRequestRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::BuildAuthorizationRequestResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME,
                "BuildAuthorizationRequest",
                request,
                options,
            )
            .await
    }
    /// Call the ValidateAuthorizationResponse RPC. Sends a request to /openid4vp.v1.OpenId4VpVerifierService/ValidateAuthorizationResponse.
    pub async fn validate_authorization_response(
        &self,
        request: crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.validate_authorization_response_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ValidateAuthorizationResponse RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn validate_authorization_response_with_options(
        &self,
        request: crate::generated::proto::openid4vp::v1::ValidateAuthorizationResponseRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::ValidateAuthorizationResponseResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                OPEN_ID4_VP_VERIFIER_SERVICE_SERVICE_NAME,
                "ValidateAuthorizationResponse",
                request,
                options,
            )
            .await
    }
}
/// Full service name for this service.
pub const OPEN_ID4_VP_WALLET_SERVICE_SERVICE_NAME: &str = "openid4vp.v1.OpenId4VpWalletService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ParseAuthorizationRequestTransport` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const OPEN_ID4_VP_WALLET_SERVICE_PARSE_AUTHORIZATION_REQUEST_TRANSPORT_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/openid4vp.v1.OpenId4VpWalletService/ParseAuthorizationRequestTransport",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `VerifyAuthorizationRequest` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const OPEN_ID4_VP_WALLET_SERVICE_VERIFY_AUTHORIZATION_REQUEST_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/openid4vp.v1.OpenId4VpWalletService/VerifyAuthorizationRequest",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// OpenId4VpWalletService is the Connect wallet boundary.
///
/// # Implementing handlers
///
/// Implement methods with plain `async fn`; the returned future satisfies
/// the `Send` bound automatically.
///
/// **Unary and server-streaming requests** arrive as
/// [`ServiceRequest<'_, Req>`](::connectrpc::ServiceRequest): a zero-copy
/// view of the request plus its body, valid for the duration of the call.
/// Fields are read directly (`request.name` is a `&str` into the decoded
/// buffer) and the borrow may be held across `.await` points. Anything
/// that must outlive the call — `tokio::spawn`, channels, server state,
/// or data captured by a returned response stream — takes owned data:
/// call `request.to_owned_message()` (or copy the specific fields)
/// first.
///
/// **Client-streaming and bidi requests** arrive as
/// [`InboundStream<Req>`](::connectrpc::InboundStream) — a
/// `ServiceStream` of [`StreamMessage`](::connectrpc::StreamMessage)s.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.8.0 and views enabled so the
/// backing `HasMessageView` impl exists.
///
/// The `impl Encodable<Out>` return bound accepts the owned `Out`, the
/// generated `OutView<'_>` / `OwnedOutView`,
/// [`MaybeBorrowed`](::connectrpc::MaybeBorrowed), or
/// [`PreEncoded`](::connectrpc::PreEncoded) for handlers that encode a
/// non-`'static` view internally and pass the bytes across the handler
/// boundary. View bodies are not emitted for output types mapped via
/// `extern_path` (the impl would be an orphan); return owned for
/// WKT/extern outputs.
///
/// Server-streaming and bidi-streaming methods return
/// `ServiceStream<impl Encodable<Out> + Send + use<Self>>`. The
/// `use<Self>` precise-capturing clause excludes `&self`'s lifetime and
/// the request's lifetime (unary methods use `use<'a, Self>` and may
/// borrow from `&self`), so stream items must be `'static` and cannot
/// borrow from the request. To stream view-encoded data, encode each
/// item inside the stream body and yield
/// [`PreEncoded`](::connectrpc::PreEncoded) — see its `# Streaming
/// example` doc.
#[allow(clippy::type_complexity)]
pub trait OpenId4VpWalletService: Send + Sync + 'static {
    /// Handle the ParseAuthorizationRequestTransport RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn parse_authorization_request_transport<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the VerifyAuthorizationRequest RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn verify_authorization_request<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
/// Prefer [`Router::add_service`](::connectrpc::Router::add_service) for
/// top-down registration; `register` remains available for compatibility
/// and cases where the service-first call shape is more convenient.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait OpenId4VpWalletServiceExt: OpenId4VpWalletService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: OpenId4VpWalletService> OpenId4VpWalletServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                OPEN_ID4_VP_WALLET_SERVICE_SERVICE_NAME,
                "ParseAuthorizationRequestTransport",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.parse_authorization_request_transport(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(
                OPEN_ID4_VP_WALLET_SERVICE_PARSE_AUTHORIZATION_REQUEST_TRANSPORT_SPEC,
            )
            .route_view(
                OPEN_ID4_VP_WALLET_SERVICE_SERVICE_NAME,
                "VerifyAuthorizationRequest",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.verify_authorization_request(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(OPEN_ID4_VP_WALLET_SERVICE_VERIFY_AUTHORIZATION_REQUEST_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct OpenId4VpWalletServiceRegisterMarker;
impl<
    S: OpenId4VpWalletService,
> ::connectrpc::ServiceRegister<OpenId4VpWalletServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as OpenId4VpWalletServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `OpenId4VpWalletService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = OpenId4VpWalletServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct OpenId4VpWalletServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: OpenId4VpWalletService> OpenId4VpWalletServiceServer<T> {
    /// Wrap a service implementation in a monomorphic dispatcher.
    pub fn new(service: T) -> Self {
        Self {
            inner: ::std::sync::Arc::new(service),
        }
    }
    /// Wrap an already-`Arc`'d service implementation.
    pub fn from_arc(inner: ::std::sync::Arc<T>) -> Self {
        Self { inner }
    }
}
impl<T> Clone for OpenId4VpWalletServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: OpenId4VpWalletService> ::connectrpc::Dispatcher
for OpenId4VpWalletServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("openid4vp.v1.OpenId4VpWalletService/")?;
        match method {
            "ParseAuthorizationRequestTransport" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            OPEN_ID4_VP_WALLET_SERVICE_PARSE_AUTHORIZATION_REQUEST_TRANSPORT_SPEC,
                        ),
                )
            }
            "VerifyAuthorizationRequest" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            OPEN_ID4_VP_WALLET_SERVICE_VERIFY_AUTHORIZATION_REQUEST_SPEC,
                        ),
                )
            }
            _ => None,
        }
    }
    fn call_unary(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::Payload,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpWalletService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "ParseAuthorizationRequestTransport" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportRequest,
                    >::from_parts(&req, &body);
                    svc.parse_authorization_request_transport(ctx, req)
                        .await?
                        .encode::<
                            crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportResponse,
                        >(format)
                })
            }
            "VerifyAuthorizationRequest" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestRequest,
                    >::from_parts(&req, &body);
                    svc.verify_authorization_request(ctx, req)
                        .await?
                        .encode::<
                            crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestResponse,
                        >(format)
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_server_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::buffa::bytes::Bytes,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpWalletService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
    fn call_client_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpWalletService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_bidi_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpWalletService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
}
/// Client for this service.
///
/// Generic over `T: ClientTransport`. For **gRPC** (HTTP/2), use
/// `Http2Connection` — it has honest `poll_ready` and composes with
/// `tower::balance` for multi-connection load balancing. For **Connect
/// over HTTP/1.1** (or unknown protocol), use `HttpClient`.
///
/// # Example (gRPC / HTTP/2)
///
/// ```rust,ignore
/// use connectrpc::client::{Http2Connection, ClientConfig};
/// use connectrpc::Protocol;
///
/// let uri: http::Uri = "http://localhost:8080".parse()?;
/// let conn = Http2Connection::connect_plaintext(uri.clone()).await?.shared(1024);
/// let config = ClientConfig::new(uri).with_protocol(Protocol::Grpc);
///
/// let client = OpenId4VpWalletServiceClient::new(conn, config);
/// let response = client.parse_authorization_request_transport(request).await?;
/// ```
///
/// # Example (Connect / HTTP/1.1 or ALPN)
///
/// ```rust,ignore
/// use connectrpc::client::{HttpClient, ClientConfig};
///
/// let http = HttpClient::plaintext();  // cleartext http:// only
/// let config = ClientConfig::new("http://localhost:8080".parse()?);
///
/// let client = OpenId4VpWalletServiceClient::new(http, config);
/// let response = client.parse_authorization_request_transport(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.parse_authorization_request_transport(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.parse_authorization_request_transport(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct OpenId4VpWalletServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> OpenId4VpWalletServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::connectrpc::http_body::Body>::Error: ::std::fmt::Display,
{
    /// Create a new client with the given transport and configuration.
    pub fn new(transport: T, config: ::connectrpc::client::ClientConfig) -> Self {
        Self { transport, config }
    }
    /// Get the client configuration.
    pub fn config(&self) -> &::connectrpc::client::ClientConfig {
        &self.config
    }
    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ::connectrpc::client::ClientConfig {
        &mut self.config
    }
    /// Call the ParseAuthorizationRequestTransport RPC. Sends a request to /openid4vp.v1.OpenId4VpWalletService/ParseAuthorizationRequestTransport.
    pub async fn parse_authorization_request_transport(
        &self,
        request: crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.parse_authorization_request_transport_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ParseAuthorizationRequestTransport RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn parse_authorization_request_transport_with_options(
        &self,
        request: crate::generated::proto::openid4vp::v1::ParseAuthorizationRequestTransportRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::ParseAuthorizationRequestTransportResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                OPEN_ID4_VP_WALLET_SERVICE_SERVICE_NAME,
                "ParseAuthorizationRequestTransport",
                request,
                options,
            )
            .await
    }
    /// Call the VerifyAuthorizationRequest RPC. Sends a request to /openid4vp.v1.OpenId4VpWalletService/VerifyAuthorizationRequest.
    pub async fn verify_authorization_request(
        &self,
        request: crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.verify_authorization_request_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the VerifyAuthorizationRequest RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn verify_authorization_request_with_options(
        &self,
        request: crate::generated::proto::openid4vp::v1::VerifyAuthorizationRequestRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::VerifyAuthorizationRequestResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                OPEN_ID4_VP_WALLET_SERVICE_SERVICE_NAME,
                "VerifyAuthorizationRequest",
                request,
                options,
            )
            .await
    }
}
/// Full service name for this service.
pub const OPEN_ID4_VP_DC_API_SERVICE_SERVICE_NAME: &str = "openid4vp.v1.OpenId4VpDcApiService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `BuildDigitalCredentialRequestOptions` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const OPEN_ID4_VP_DC_API_SERVICE_BUILD_DIGITAL_CREDENTIAL_REQUEST_OPTIONS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/openid4vp.v1.OpenId4VpDcApiService/BuildDigitalCredentialRequestOptions",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DecodeDcApiAuthorizationResponse` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const OPEN_ID4_VP_DC_API_SERVICE_DECODE_DC_API_AUTHORIZATION_RESPONSE_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/openid4vp.v1.OpenId4VpDcApiService/DecodeDcApiAuthorizationResponse",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// OpenId4VpDcApiService is the Connect boundary for W3C Digital Credentials
/// API binding helpers.
///
/// # Implementing handlers
///
/// Implement methods with plain `async fn`; the returned future satisfies
/// the `Send` bound automatically.
///
/// **Unary and server-streaming requests** arrive as
/// [`ServiceRequest<'_, Req>`](::connectrpc::ServiceRequest): a zero-copy
/// view of the request plus its body, valid for the duration of the call.
/// Fields are read directly (`request.name` is a `&str` into the decoded
/// buffer) and the borrow may be held across `.await` points. Anything
/// that must outlive the call — `tokio::spawn`, channels, server state,
/// or data captured by a returned response stream — takes owned data:
/// call `request.to_owned_message()` (or copy the specific fields)
/// first.
///
/// **Client-streaming and bidi requests** arrive as
/// [`InboundStream<Req>`](::connectrpc::InboundStream) — a
/// `ServiceStream` of [`StreamMessage`](::connectrpc::StreamMessage)s.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.8.0 and views enabled so the
/// backing `HasMessageView` impl exists.
///
/// The `impl Encodable<Out>` return bound accepts the owned `Out`, the
/// generated `OutView<'_>` / `OwnedOutView`,
/// [`MaybeBorrowed`](::connectrpc::MaybeBorrowed), or
/// [`PreEncoded`](::connectrpc::PreEncoded) for handlers that encode a
/// non-`'static` view internally and pass the bytes across the handler
/// boundary. View bodies are not emitted for output types mapped via
/// `extern_path` (the impl would be an orphan); return owned for
/// WKT/extern outputs.
///
/// Server-streaming and bidi-streaming methods return
/// `ServiceStream<impl Encodable<Out> + Send + use<Self>>`. The
/// `use<Self>` precise-capturing clause excludes `&self`'s lifetime and
/// the request's lifetime (unary methods use `use<'a, Self>` and may
/// borrow from `&self`), so stream items must be `'static` and cannot
/// borrow from the request. To stream view-encoded data, encode each
/// item inside the stream body and yield
/// [`PreEncoded`](::connectrpc::PreEncoded) — see its `# Streaming
/// example` doc.
#[allow(clippy::type_complexity)]
pub trait OpenId4VpDcApiService: Send + Sync + 'static {
    /// Handle the BuildDigitalCredentialRequestOptions RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn build_digital_credential_request_options<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the DecodeDcApiAuthorizationResponse RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn decode_dc_api_authorization_response<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
/// Prefer [`Router::add_service`](::connectrpc::Router::add_service) for
/// top-down registration; `register` remains available for compatibility
/// and cases where the service-first call shape is more convenient.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait OpenId4VpDcApiServiceExt: OpenId4VpDcApiService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: OpenId4VpDcApiService> OpenId4VpDcApiServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                OPEN_ID4_VP_DC_API_SERVICE_SERVICE_NAME,
                "BuildDigitalCredentialRequestOptions",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.build_digital_credential_request_options(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(
                OPEN_ID4_VP_DC_API_SERVICE_BUILD_DIGITAL_CREDENTIAL_REQUEST_OPTIONS_SPEC,
            )
            .route_view(
                OPEN_ID4_VP_DC_API_SERVICE_SERVICE_NAME,
                "DecodeDcApiAuthorizationResponse",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.decode_dc_api_authorization_response(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(
                OPEN_ID4_VP_DC_API_SERVICE_DECODE_DC_API_AUTHORIZATION_RESPONSE_SPEC,
            )
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct OpenId4VpDcApiServiceRegisterMarker;
impl<
    S: OpenId4VpDcApiService,
> ::connectrpc::ServiceRegister<OpenId4VpDcApiServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as OpenId4VpDcApiServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `OpenId4VpDcApiService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = OpenId4VpDcApiServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct OpenId4VpDcApiServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: OpenId4VpDcApiService> OpenId4VpDcApiServiceServer<T> {
    /// Wrap a service implementation in a monomorphic dispatcher.
    pub fn new(service: T) -> Self {
        Self {
            inner: ::std::sync::Arc::new(service),
        }
    }
    /// Wrap an already-`Arc`'d service implementation.
    pub fn from_arc(inner: ::std::sync::Arc<T>) -> Self {
        Self { inner }
    }
}
impl<T> Clone for OpenId4VpDcApiServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: OpenId4VpDcApiService> ::connectrpc::Dispatcher
for OpenId4VpDcApiServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("openid4vp.v1.OpenId4VpDcApiService/")?;
        match method {
            "BuildDigitalCredentialRequestOptions" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            OPEN_ID4_VP_DC_API_SERVICE_BUILD_DIGITAL_CREDENTIAL_REQUEST_OPTIONS_SPEC,
                        ),
                )
            }
            "DecodeDcApiAuthorizationResponse" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            OPEN_ID4_VP_DC_API_SERVICE_DECODE_DC_API_AUTHORIZATION_RESPONSE_SPEC,
                        ),
                )
            }
            _ => None,
        }
    }
    fn call_unary(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::Payload,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpDcApiService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "BuildDigitalCredentialRequestOptions" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsRequest,
                    >::from_parts(&req, &body);
                    svc.build_digital_credential_request_options(ctx, req)
                        .await?
                        .encode::<
                            crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsResponse,
                        >(format)
                })
            }
            "DecodeDcApiAuthorizationResponse" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseRequest,
                    >::from_parts(&req, &body);
                    svc.decode_dc_api_authorization_response(ctx, req)
                        .await?
                        .encode::<
                            crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseResponse,
                        >(format)
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_server_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::buffa::bytes::Bytes,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpDcApiService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
    fn call_client_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpDcApiService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_bidi_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("openid4vp.v1.OpenId4VpDcApiService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
}
/// Client for this service.
///
/// Generic over `T: ClientTransport`. For **gRPC** (HTTP/2), use
/// `Http2Connection` — it has honest `poll_ready` and composes with
/// `tower::balance` for multi-connection load balancing. For **Connect
/// over HTTP/1.1** (or unknown protocol), use `HttpClient`.
///
/// # Example (gRPC / HTTP/2)
///
/// ```rust,ignore
/// use connectrpc::client::{Http2Connection, ClientConfig};
/// use connectrpc::Protocol;
///
/// let uri: http::Uri = "http://localhost:8080".parse()?;
/// let conn = Http2Connection::connect_plaintext(uri.clone()).await?.shared(1024);
/// let config = ClientConfig::new(uri).with_protocol(Protocol::Grpc);
///
/// let client = OpenId4VpDcApiServiceClient::new(conn, config);
/// let response = client.build_digital_credential_request_options(request).await?;
/// ```
///
/// # Example (Connect / HTTP/1.1 or ALPN)
///
/// ```rust,ignore
/// use connectrpc::client::{HttpClient, ClientConfig};
///
/// let http = HttpClient::plaintext();  // cleartext http:// only
/// let config = ClientConfig::new("http://localhost:8080".parse()?);
///
/// let client = OpenId4VpDcApiServiceClient::new(http, config);
/// let response = client.build_digital_credential_request_options(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.build_digital_credential_request_options(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.build_digital_credential_request_options(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct OpenId4VpDcApiServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> OpenId4VpDcApiServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::connectrpc::http_body::Body>::Error: ::std::fmt::Display,
{
    /// Create a new client with the given transport and configuration.
    pub fn new(transport: T, config: ::connectrpc::client::ClientConfig) -> Self {
        Self { transport, config }
    }
    /// Get the client configuration.
    pub fn config(&self) -> &::connectrpc::client::ClientConfig {
        &self.config
    }
    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ::connectrpc::client::ClientConfig {
        &mut self.config
    }
    /// Call the BuildDigitalCredentialRequestOptions RPC. Sends a request to /openid4vp.v1.OpenId4VpDcApiService/BuildDigitalCredentialRequestOptions.
    pub async fn build_digital_credential_request_options(
        &self,
        request: crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.build_digital_credential_request_options_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the BuildDigitalCredentialRequestOptions RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn build_digital_credential_request_options_with_options(
        &self,
        request: crate::generated::proto::openid4vp::v1::BuildDigitalCredentialRequestOptionsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::BuildDigitalCredentialRequestOptionsResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                OPEN_ID4_VP_DC_API_SERVICE_SERVICE_NAME,
                "BuildDigitalCredentialRequestOptions",
                request,
                options,
            )
            .await
    }
    /// Call the DecodeDcApiAuthorizationResponse RPC. Sends a request to /openid4vp.v1.OpenId4VpDcApiService/DecodeDcApiAuthorizationResponse.
    pub async fn decode_dc_api_authorization_response(
        &self,
        request: crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.decode_dc_api_authorization_response_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DecodeDcApiAuthorizationResponse RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn decode_dc_api_authorization_response_with_options(
        &self,
        request: crate::generated::proto::openid4vp::v1::DecodeDcApiAuthorizationResponseRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::generated::proto::openid4vp::v1::__buffa::view::DecodeDcApiAuthorizationResponseResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                OPEN_ID4_VP_DC_API_SERVICE_SERVICE_NAME,
                "DecodeDcApiAuthorizationResponse",
                request,
                options,
            )
            .await
    }
}
