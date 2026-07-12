<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# OpenID4VP Threat Model

Scope: OpenID4VP verifier and wallet protocol code in this repository, including
DCQL, Request Object transport, response-mode handling, DC API helpers, ZK
presentation envelopes, protobuf/Connect contracts, and framework-neutral HTTP
runtime adapters.

Out of scope: credential-format cryptography owned by `reallyme/identity`,
primitive cryptography owned by `reallyme/crypto`, concrete service storage,
network ingress, TLS termination, and platform package signing.

## Trust Boundaries

| Boundary | Trusted side | Untrusted side | Controls |
| --- | --- | --- | --- |
| Authorization Request input | Wallet parser and verifier adapters | Browser URL, QR content, app link, request URI contents | `crates/wallet/src/transport.rs`, request size limits, signed Request Object policy |
| Request URI retrieval | Wallet HTTP adapter | Verifier-controlled URL and HTTP body | HTTPS-only policy, media-type checks, max JWT size, `wallet_nonce` rules |
| Verifier response endpoint | Runtime verifier host | Wallet POST body and user agent | Method/content-type checks, body limits, form duplicate rejection, state/session binding |
| Encrypted response decryptor | Injected JOSE adapter | Compact JWE string | Compact JWE preflight, fail-closed missing decryptor, upstream `reallyme-jose` header policy |
| Presentation validation | Verifier protocol core | VP Token entries and presentations | DCQL-keyed response model, non-empty checks, holder-binding validation, ZK fail-closed policy |
| ZK backend | Injected `reallyme-zk-api` traits | ZK presentation envelope | Circuit capability registry, nonce/audience/transaction public input checks |
| Protobuf/Connect boundary | Generated Buffa messages | RPC clients | Typed protobuf mappings, problem-details fields for protocol failures |

## Primary Threats

| Threat | Impact | Mitigation |
| --- | --- | --- |
| Presentation replay to a different verifier | Credential replay, account takeover | Holder-binding audience and nonce checks in `crates/verifier/src/holder_binding.rs`; ZK binding checks in `crates/formats/src/prove_zk_presentation.rs` |
| Session fixation through `direct_post` | Attacker completes a verifier session started elsewhere | State checking, response binding validation, and documented need for verifier-owned response-code/redirect continuation |
| Mixed success and error response body | Parser confusion or forged callback state | `crates/runtime/src/handle_authorization_error_response.rs` rejects bodies carrying both `error` and `vp_token` or `response` |
| Duplicate form fields | Ambiguous parser interpretation | `crates/runtime/src/parse_form_urlencoded.rs` rejects duplicates for security-sensitive fields |
| Oversized callback body or Request Object | Memory pressure and parser DoS | Runtime direct-post body limit; wallet/http Request Object size limits |
| Request URI downgrade or exfiltration | Wallet retrieves unsigned or attacker-controlled request | HTTPS default in `crates/http`; signed-request policy in `crates/wallet`; final client-id prefix binding |
| Unsupported ZK presentation accepted without verification | Invalid derived-claim proof | `crates/verifier/src/response.rs` fails closed when no `ZkVerifier` is injected |
| Missing encrypted-response decryptor | Unencrypted or unchecked sensitive callback | `direct_post.jwt` maps missing decryptor to unsupported feature; encrypted payload is never skipped |
| PII leakage through error strings | Logs or telemetry expose credentials or claims | Error enums carry stable reasons only; RFC 9457 problems omit raw request/credential data |
| Multiple Rust binaries in one app | Handle/state mismatch across FFI/wasm layers | `PACKAGING.md` Russian-doll rule; root facade intended for identity-sdk aggregation |

## Privacy Review

OpenID4VP responses can contain highly sensitive presentations. Runtime code
therefore treats raw bodies, `vp_token`, compact JWE values, and decrypted
payloads as untrusted sensitive material. The repository does not log or format
these values into errors. Problem Details expose only stable problem kinds and
transport-owned instance IDs.

The DCQL engine supports data minimization by selecting credentials and claims
against the verifier query. ZK presentation envelopes add a derivation path so
wallets can prove statements without disclosing underlying claims, while keeping
circuit semantics in `reallyme-zk-api` instead of this crate.

Digital Credentials API support is intentionally isolated in `crates/dc-api`
because the W3C draft is volatile. Public comments warn consumers not to treat
draft string constants as permanent platform law.

## Operational Requirements

- Terminate TLS before exposing any verifier response endpoint.
- Store verifier sessions server-side with short expirations and one-time
  consumption semantics in the service host.
- Use high-entropy `state`, `nonce`, `wallet_nonce`, and any response-code
  continuation secret.
- Never log request bodies, VP Tokens, compact JWEs, decrypted response
  payloads, transaction data, or holder-binding claims.
- Inject production JOSE and ZK backends explicitly; feature-disabled paths
  must remain fail-closed.
- Run OIDF conformance and interop fixture suites before launch and preserve
  machine-readable result artifacts.

## Open Items

- Wire service-host ECDH-ES key resolvers into the runtime JOSE decryptor.
- Add a runnable verifier service process for the OIDF conformance harness.
- Add malicious-input corpora for nested JSON, duplicate JSON keys, bad
  base64url, stale nonce, swapped audience, and request URI downgrade attempts.
- Add service-host replay store tests once the concrete storage adapter exists.
