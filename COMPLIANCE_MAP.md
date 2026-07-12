<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# OpenID4VP Compliance Map

This map ties normative requirements to repo modules, tests, and conformance
assets. Historical meproto `presentation/` sources were used only as porting
input and are no longer tracked in this repository; all active protocol
surfaces target OpenID4VP 1.0 final wire shapes.

| Standard or profile | Scope in this repo | Primary modules | Verification assets |
| --- | --- | --- | --- |
| OpenID4VP 1.0 final | Authorization Request/Response objects, DCQL, final `vp_token` object keyed by DCQL query id, client identifier prefixes | `crates/types`, `crates/dcql`, `crates/verifier`, `crates/wallet` | Unit tests in each crate; conformance harness in `conformance/` |
| RFC 9101 JAR | Request Object signing and verifier/wallet validation policy | `crates/verifier::jar`, `crates/wallet::jar` | Claim validation tests; injected signer/verifier traits for reallyme crypto adapters |
| OpenID4VP Request Object transport | Pure wallet parsing plus HTTP `request_uri` resolution | `crates/wallet::transport`, `crates/http` | Transport classification, POST wallet_nonce, HTTPS, and resolver tests |
| OpenID4VP holder binding | OID4VP-specific comparison of decoded proof claims to request binding | `crates/verifier::holder_binding` | Audience, nonce, and expiration tests; crypto/JWT parsing remains in `reallyme-identity` |
| OpenID4VP Authorization Response validation | Verifier session binding and final `vp_token` shape acceptance checks | `crates/verifier::response` | State mismatch and non-empty `vp_token` tests |
| OpenID4VP Authorization Error Response | Response URI processing for wallet error callbacks and `direct_post.jwt` plain-error fallback | `crates/runtime::handle_direct_post`, `crates/runtime::handle_direct_post_jwt` | Runtime tests for accepted error responses, state mismatch, and mixed success/error rejection |
| OpenID4VP encrypted Authorization Response | `direct_post.jwt` compact JWE decryption through `reallyme-jose` and `reallyme-crypto` | `crates/runtime::JoseAuthorizationResponseJwtDecryptor` | A128GCM and ECDH-ES compact JWE runtime tests with injected host key resolvers |
| W3C Digital Credentials API response normalization | Plain `dc_api` and encrypted `dc_api.jwt` browser responses over Connect | `crates/runtime::OpenId4VpDcApiService` implementation | Runtime tests for plaintext and JOSE-backed encrypted response decode |
| Protobuf-first transport | Stable Buffa-generated OpenID4VP contract with JSON only as protobuf JSON or canonical bytes for JSON-native spec fields | `protos/openid4vp/v1/openid4vp.proto`, `crates/proto/openid4vp`, `crates/proto/codec` | `buf lint`, `buf generate`, generated crate checks, response codec tests |
| RFC 9457 Problem Details | Typed problem details mapping for verifier and wallet errors | `crates/types::problem_details` | Serialization tests; crate-level `From<...>` mappings |
| W3C Digital Credentials API Editor's Draft | `dc_api` and `dc_api.jwt` request/response mode models | `crates/dc-api` | DC API request/response unit tests; OIDF conformance harness target |
| ISO/IEC 18013-7 Annex B | OID4VP mdoc SessionTranscript handover inputs | `crates/dc-api::mdoc` | Handover digest tests with delegated CBOR encoder |
| ISO/IEC 18013-5 mdoc | DeviceResponse and issuer-signed mdoc structures | `reallyme-identity` dependency `envelopes-mdoc` | Identity mdoc tests; this repo does not reimplement CBOR structures |
| HAIP 1.0 | High Assurance Interoperability Profile presentation capabilities | `crates/profiles` | HAIP profile unit tests |
| eIDAS ARF and CIR 2024/2977-2982 | Presentation profile alignment and EUDI interoperability | `crates/profiles`, `conformance/fixtures/eudi` | EUDI reference verifier/wallet fixtures |
| OIDF conformance suite | Scheduled verifier test-plan execution against the runtime verifier host | `.github/workflows/conformance.yml`, `conformance/scripts/run_oidf_verifier_plan.sh`, `crates/runtime` | GitHub Actions scheduled job and result artifact |
| EWC eudi-wallet-rfcs | Interop flows for EUDI wallet community profiles | `conformance/fixtures/ewc` | Fixture manifest and future machine-readable vectors |

## Notes

- The W3C Digital Credentials API is draft-volatility-sensitive. Public doc
  comments in `crates/dc-api` call this out so downstream users do not treat
  those strings as immutable platform law.
- RFC 9101 cryptographic operations are trait boundaries here. Concrete JOSE
  signing, encryption, and signature validation should live in adapters backed
  by `reallyme-crypto`.
- mdoc CBOR and DeviceResponse structures remain in `reallyme-identity`
  `envelopes-mdoc`; this repo only constructs the OID4VP handover inputs and
  delegates encoding.
- The active OpenID4VP proto intentionally owns only protocol DTOs. It does not
  import sibling wallet, identity, or zk protos until those repositories expose
  stable buf modules for cross-repo generation; integration currently happens
  through Rust API dependencies and generated OpenID4VP bytes.
