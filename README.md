<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe OpenID4VP

[![Rust workspace](https://img.shields.io/github/actions/workflow/status/reallyme/openidvp/ci.yml?branch=main&label=Rust%20workspace)](https://github.com/reallyme/openidvp/actions/workflows/ci.yml)
[![OIDF plans](https://img.shields.io/github/actions/workflow/status/reallyme/openidvp/conformance.yml?branch=main&label=OIDF%20plans)](https://github.com/reallyme/openidvp/actions/workflows/conformance.yml)

Protocol-grade OpenID4VP 1.0 final for Rust and ReallyMe SDK hosts.

If you're looking for an eIDAS 2.0 integration that contains OpenID4VP, refer to the [Identity-SDK](https://github.com/reallyme/identity-sdk).

`reallyme-openid4vp` provides final-spec OpenID4VP request and response models,
DCQL validation and evaluation, verifier and wallet protocol boundaries, W3C
Digital Credentials API support, HAIP profile support, and generated
protobuf/Connect contracts. It is designed to be embedded by higher-level
wallets, verifier services, and SDK packages without duplicating protocol
logic.

## Standards

This project implements [OpenID for Verifiable Presentations 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html),
part of the [OpenID for Verifiable Credentials](https://openid.net/sg/openid4vc/)
protocol family.

## What You Get

- OpenID4VP 1.0 final wire shapes: DCQL, DCQL-keyed `vp_token`, final Client
  Identifier Prefixes, transaction data, and RFC 9457 problem details.
- A standalone DCQL engine for query validation, claims-path processing,
  wallet-side matching, and selected-claim minimization.
- Verifier-side request binding, JAR policy, response validation, Direct Post,
  `direct_post.jwt`, and optional ZK verification hooks.
- Wallet-side request transport parsing, network-free Request Object
  verification boundaries, verifier-attestation enforcement, and metadata trust
  evidence boundaries.
- W3C Digital Credentials API request/response support, including `dc_api`,
  `dc_api.jwt`, and ISO/IEC 18013-7 Annex B mdoc handover construction.
- Buffa-generated protobuf messages and Connect services for SDK and service
  integrations.
- Conformance assets for OIDF, EUDI, EWC, malicious inputs, property tests, and
  fuzz smoke targets.

## Crates

| Crate | Role |
| --- | --- |
| [`reallyme-openid4vp-dcql`](crates/dcql) | Standalone DCQL model, validation, and evaluation engine. |
| [`reallyme-openid4vp-types`](crates/types) | Request/response, metadata, transaction data, client identifier prefixes, and problem details. |
| [`reallyme-openid4vp-verifier`](crates/verifier) | Verifier request construction, JAR policy, sessions, response validation, and ZK verifier injection. |
| [`reallyme-openid4vp-wallet`](crates/wallet) | Wallet request parsing, Request Object verification boundaries, trust evidence, and wallet-side validation. |
| [`reallyme-openid4vp-dc-api`](crates/dc-api) | Digital Credentials API and ISO/IEC 18013-7 Annex B handover support. |
| [`reallyme-openid4vp-formats`](crates/formats) | OpenID4VP presentation-format glue, including ZK presentation entries and mdoc integration. |
| [`reallyme-openid4vp-runtime`](crates/runtime) | Framework-neutral HTTP and Connect runtime handlers. |
| [`reallyme-openid4vp-proto`](crates/proto/openid4vp) / [`reallyme-openid4vp-proto-codec`](crates/proto/codec) | Generated protobuf/Connect contract and checked domain-codec mappings. |
| [`reallyme-openid4vp-profiles`](crates/profiles) | HAIP and eIDAS-aligned presentation profile descriptors. |
| [`reallyme-openid4vp-conformance`](conformance) | Requirement manifests, OIDF runners, interop fixtures, malicious vectors, and property tests. |

## Boundaries

- Credential formats and cryptographic primitives come from
  `reallyme/identity` and `reallyme/crypto`.
- Wallet inventory, consent UX, storage, and presentation flow orchestration
  belong to `reallyme/wallet` and `reallyme/identity-sdk`.
- Request Object verification is network-free. Hosts inject trusted keys,
  verifier-attestation evidence, and metadata-reference evidence.
- `direct_post.jwt` and `dc_api.jwt` decrypt through `reallyme-jose` and
  `reallyme-crypto`; service hosts own concrete key resolution.
- The W3C Digital Credentials API is still an Editor's Draft. Draft-specific
  strings are isolated in `crates/dc-api`.

## Conformance

The repository includes local conformance vectors, requirement maps, OIDF runner
scripts, EUDI/EWC fixtures, property tests, and fuzz smoke targets.

Live OIDF certification evidence requires reachable hosts:

- Verifier role: configure `CONFORMANCE_SUITE_DIR`, `CONFORMANCE_SERVER`,
  `EXAMPLE_VERIFIER_BASE_URL`, `OIDF_VERIFIER_LAUNCH_ENDPOINT`,
  `OIDF_RUNNER_MODE=execute`, and `OIDF_VERIFIER_FLOW_DRIVER_MODE=execute`.
- Wallet role: configure `CONFORMANCE_SUITE_DIR`, `CONFORMANCE_SERVER`,
  `OIDF_WALLET_HARNESS_ENDPOINT`, `OIDF_WALLET_RUNNER_MODE=execute`, and
  `OIDF_WALLET_FLOW_DRIVER_MODE=execute`.

See `conformance/README.md` for run commands and artifact locations.

## Validate

```sh
cargo fmt --check
cargo check --workspace --all-features
RUSTFLAGS=-Dwarnings cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
buf lint
scripts/check-rust-packaging.sh
node scripts/check-release-readiness.mjs
OPENIDVP_FUZZ_RUNS=16 OPENIDVP_FUZZ_MAX_LEN=4096 scripts/run-fuzz-smoke.sh
```

## Documentation

- [`COMPLIANCE_MAP.md`](COMPLIANCE_MAP.md): requirement-to-module map.
- [`THREAT_MODEL.md`](THREAT_MODEL.md): operational and privacy threat model.
- [`PACKAGING.md`](PACKAGING.md): Rust binary packaging policy.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.

## Trademarks & Copyrights

OpenID4VP is the name of an [OpenID Foundation](https://openid.net/foundation/)
specification. [OpenID](https://openid.net/), OpenID4VP, and related names are
used here only to identify protocol compatibility. ReallyMe LLC claims no
trademark rights in OpenID4VP or any OpenID Foundation marks.

This project is not affiliated with, endorsed by, sponsored by, or reviewed by
the OpenID Foundation.

ReallyMe LLC claims no copyright over the
[OpenID4VP specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

ReallyMe® is a registered trademark of ReallyMe LLC.
