<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Conformance Harness

This directory contains the OpenID Foundation conformance-suite harness and
interop fixtures for OpenID4VP 1.0 final.

## Structure

- `specifications.lock`: normative and tracked draft source inventory.
- `requirements/`: machine-readable requirement-to-code/test mappings.
- `oidf/`: OpenID Foundation suite pin, plan/module map, and exclusions.
- `eudi/`: EUDI reference-source pins, upstream test map, test cases, and
  exclusions.
- `fixtures/`: local deterministic protocol fixtures, split by protocol area.
- `reports/`: stable report outputs used by CI and release evidence.
- `results/`: generated conformance runner outputs.
- `src/`, `tests/`, `vectors/`: the workspace conformance crate. It executes
  malicious JSON and protocol vectors against the real parsers and validates
  that requirement manifests keep implementation and test anchors current.

The scheduled GitHub Actions job checks out
`https://gitlab.com/openid/conformance-suite` and prepares both OID4VP verifier
and wallet test-plan execution. The native Connect service is available through
`crates/runtime`; the browser-facing request-object and `direct_post` endpoints
are exposed by the framework-neutral HTTP facade so service hosts can mount them
without duplicating protocol checks.

The harness always writes a machine-readable JSON result under
`conformance/results/`. By default it records a pending result. Set
`OIDF_RUNNER_MODE=execute` only when both the OIDF conformance-suite server and
the ReallyMe verifier flow driver are running; configuration failures are
emitted as `failed` results with stable non-PII reason codes.

The verifier plan needs an active flow driver because the OIDF suite plays the
wallet role. `conformance/scripts/drive_oidf_verifier_flow.py` polls
`CONFORMANCE_SERVER` for WAITING verifier modules, reads only the exposed
`authorization_endpoint`, and triggers one of two paths:

- Preferred launch path: set `OIDF_VERIFIER_LAUNCH_ENDPOINT` to a
  conformance-only endpoint on the ReallyMe verifier host. The driver POSTs the
  authorization endpoint and module id so the host can create a fresh verifier
  session and host a fresh Request Object. The endpoint may return `204 No
  Content` after starting the flow itself, but the preferred adapter shape is a
  JSON object with `authorization_endpoint`, optional `method`, and
  `parameters: [{ "name": "client_id", "value": "..." }, ...]`; the driver
  then submits those parameters to the OIDF mock wallet.
- Direct smoke path: set `OIDF_CLIENT_ID` plus `OIDF_REQUEST_URI`, or set
  `OIDF_REQUEST_OBJECT_JWT`, and the driver calls the OIDF authorization
  endpoint itself. This is useful for local checks but is not enough for a full
  multi-module certification run because sessions should be unique per module.

Set `OIDF_VERIFIER_FLOW_DRIVER_MODE=execute` to have
`run_oidf_verifier_plan.sh` start the sidecar alongside the OIDF runner. A live
verifier-role run needs these environment variables:

```sh
export CONFORMANCE_SUITE_DIR=/path/to/openid-conformance-suite
export CONFORMANCE_SERVER=https://suite.example.test
export EXAMPLE_VERIFIER_BASE_URL=https://verifier.example.test
export OIDF_VERIFIER_LAUNCH_ENDPOINT=https://verifier.example.test/oidf/launch
export OIDF_RUNNER_MODE=execute
export OIDF_VERIFIER_FLOW_DRIVER_MODE=execute
conformance/scripts/run_oidf_verifier_plan.sh
```

The driver writes its own machine-readable status to
`conformance/results/oidf-verifier-flow-driver.json` and intentionally avoids
printing Request Objects, request URIs, bearer tokens, or wallet response data.

The wallet plans use `conformance/scripts/run_oidf_wallet_plan.sh`. Set
`OIDF_WALLET_RUNNER_MODE=execute` only when a conformance wallet harness is
available through `OIDF_WALLET_HARNESS_ENDPOINT`. `reallyme/wallet` provides
`conformance/scripts/serve_oidf_wallet_harness.sh`, which serves
`/oidf/wallet/authorize` and validates launch transport through
`reallyme-openid4vp-wallet`. A passing OIDF wallet-role run needs a composed
identity-sdk or application harness for the same endpoint shape, because the
flow must resolve `request_uri`, verify the Request Object, select credentials,
build a DCQL-keyed `vp_token`, encrypt `direct_post.jwt`, and post the response
to the suite. This repository owns the OpenID4VP request/response/proto/DCQL
validation boundary, not wallet storage, consent UI, credential inventory, or
the composed presentation driver.

Set `OIDF_WALLET_FLOW_DRIVER_MODE=execute` to have
`run_oidf_wallet_plan.sh` start `conformance/scripts/drive_oidf_wallet_flow.py`
beside the OIDF runner. The driver polls `CONFORMANCE_SERVER` for WAITING
wallet modules, extracts the suite-published authorization request URL from the
runner status, and forwards only the authorization request parameters to
`OIDF_WALLET_HARNESS_ENDPOINT`. The default wallet-plan config is the
repo-owned DCQL/HAIP template in
`conformance/oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json`; it
keeps Presentation Exchange out of OpenID4VP 1.0 final runs and supplies the
HAIP credential and status-list trust anchors required by the pinned suite.

A live wallet-role run needs these environment variables:

```sh
export CONFORMANCE_SUITE_DIR=/path/to/openid-conformance-suite
export CONFORMANCE_SERVER=https://suite.example.test
export OIDF_WALLET_HARNESS_ENDPOINT=https://wallet.example.test/oidf/wallet/authorize
export OIDF_WALLET_RUNNER_MODE=execute
export OIDF_WALLET_FLOW_DRIVER_MODE=execute
conformance/scripts/run_oidf_wallet_plan.sh
```

The OIDF suite is release-pinned in `oidf/suite.lock`, and `oidf/plans.json`
plus `oidf/modules.json` record the OpenID4VP 1.0 Final plan/module identifiers
from that exact revision. `reports/oidf-manifest.json` maps every pinned plan to
the external report artifact that must be archived before a certification claim
is made. CI runs `scripts/preflight_oidf_verifier.sh`, builds the pinned suite,
and writes discovery artifacts with `scripts/discover_oidf_openid4vp.py` before
the runner starts. Before any release can claim external conformance, the
scheduled job must boot the local verifier host or wallet harness, trigger the
suite flow, and publish the suite export from execute mode.

`reallyme/openidvc` uses the same OIDF conformance-suite release pin for
OpenID4VCI issuer/wallet plans. The two repositories may share runner and report
manifest conventions, but OpenIDVC reports must not be counted as OpenID4VP
coverage, and OpenID4VP verifier/wallet reports must not be counted as
OpenIDVC coverage.

Interop fixture targets:

- EUDI reference verifier and wallet:
  `https://github.com/eu-digital-identity-wallet`
- EWC EUDI wallet RFC flows:
  `https://github.com/EWC-consortium/eudi-wallet-rfcs`

Hardening targets:

- `tests/property_tests.rs` covers parser and generated-message invariants with
  bounded `proptest` cases.
- `../fuzz/` contains `cargo-fuzz` targets for DCQL JSON and evaluation,
  request transport, Request Object JWT shape, Client Identifier parsing,
  Authorization Response JSON/protobuf, metadata JSON, transaction data JSON,
  Direct Post/direct_post.jwt forms, DC API request/response JSON, and
  verifier-attestation parameters.
- `../scripts/run-fuzz-smoke.sh` runs a short bounded fuzz smoke pass suitable
  for CI and local pre-release validation.

Fixtures must use final OpenID4VP wire shapes: DCQL queries, `vp_token` objects
keyed by DCQL query id, and client identifier prefixes.
