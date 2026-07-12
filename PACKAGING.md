<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Rust Binary Packaging Policy

ReallyMe Rust packages follow the Russian-doll rule: each higher layer embeds
all lower Rust layers through Cargo dependencies and exposes one top-level
binary artifact to the consuming app.

## Rules

- Every FFI or wasm binding crate must declare `crate-type = ["rlib", ...]`.
  The `rlib` is mandatory because higher-layer packages aggregate symbols from
  lower layers through ordinary Cargo dependency linking.
- A platform package at layer N embeds all lower Rust layers in its single
  binary. For example, an identity xcframework contains crypto's Rust code
  because identity depends on crypto. It must not link or load crypto's separate
  xcframework, dylib, JNI library, or wasm module.
- An app must not contain two ReallyMe Rust binaries. Standalone layer packages
  exist for single-layer consumers; composed consumers use the highest-layer
  package, or an SDK repository's combined package when multiple top-level
  layers are intentionally bundled.
- Swift and Kotlin facade source stays binary-agnostic. It programs against C
  ABI names, JNI names, or wasm exports. The top-level package decides which
  artifact provides those symbols.
- Wasm packages embed every lower Rust layer into one wasm module. A page or app
  must not load two ReallyMe wasm modules that expect shared state, because
  separate wasm instances have separate memories and handles cannot cross them.

## Practical Consequences

- Add FFI/wasm exports only at deliberate package boundaries.
- Prefer source-level facade crates over platform binaries for lower layers.
- Do not make lower-layer native or wasm artifacts runtime dependencies of a
  higher-layer package.
- If a new leaf crate needs `cdylib`, `staticlib`, or `dylib`, keep `rlib` in
  the crate type list and add a test or CI check that the top-level package can
  link it through Cargo.
- Documentation for platform package consumers should name the highest package
  they should install, not a stack of lower ReallyMe binaries.
