#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

check_crate_types() {
  local manifest="$1"
  local crate_types="$2"

  if [[ "$crate_types" == *"cdylib"* || "$crate_types" == *"staticlib"* || "$crate_types" == *"dylib"* ]]; then
    if [[ "$crate_types" != *"rlib"* ]]; then
      printf '%s\n' "error: $manifest declares FFI/wasm crate-type without rlib"
      return 1
    fi
  fi
  return 0
}

failures=0

if command -v cargo >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  while IFS= read -r target; do
    manifest=${target%%	*}
    crate_types=${target#*	}
    if ! check_crate_types "$manifest" "$crate_types"; then
      failures=1
    fi
  done < <(
    cargo metadata --format-version=1 --no-deps |
      jq -r '.packages[] | .manifest_path as $manifest | .targets[] | [$manifest, (.crate_types | join(","))] | @tsv'
  )

  if [[ "$failures" -ne 0 ]]; then
    printf '%s\n' "Rust binary packaging policy failed. See PACKAGING.md."
    exit 1
  fi

  printf '%s\n' "Rust binary packaging policy passed."
  exit 0
fi

while IFS= read -r manifest; do
  in_lib=0
  crate_type=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      "[lib]"*)
        in_lib=1
        crate_type=""
        ;;
      "["*)
        if [[ "$in_lib" -eq 1 ]]; then
          if ! check_crate_types "$manifest" "$crate_type"; then
            failures=1
          fi
        fi
        in_lib=0
        crate_type=""
        ;;
      *"crate-type"*)
        if [[ "$in_lib" -eq 1 ]]; then
          crate_type="$line"
        fi
        ;;
      *)
        if [[ "$in_lib" -eq 1 && -n "$crate_type" ]]; then
          crate_type="$crate_type $line"
        fi
        ;;
    esac
  done < "$manifest"

  if [[ "$in_lib" -eq 1 ]]; then
    if ! check_crate_types "$manifest" "$crate_type"; then
      failures=1
    fi
  fi
done < <(find . -path './target' -prune -o -name Cargo.toml -print | sort)

if [[ "$failures" -ne 0 ]]; then
  printf '%s\n' "Rust binary packaging policy failed. See PACKAGING.md."
  exit 1
fi

printf '%s\n' "Rust binary packaging policy passed."
