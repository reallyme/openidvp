#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly FUZZ_MANIFEST="fuzz/Cargo.toml"
readonly FUZZ_RUNS="${OPENIDVP_FUZZ_RUNS:-16}"
readonly FUZZ_MAX_LEN="${OPENIDVP_FUZZ_MAX_LEN:-4096}"

readonly -a FUZZ_TARGETS=(
  "dcql_json"
  "authorization_request_transport"
  "request_object_jwt"
  "client_identifier"
  "authorization_response_json"
  "authorization_response_proto"
  "metadata_json"
  "transaction_data_json"
  "dc_api_response_json"
  "dcql_evaluation"
  "direct_post_form"
  "direct_post_jwt_form"
  "dc_api_request_json"
  "verifier_attestation_parameters"
)

require_positive_integer() {
  local name="$1"
  local value="$2"

  case "$value" in
    "" | *[!0-9]*)
      printf '%s must be a positive integer\n' "$name" >&2
      exit 2
      ;;
  esac

  if [ "$value" -eq 0 ]; then
    printf '%s must be greater than zero\n' "$name" >&2
    exit 2
  fi
}

require_positive_integer "OPENIDVP_FUZZ_RUNS" "$FUZZ_RUNS"
require_positive_integer "OPENIDVP_FUZZ_MAX_LEN" "$FUZZ_MAX_LEN"

for target in "${FUZZ_TARGETS[@]}"; do
  artifact_dir="fuzz/artifacts/${target}"
  mkdir -p "$artifact_dir"
  printf 'Running fuzz smoke target: %s\n' "$target"
  cargo run \
    --quiet \
    --manifest-path "$FUZZ_MANIFEST" \
    --bin "$target" \
    -- \
    "-runs=${FUZZ_RUNS}" \
    "-max_len=${FUZZ_MAX_LEN}" \
    "-artifact_prefix=${artifact_dir}/"
done
