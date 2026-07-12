#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

suite_dir="${CONFORMANCE_SUITE_DIR:-}"
plan_id="${OIDF_PLAN_ID:-oid4vp-1final-wallet-test-plan}"
suite_commit="${OIDF_SUITE_COMMIT:-dee9a25160e789f0f80517674693ef7989ab9fa1}"
runner_mode="${OIDF_WALLET_RUNNER_MODE:-${OIDF_RUNNER_MODE:-pending}}"
flow_driver_mode="${OIDF_WALLET_FLOW_DRIVER_MODE:-pending}"
results_dir="${CONFORMANCE_RESULTS_DIR:-conformance/results}"
result_file="${results_dir}/${plan_id}.json"
result_assertion="${OIDF_RESULT_ASSERTION:-conformance/scripts/assert_oidf_results.sh}"
wallet_harness_endpoint="${OIDF_WALLET_HARNESS_ENDPOINT:-}"
flow_driver_pid=""

cleanup_flow_driver() {
  if [[ -n "${flow_driver_pid}" ]]; then
    kill "${flow_driver_pid}" 2>/dev/null || true
    wait "${flow_driver_pid}" 2>/dev/null || true
  fi
}

trap cleanup_flow_driver EXIT

write_result() {
  local status="$1"
  local reason="$2"
  mkdir -p "${results_dir}"
  printf '{"plan_id":"%s","status":"%s","reason":"%s"}\n' \
    "${plan_id}" "${status}" "${reason}" > "${result_file}"
}

fail_with_result() {
  local reason="$1"
  write_result "failed" "${reason}"
  echo "${reason}" >&2
  exit 2
}

if [[ -z "${suite_dir}" || ! -d "${suite_dir}" ]]; then
  fail_with_result "missing_conformance_suite"
fi

actual_commit="$(git -C "${suite_dir}" rev-parse HEAD 2>/dev/null || true)"
if [[ "${actual_commit}" != "${suite_commit}" ]]; then
  fail_with_result "conformance_suite_commit_mismatch"
fi

if [[ ! -f "conformance/oidf-wallet-plan.toml" ]]; then
  fail_with_result "missing_oidf_wallet_plan"
fi

runner="${suite_dir}/scripts/run-test-plan.py"
config_file="${OIDF_WALLET_CONFIG_FILE:-conformance/oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json}"
plan_expression="${OIDF_WALLET_PLAN_EXPRESSION:-${plan_id}[response_mode=direct_post.jwt][credential_format=sd_jwt_vc][request_method=request_uri_signed][client_id_prefix=x509_hash]}"
export_dir="${OIDF_WALLET_EXPORT_DIR:-${results_dir}/oidf-wallet-export}"
python_bin="${PYTHON:-python3}"
flow_driver="${OIDF_WALLET_FLOW_DRIVER:-conformance/scripts/drive_oidf_wallet_flow.py}"

echo "OIDF suite: ${suite_dir}"
echo "OIDF suite commit: ${suite_commit}"
echo "Plan: ${plan_id}"
echo "Wallet harness: ${wallet_harness_endpoint:-pending}"

if [[ "${runner_mode}" != "execute" ]]; then
  echo "Harness ready: set OIDF_WALLET_RUNNER_MODE=execute after a wallet harness endpoint is available."
  write_result "pending_runner" "oidf_wallet_runner_not_yet_enabled"
  exit 0
fi

if [[ -z "${CONFORMANCE_SERVER:-}" ]]; then
  fail_with_result "missing_conformance_server"
fi

if [[ -z "${wallet_harness_endpoint}" ]]; then
  fail_with_result "missing_wallet_harness_endpoint"
fi

if [[ ! -f "${runner}" ]]; then
  fail_with_result "missing_oidf_runner"
fi

if [[ ! -f "${config_file}" ]]; then
  fail_with_result "missing_oidf_wallet_config"
fi

if [[ ! -f "${result_assertion}" ]]; then
  fail_with_result "missing_oidf_result_assertion"
fi

if [[ "${flow_driver_mode}" == "execute" ]]; then
  if [[ ! -f "${flow_driver}" ]]; then
    fail_with_result "missing_oidf_wallet_flow_driver"
  fi
  if ! "${python_bin}" "${flow_driver}" --dry-run; then
    fail_with_result "oidf_wallet_flow_driver_configuration_failed"
  fi
  "${python_bin}" "${flow_driver}" &
  flow_driver_pid="$!"
  echo "OIDF wallet flow driver started: pid=${flow_driver_pid}"
elif [[ "${flow_driver_mode}" != "pending" ]]; then
  fail_with_result "invalid_oidf_wallet_flow_driver_mode"
fi

mkdir -p "${export_dir}"
if OIDF_WALLET_HARNESS_ENDPOINT="${wallet_harness_endpoint}" \
  "${python_bin}" "${runner}" --export-dir "${export_dir}" "${plan_expression}" "${config_file}"; then
  if ! "${result_assertion}" "${export_dir}"; then
    fail_with_result "oidf_suite_export_missing"
  fi
  write_result "passed" "oidf_wallet_suite_runner_completed"
else
  fail_with_result "oidf_wallet_suite_runner_failed"
fi
