#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

suite_dir="${CONFORMANCE_SUITE_DIR:-}"
base_url="${EXAMPLE_VERIFIER_BASE_URL:-}"
plan_id="${OIDF_PLAN_ID:-oid4vp-1final-verifier-test-plan}"
suite_commit="${OIDF_SUITE_COMMIT:-dee9a25160e789f0f80517674693ef7989ab9fa1}"
runner_mode="${OIDF_RUNNER_MODE:-pending}"
flow_driver_mode="${OIDF_VERIFIER_FLOW_DRIVER_MODE:-pending}"
results_dir="${CONFORMANCE_RESULTS_DIR:-conformance/results}"
result_file="${results_dir}/${plan_id}.json"
result_assertion="${OIDF_RESULT_ASSERTION:-conformance/scripts/assert_oidf_results.sh}"

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

if [[ -z "${base_url}" ]]; then
  fail_with_result "missing_example_verifier_base_url"
fi

actual_commit="$(git -C "${suite_dir}" rev-parse HEAD 2>/dev/null || true)"
if [[ "${actual_commit}" != "${suite_commit}" ]]; then
  fail_with_result "conformance_suite_commit_mismatch"
fi

if [[ ! -f "conformance/oidf-verifier-plan.toml" ]]; then
  fail_with_result "missing_oidf_verifier_plan"
fi

runner="${suite_dir}/scripts/run-test-plan.py"
config_file="${OIDF_CONFIG_FILE:-${suite_dir}/scripts/test-configs-rp-against-op/vp-verifier-test-config.json}"
plan_expression="${OIDF_PLAN_EXPRESSION:-${plan_id}[response_mode=direct_post.jwt][credential_format=sd_jwt_vc][request_method=request_uri_signed][client_id_prefix=x509_hash]}"
export_dir="${OIDF_EXPORT_DIR:-${results_dir}/oidf-export}"
python_bin="${PYTHON:-python3}"
flow_driver="${OIDF_VERIFIER_FLOW_DRIVER:-conformance/scripts/drive_oidf_verifier_flow.py}"
flow_driver_pid=""

cleanup_flow_driver() {
  if [[ -n "${flow_driver_pid}" ]]; then
    kill "${flow_driver_pid}" 2>/dev/null || true
    wait "${flow_driver_pid}" 2>/dev/null || true
  fi
}

trap cleanup_flow_driver EXIT

echo "OIDF suite: ${suite_dir}"
echo "OIDF suite commit: ${suite_commit}"
echo "Plan: ${plan_id}"
echo "Verifier: ${base_url}"

if [[ "${runner_mode}" != "execute" ]]; then
  echo "Harness ready: set OIDF_RUNNER_MODE=execute after the OIDF suite server and verifier flow driver are available."
  write_result "pending_runner" "oidf_suite_runner_not_yet_enabled"
  exit 0
fi

if [[ -z "${CONFORMANCE_SERVER:-}" ]]; then
  fail_with_result "missing_conformance_server"
fi

if [[ ! -f "${runner}" ]]; then
  fail_with_result "missing_oidf_runner"
fi

if [[ ! -f "${config_file}" ]]; then
  fail_with_result "missing_oidf_config"
fi

if [[ ! -f "${result_assertion}" ]]; then
  fail_with_result "missing_oidf_result_assertion"
fi

if [[ "${flow_driver_mode}" == "execute" ]]; then
  if [[ ! -f "${flow_driver}" ]]; then
    fail_with_result "missing_oidf_flow_driver"
  fi
  if ! "${python_bin}" "${flow_driver}" --dry-run; then
    fail_with_result "oidf_flow_driver_configuration_failed"
  fi
  "${python_bin}" "${flow_driver}" &
  flow_driver_pid="$!"
  echo "OIDF verifier flow driver started: pid=${flow_driver_pid}"
elif [[ "${flow_driver_mode}" != "pending" ]]; then
  fail_with_result "invalid_oidf_flow_driver_mode"
fi

mkdir -p "${export_dir}"
if "${python_bin}" "${runner}" --export-dir "${export_dir}" "${plan_expression}" "${config_file}"; then
  if ! "${result_assertion}" "${export_dir}"; then
    fail_with_result "oidf_suite_export_missing"
  fi
  write_result "passed" "oidf_suite_runner_completed"
else
  fail_with_result "oidf_suite_runner_failed"
fi
