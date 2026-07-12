#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -eu

results_dir="${1:-}"

if [ -z "$results_dir" ]; then
  echo "usage: assert_oidf_results.sh <results-dir>" >&2
  exit 64
fi

if [ ! -d "$results_dir" ]; then
  echo "OIDF conformance results directory not found" >&2
  exit 66
fi

result_files="$(find "$results_dir" \
  -type f \
  \( -name '*.json' -o -name '*.html' -o -name '*.zip' -o -name '*.xml' \) \
  ! -path "$results_dir/oidf-discovery/*")"

if [ -z "$result_files" ]; then
  echo "OIDF conformance suite did not export any result files" >&2
  exit 70
fi

for result_file in $result_files; do
  if [ -s "$result_file" ]; then
    exit 0
  fi
done

echo "OIDF conformance suite exported only empty result files" >&2
exit 70
