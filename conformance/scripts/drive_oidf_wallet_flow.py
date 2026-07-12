#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

"""Drive OIDF OpenID4VP wallet modules into the ReallyMe wallet harness.

The OIDF wallet plan acts as a verifier. Once a module reaches WAITING, the
suite publishes the authorization request URL it expects a wallet to open. This
sidecar discovers that URL and forwards only the authorization request
parameters to the injected wallet harness. The harness remains responsible for
parsing and recording the wallet launch; credential inventory, consent, and
presentation generation stay in reallyme/wallet.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 900.0
DEFAULT_POLL_SECONDS = 1.0
HTTP_TIMEOUT_SECONDS = 20.0
RESULT_FILENAME = "oidf-wallet-flow-driver.json"
STATUS_WAITING = "WAITING"


@dataclass(frozen=True)
class DriverConfig:
    conformance_server: str | None
    conformance_api_token: str | None
    conformance_verify_ssl: bool
    module_id: str | None
    wallet_harness_endpoint: str | None
    wallet_harness_method: str
    timeout_seconds: float
    poll_seconds: float
    result_file: str


class DriverFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Trigger OIDF OpenID4VP wallet harness flows.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate configuration and write a result without network calls",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="trigger one discovered wallet launch and exit instead of watching",
    )
    args = parser.parse_args()

    config: DriverConfig | None = None
    try:
        config = read_config()
        validate_config(config)
        if args.dry_run:
            write_result(config.result_file, "dry_run", "configuration_valid", 0)
            print("OIDF wallet flow driver dry run: configuration_valid")
            return 0
        triggered = run_driver(config, args.once)
        write_result(config.result_file, "passed", "flow_driver_completed", triggered)
        print(f"OIDF wallet flow driver completed: triggered={triggered}")
        return 0
    except DriverFailure as error:
        result_file = config.result_file if config is not None else default_result_file()
        write_result(result_file, "failed", error.reason, 0)
        print(error.reason, file=sys.stderr)
        return 2


def default_result_file() -> str:
    results_dir = os.environ.get("CONFORMANCE_RESULTS_DIR", "conformance/results")
    return os.path.join(results_dir, RESULT_FILENAME)


def read_config() -> DriverConfig:
    result_file = os.environ.get(
        "OIDF_WALLET_FLOW_DRIVER_RESULT_FILE",
        default_result_file(),
    )
    return DriverConfig(
        conformance_server=empty_to_none(os.environ.get("CONFORMANCE_SERVER")),
        conformance_api_token=empty_to_none(os.environ.get("CONFORMANCE_API_TOKEN")),
        conformance_verify_ssl=read_bool_env("CONFORMANCE_VERIFY_SSL", True),
        module_id=empty_to_none(os.environ.get("OIDF_MODULE_ID")),
        wallet_harness_endpoint=empty_to_none(os.environ.get("OIDF_WALLET_HARNESS_ENDPOINT")),
        wallet_harness_method=os.environ.get("OIDF_WALLET_HARNESS_METHOD", "GET"),
        timeout_seconds=read_float_env(
            "OIDF_WALLET_FLOW_DRIVER_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        ),
        poll_seconds=read_float_env("OIDF_WALLET_FLOW_DRIVER_POLL_SECONDS", DEFAULT_POLL_SECONDS),
        result_file=result_file,
    )


def empty_to_none(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return value


def read_bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    normalized = value.lower()
    if normalized in ("1", "true", "yes"):
        return True
    if normalized in ("0", "false", "no"):
        return False
    raise DriverFailure("invalid_boolean_environment")


def read_float_env(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise DriverFailure("invalid_numeric_environment") from exc
    if parsed <= 0:
        raise DriverFailure("invalid_numeric_environment")
    return parsed


def validate_config(config: DriverConfig) -> None:
    if config.conformance_server is None:
        raise DriverFailure("missing_conformance_server")
    if config.wallet_harness_endpoint is None:
        raise DriverFailure("missing_wallet_harness_endpoint")
    method = config.wallet_harness_method.upper()
    if method not in ("GET", "POST"):
        raise DriverFailure("invalid_wallet_harness_method")


def run_driver(config: DriverConfig, once: bool) -> int:
    deadline = time.monotonic() + config.timeout_seconds
    triggered_modules: set[str] = set()
    while time.monotonic() < deadline:
        triggered_this_poll = trigger_waiting_modules(config, triggered_modules)
        if once and triggered_this_poll > 0:
            return len(triggered_modules)
        time.sleep(config.poll_seconds)
    if len(triggered_modules) == 0:
        raise DriverFailure("no_waiting_oidf_wallet_module")
    return len(triggered_modules)


def trigger_waiting_modules(config: DriverConfig, triggered_modules: set[str]) -> int:
    module_ids = [config.module_id] if config.module_id is not None else fetch_running_module_ids(config)
    triggered = 0
    for module_id in module_ids:
        if module_id in triggered_modules:
            continue
        info = fetch_module_info(config, module_id)
        if info.get("status") != STATUS_WAITING:
            continue
        runner_status = fetch_runner_status(config, module_id)
        authorization_request = wallet_authorization_request(runner_status)
        if authorization_request is None:
            continue
        call_wallet_harness(config, authorization_request)
        triggered_modules.add(module_id)
        triggered += 1
    return triggered


def fetch_running_module_ids(config: DriverConfig) -> list[str]:
    data = api_get_json(config, "api/runner/running")
    if not isinstance(data, list):
        raise DriverFailure("invalid_oidf_running_response")
    module_ids: list[str] = []
    for item in data:
        module_id = string_value(item)
        if module_id is not None:
            module_ids.append(module_id)
    return module_ids


def fetch_module_info(config: DriverConfig, module_id: str) -> dict[str, Any]:
    data = api_get_json(config, f"api/info/{quote_path_segment(module_id)}")
    if not isinstance(data, dict):
        raise DriverFailure("invalid_oidf_info_response")
    return data


def fetch_runner_status(config: DriverConfig, module_id: str) -> dict[str, Any]:
    data = api_get_json(config, f"api/runner/{quote_path_segment(module_id)}")
    if not isinstance(data, dict):
        raise DriverFailure("invalid_oidf_runner_response")
    return data


def wallet_authorization_request(status: dict[str, Any]) -> str | None:
    browser = status.get("browser")
    if not isinstance(browser, dict):
        return None
    for key in ("visited", "urls"):
        value = last_string(browser.get(key))
        if value is not None:
            query = urllib.parse.urlsplit(value).query
            if query != "":
                return query
    return None


def last_string(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    for item in reversed(value):
        parsed = string_value(item)
        if parsed is not None and parsed != "":
            return parsed
    return None


def call_wallet_harness(config: DriverConfig, authorization_request: str) -> None:
    endpoint = require_value(config.wallet_harness_endpoint, "missing_wallet_harness_endpoint")
    method = config.wallet_harness_method.upper()
    if method == "POST":
        body = json.dumps(
            {"authorization_request": authorization_request},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    else:
        separator = "&" if "?" in endpoint else "?"
        request = urllib.request.Request(f"{endpoint}{separator}{authorization_request}", method="GET")
    open_request(request, config.conformance_verify_ssl, "wallet_harness_call_failed")


def api_get_json(config: DriverConfig, relative_path: str) -> Any:
    server = require_value(config.conformance_server, "missing_conformance_server")
    base = server if server.endswith("/") else f"{server}/"
    request = urllib.request.Request(urllib.parse.urljoin(base, relative_path), method="GET")
    request.add_header("Accept", "application/json")
    if config.conformance_api_token is not None:
        request.add_header("Authorization", f"Bearer {config.conformance_api_token}")
    body = open_request(request, config.conformance_verify_ssl, "oidf_api_request_failed")
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise DriverFailure("oidf_api_invalid_json") from exc


def open_request(request: urllib.request.Request, verify_ssl: bool, reason: str) -> bytes:
    context = None if verify_ssl else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS, context=context) as response:
            status = response.getcode()
            body = response.read()
    except urllib.error.HTTPError as exc:
        raise DriverFailure(reason) from exc
    except urllib.error.URLError as exc:
        raise DriverFailure(reason) from exc
    if status < 200 or status >= 400:
        raise DriverFailure(reason)
    return body


def require_value(value: str | None, reason: str) -> str:
    if value is None:
        raise DriverFailure(reason)
    return value


def quote_path_segment(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def string_value(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    return None


def write_result(path: str, status: str, reason: str, triggered: int) -> None:
    directory = os.path.dirname(path)
    if directory != "":
        os.makedirs(directory, exist_ok=True)
    result = {
        "status": status,
        "reason": reason,
        "triggered_modules": triggered,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, separators=(",", ":"))
        handle.write("\n")


if __name__ == "__main__":
    sys.exit(main())
