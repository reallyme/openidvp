#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

"""Drive OIDF OpenID4VP verifier modules from the suite mock wallet.

The OIDF verifier plan acts as a mock wallet. Once each module reaches
WAITING it exposes an authorization endpoint; a verifier under test must start
its normal presentation request flow against that endpoint. This script is the
small CI sidecar that discovers those endpoints and triggers the verifier host
without logging Request Objects, request URIs, bearer tokens, or wallet data.
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
RESULT_FILENAME = "oidf-verifier-flow-driver.json"
STATUS_WAITING = "WAITING"


@dataclass(frozen=True)
class DriverConfig:
    conformance_server: str | None
    conformance_api_token: str | None
    conformance_verify_ssl: bool
    module_id: str | None
    authorization_endpoint: str | None
    verifier_launch_endpoint: str | None
    verifier_launch_token: str | None
    client_id: str | None
    request_uri: str | None
    request_object_jwt: str | None
    request_uri_method: str | None
    authorization_http_method: str
    timeout_seconds: float
    poll_seconds: float
    result_file: str


class DriverFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Trigger OIDF OpenID4VP verifier mock-wallet flows.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate configuration and write a result without network calls",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="trigger one discovered endpoint and exit instead of watching",
    )
    args = parser.parse_args()

    config: DriverConfig | None = None
    try:
        config = read_config()
        validate_config(config)
        if args.dry_run:
            write_result(config.result_file, "dry_run", "configuration_valid", 0)
            print("OIDF verifier flow driver dry run: configuration_valid")
            return 0
        triggered = run_driver(config, args.once)
        write_result(config.result_file, "passed", "flow_driver_completed", triggered)
        print(f"OIDF verifier flow driver completed: triggered={triggered}")
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
        "OIDF_FLOW_DRIVER_RESULT_FILE",
        default_result_file(),
    )
    return DriverConfig(
        conformance_server=empty_to_none(os.environ.get("CONFORMANCE_SERVER")),
        conformance_api_token=empty_to_none(os.environ.get("CONFORMANCE_API_TOKEN")),
        conformance_verify_ssl=read_bool_env("CONFORMANCE_VERIFY_SSL", True),
        module_id=empty_to_none(os.environ.get("OIDF_MODULE_ID")),
        authorization_endpoint=empty_to_none(os.environ.get("OIDF_AUTHORIZATION_ENDPOINT")),
        verifier_launch_endpoint=empty_to_none(os.environ.get("OIDF_VERIFIER_LAUNCH_ENDPOINT")),
        verifier_launch_token=empty_to_none(os.environ.get("OIDF_VERIFIER_LAUNCH_TOKEN")),
        client_id=empty_to_none(os.environ.get("OIDF_CLIENT_ID")),
        request_uri=empty_to_none(os.environ.get("OIDF_REQUEST_URI")),
        request_object_jwt=empty_to_none(os.environ.get("OIDF_REQUEST_OBJECT_JWT")),
        request_uri_method=empty_to_none(os.environ.get("OIDF_REQUEST_URI_METHOD")),
        authorization_http_method=os.environ.get("OIDF_AUTHORIZATION_HTTP_METHOD", "GET"),
        timeout_seconds=read_float_env("OIDF_FLOW_DRIVER_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
        poll_seconds=read_float_env("OIDF_FLOW_DRIVER_POLL_SECONDS", DEFAULT_POLL_SECONDS),
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
    method = config.authorization_http_method.upper()
    if method not in ("GET", "POST"):
        raise DriverFailure("invalid_authorization_http_method")
    if config.request_uri is not None and config.request_object_jwt is not None:
        raise DriverFailure("conflicting_request_material")
    if config.verifier_launch_endpoint is None:
        if config.request_uri is None and config.request_object_jwt is None:
            raise DriverFailure("missing_verifier_launch_or_request_material")
        if config.request_uri is not None and config.client_id is None:
            raise DriverFailure("missing_client_id_for_request_uri")
    if config.authorization_endpoint is None and config.conformance_server is None:
        raise DriverFailure("missing_authorization_endpoint_or_conformance_server")


def run_driver(config: DriverConfig, once: bool) -> int:
    if config.authorization_endpoint is not None:
        trigger_endpoint(config, "manual", None, config.authorization_endpoint)
        return 1

    deadline = time.monotonic() + config.timeout_seconds
    triggered_modules: set[str] = set()
    while time.monotonic() < deadline:
        triggered_this_poll = trigger_waiting_modules(config, triggered_modules)
        if once and triggered_this_poll > 0:
            return len(triggered_modules)
        time.sleep(config.poll_seconds)
    if len(triggered_modules) == 0:
        raise DriverFailure("no_waiting_oidf_verifier_module")
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
        endpoint = exposed_authorization_endpoint(runner_status)
        if endpoint is None:
            continue
        module_name = string_value(info.get("testName"))
        trigger_endpoint(config, module_id, module_name, endpoint)
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


def exposed_authorization_endpoint(status: dict[str, Any]) -> str | None:
    exposed = status.get("exposed")
    if not isinstance(exposed, dict):
        return None
    return string_value(exposed.get("authorization_endpoint"))


def trigger_endpoint(
    config: DriverConfig,
    module_id: str,
    module_name: str | None,
    authorization_endpoint: str,
) -> None:
    if config.verifier_launch_endpoint is not None:
        launch_verifier_host(config, module_id, module_name, authorization_endpoint)
    else:
        call_authorization_endpoint(config, authorization_endpoint)


def launch_verifier_host(
    config: DriverConfig,
    module_id: str,
    module_name: str | None,
    authorization_endpoint: str,
) -> None:
    payload = {
        "authorization_endpoint": authorization_endpoint,
        "module_id": module_id,
    }
    if module_name is not None:
        payload["module_name"] = module_name
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if config.verifier_launch_token is not None:
        headers["Authorization"] = f"Bearer {config.verifier_launch_token}"
    request = urllib.request.Request(
        config.verifier_launch_endpoint,
        data=body,
        headers=headers,
        method="POST",
    )
    response_body = open_request(request, config.conformance_verify_ssl, "verifier_launch_failed")
    if len(response_body) == 0:
        return
    launch = parse_verifier_launch_response(response_body)
    method = launch.get("method") or config.authorization_http_method
    call_authorization_endpoint_with_params(
        config,
        launch["authorization_endpoint"],
        launch["parameters"],
        method,
    )


def call_authorization_endpoint(config: DriverConfig, authorization_endpoint: str) -> None:
    params = authorization_endpoint_params(config)
    call_authorization_endpoint_with_params(
        config,
        authorization_endpoint,
        params,
        config.authorization_http_method,
    )


def call_authorization_endpoint_with_params(
    config: DriverConfig,
    authorization_endpoint: str,
    params: dict[str, str],
    authorization_http_method: str,
) -> None:
    method = authorization_http_method.upper()
    if method not in ("GET", "POST"):
        raise DriverFailure("invalid_authorization_http_method")
    if method == "POST":
        body = urllib.parse.urlencode(params).encode("utf-8")
        request = urllib.request.Request(
            authorization_endpoint,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
    else:
        separator = "&" if "?" in authorization_endpoint else "?"
        target = f"{authorization_endpoint}{separator}{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(target, method="GET")
    open_request(request, config.conformance_verify_ssl, "authorization_endpoint_call_failed")


def parse_verifier_launch_response(body: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise DriverFailure("verifier_launch_invalid_json") from exc
    if not isinstance(parsed, dict):
        raise DriverFailure("verifier_launch_invalid_json")
    endpoint = string_value(parsed.get("authorization_endpoint"))
    if endpoint is None:
        raise DriverFailure("verifier_launch_missing_authorization_endpoint")
    parameters = parse_verifier_launch_parameters(parsed.get("parameters"))
    launch: dict[str, Any] = {
        "authorization_endpoint": endpoint,
        "parameters": parameters,
    }
    method = string_value(parsed.get("method"))
    if method is not None:
        launch["method"] = method
    return launch


def parse_verifier_launch_parameters(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise DriverFailure("verifier_launch_invalid_parameters")
    parameters: dict[str, str] = {}
    for item in value:
        if not isinstance(item, dict):
            raise DriverFailure("verifier_launch_invalid_parameters")
        name = string_value(item.get("name"))
        parameter_value = string_value(item.get("value"))
        if name is None or parameter_value is None:
            raise DriverFailure("verifier_launch_invalid_parameters")
        if name in parameters:
            raise DriverFailure("verifier_launch_duplicate_parameter")
        parameters[name] = parameter_value
    if "request" not in parameters and "request_uri" not in parameters:
        raise DriverFailure("verifier_launch_missing_request_material")
    return parameters


def authorization_endpoint_params(config: DriverConfig) -> dict[str, str]:
    if config.request_uri is not None:
        params = {
            "client_id": require_value(config.client_id, "missing_client_id_for_request_uri"),
            "request_uri": config.request_uri,
        }
        if config.request_uri_method is not None:
            params["request_uri_method"] = config.request_uri_method
        return params
    return {"request": require_value(config.request_object_jwt, "missing_request_object_jwt")}


def require_value(value: str | None, reason: str) -> str:
    if value is None:
        raise DriverFailure(reason)
    return value


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
        if 300 <= exc.code < 400:
            raise DriverFailure(reason) from exc
        raise DriverFailure(reason) from exc
    except urllib.error.URLError as exc:
        raise DriverFailure(reason) from exc
    if status < 200 or status >= 400:
        raise DriverFailure(reason)
    return body


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
