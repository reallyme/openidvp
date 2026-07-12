// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Checks that conformance control-plane manifests remain machine-readable.

use serde_json::Value;

#[test]
fn conformance_manifests_are_valid_json() {
    for (name, body) in manifests() {
        let parsed = serde_json::from_str::<Value>(body);
        assert!(parsed.is_ok(), "manifest {name} must parse as JSON");
    }
}

#[test]
fn oidf_baseline_is_pinned_and_vp_scoped() {
    let suite_lock = parse_json_or_null(include_str!("../oidf/suite.lock"));
    let suite = suite_lock.get("suite").unwrap_or(&Value::Null).clone();
    assert!(
        suite.get("repository").and_then(Value::as_str)
            == Some("https://gitlab.com/openid/conformance-suite")
    );
    assert!(suite.get("pinned_ref").and_then(Value::as_str) == Some("release-v5.2.0"));
    assert!(
        suite.get("commit").and_then(Value::as_str)
            == Some("dee9a25160e789f0f80517674693ef7989ab9fa1")
    );

    let plans = parse_json_or_null(include_str!("../oidf/plans.json"));
    assert!(
        plans.get("suite_commit").and_then(Value::as_str)
            == Some("dee9a25160e789f0f80517674693ef7989ab9fa1")
    );
    let modules = parse_json_or_null(include_str!("../oidf/modules.json"));
    assert!(
        modules.get("suite_commit").and_then(Value::as_str)
            == Some("dee9a25160e789f0f80517674693ef7989ab9fa1")
    );
    let module_entries = modules
        .get("modules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!module_entries.is_empty());
    let has_vp_modules = module_entries.iter().any(|item| {
        item.get("module_id")
            .and_then(Value::as_str)
            .is_some_and(|module_id| module_id.contains("oid4vp"))
    });
    assert!(has_vp_modules);
}

#[test]
fn oidf_report_manifest_tracks_pinned_plans() {
    let suite_lock = parse_json_or_null(include_str!("../oidf/suite.lock"));
    let reports = parse_json_or_null(include_str!("../reports/oidf-manifest.json"));
    assert!(
        reports
            .get("suite")
            .and_then(|suite| suite.get("commit"))
            .and_then(Value::as_str)
            == suite_lock
                .get("suite")
                .and_then(|suite| suite.get("commit"))
                .and_then(Value::as_str)
    );

    let report_targets = reports
        .get("report_targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!report_targets.is_empty());

    let plans = parse_json_or_null(include_str!("../oidf/plans.json"));
    for plan in plans
        .get("plans")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        assert_oidf_report_target(&report_targets, &plan);
    }
}

#[test]
fn oidf_runner_requires_exported_result_artifacts() {
    let workflow = include_str!("../../.github/workflows/conformance.yml");
    let runner = include_str!("../scripts/run_oidf_verifier_plan.sh");
    let wallet_runner = include_str!("../scripts/run_oidf_wallet_plan.sh");
    let wallet_driver = include_str!("../scripts/drive_oidf_wallet_flow.py");
    let verifier = include_str!("../scripts/assert_oidf_results.sh");
    let discovery = include_str!("../scripts/discover_oidf_openid4vp.py");
    let preflight = include_str!("../scripts/preflight_oidf_verifier.sh");
    let verifier_plan = include_str!("../oidf-verifier-plan.toml");
    let wallet_plan = include_str!("../oidf-wallet-plan.toml");
    let wallet_config = include_str!("../oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json");
    assert!(runner.contains("conformance/scripts/assert_oidf_results.sh"));
    assert!(runner.contains("oidf_suite_export_missing"));
    assert!(wallet_runner.contains("OIDF_WALLET_HARNESS_ENDPOINT"));
    assert!(wallet_runner.contains("OIDF_WALLET_FLOW_DRIVER_MODE"));
    assert!(wallet_runner.contains("conformance/scripts/drive_oidf_wallet_flow.py"));
    assert!(wallet_runner.contains("oidf_wallet_suite_runner_completed"));
    assert!(wallet_runner
        .contains("conformance/oidf/configs/vp-wallet-test-config-dcql-sdjwt-haip.json"));
    assert!(wallet_config.contains("\"dcql\""));
    assert!(!wallet_config.contains("presentation_definition"));
    assert!(wallet_config.contains("\"trust_anchor_pem\""));
    assert!(wallet_config.contains("\"status_list_trust_anchor_pem\""));
    assert!(workflow.contains("conformance/scripts/run_oidf_wallet_plan.sh"));
    assert!(workflow.contains("OIDF_WALLET_HARNESS_ENDPOINT"));
    assert!(workflow.contains("OIDF_WALLET_FLOW_DRIVER_MODE"));
    assert!(wallet_driver.contains("browser"));
    assert!(wallet_driver.contains("visited"));
    assert!(wallet_driver.contains("OIDF_WALLET_HARNESS_ENDPOINT"));
    assert!(verifier_plan.contains("oid4vp-1final-verifier-test-plan"));
    assert!(wallet_plan.contains("oid4vp-1final-wallet-test-plan"));
    assert!(wallet_plan.contains("reallyme/wallet"));
    assert!(verifier.contains("did not export any result files"));
    assert!(verifier.contains("exported only empty result files"));
    assert!(workflow.contains("conformance/scripts/preflight_oidf_verifier.sh"));
    assert!(workflow.contains("conformance/scripts/discover_oidf_openid4vp.py"));
    assert!(workflow.contains("mvn -q -DskipTests package"));
    assert!(workflow.contains("path: conformance/results"));
    assert!(workflow.contains("if-no-files-found: error"));
    assert!(preflight.contains("docker daemon is not reachable"));
    assert!(preflight.contains("missing required command"));
    assert!(discovery.contains("Discover OpenID4VP"));
}

#[test]
fn implemented_requirements_are_mapped_to_tests() {
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/openid4vp.json",
        body: parse_json_or_null(include_str!("../requirements/openid4vp.json")),
    });
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/haip-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/haip-presentation.json")),
    });
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/eudi-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/eudi-presentation.json")),
    });
}

#[test]
fn requirement_test_anchors_exist_in_repo() {
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/openid4vp.json",
        body: parse_json_or_null(include_str!("../requirements/openid4vp.json")),
    });
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/haip-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/haip-presentation.json")),
    });
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/eudi-presentation.json",
        body: parse_json_or_null(include_str!("../requirements/eudi-presentation.json")),
    });
}

#[test]
fn eudi_open_items_have_accountable_next_actions() {
    assert_open_items_have_next_actions(
        parse_json_or_null(include_str!("../eudi/test-cases.json"))
            .get("test_cases")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    assert_open_items_have_next_actions(
        parse_json_or_null(include_str!("../eudi/upstream-tests.json"))
            .get("tests")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
}

#[test]
fn eudi_fixture_inventory_has_owned_or_delegated_evidence() {
    let inventory = parse_json_or_null(include_str!("../eudi/fixture-inventory.json"));
    let fixtures = inventory
        .get("fixtures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !fixtures.is_empty(),
        "EUDI fixture inventory must contain fixture records"
    );

    for fixture in fixtures {
        let fixture_id = fixture
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-fixture");
        let status = fixture.get("status").and_then(Value::as_str).unwrap_or("");
        match status {
            "covered-locally" => {
                let path = fixture
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                assert!(
                    fixture_path_exists(path),
                    "local fixture inventory path must exist: {fixture_id} {path}"
                );
                assert!(
                    has_non_empty_string_array(&fixture, "local_evidence"),
                    "local fixture must map evidence: {fixture_id}"
                );
            }
            "delegated" => {
                assert!(
                    fixture
                        .get("owner")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "delegated fixture must name owner: {fixture_id}"
                );
                assert!(
                    has_non_empty_string_array(&fixture, "delegated_evidence"),
                    "delegated fixture must map evidence: {fixture_id}"
                );
            }
            _ => {
                assert!(
                    fixture
                        .get("next_action")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "open fixture must have next_action: {fixture_id}"
                );
            }
        }
    }
}

#[test]
fn style_audit_has_evidence_and_next_actions() {
    let audit = parse_json_or_null(include_str!("../reports/agents-style-audit.json"));
    assert!(
        audit.get("status").and_then(Value::as_str) == Some("reviewed"),
        "style audit must record a reviewed status"
    );

    let records = audit
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !records.is_empty(),
        "style audit must contain audit records"
    );

    for record in records {
        let record_id = record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-audit-record");
        assert!(
            record
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "style audit record must have status: {record_id}"
        );
        assert!(
            has_non_empty_string_array(&record, "evidence"),
            "style audit record must map evidence: {record_id}"
        );
        assert!(
            record
                .get("summary")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "style audit record must summarize finding: {record_id}"
        );
        let status = record.get("status").and_then(Value::as_str).unwrap_or("");
        if status != "passing" && status != "not_applicable" {
            assert!(
                record
                    .get("next_action")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "non-passing style audit record must have next_action: {record_id}"
            );
        }
    }
}

struct RequirementManifest {
    name: &'static str,
    body: Value,
}

fn parse_json_or_null(body: &str) -> Value {
    match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

fn assert_implemented_requirements_are_mapped(manifest: RequirementManifest) {
    let entries = requirements(&manifest);
    assert!(
        !entries.is_empty(),
        "requirement manifest must contain records: {}",
        manifest.name
    );

    for item in entries {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        if !status.starts_with("implemented") {
            continue;
        }

        let requirement_id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-requirement");
        assert!(
            has_non_empty_string_array(&item, "implementation_paths"),
            "implemented requirement must map implementation anchors: {} {}",
            manifest.name,
            requirement_id
        );
        assert!(
            has_non_empty_string_array(&item, "positive_tests")
                || has_non_empty_string_array(&item, "negative_tests"),
            "implemented requirement must map tests: {} {}",
            manifest.name,
            requirement_id
        );
    }
}

fn assert_requirement_test_anchors_exist(manifest: RequirementManifest) {
    for item in requirements(&manifest) {
        let requirement_id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-requirement");
        for test_name in string_array_values(&item, "positive_tests") {
            assert!(
                test_anchor_exists(test_name),
                "requirement maps an unknown positive test anchor: {} {} {}",
                manifest.name,
                requirement_id,
                test_name
            );
        }
        for test_name in string_array_values(&item, "negative_tests") {
            assert!(
                test_anchor_exists(test_name),
                "requirement maps an unknown negative test anchor: {} {} {}",
                manifest.name,
                requirement_id,
                test_name
            );
        }
    }
}

fn assert_open_items_have_next_actions(entries: Vec<Value>) {
    for item in entries {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        let has_local_test = item
            .get("local_test")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        let has_exclusion = item
            .get("exclusion_reason")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        if status.starts_with("implemented")
            || status.starts_with("covered-locally")
            || status == "pinned-release"
            || has_local_test
            || has_exclusion
        {
            continue;
        }
        assert!(
            item.get("next_action")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "open EUDI item must have next_action: {item:?}"
        );
    }
}

fn requirements(manifest: &RequirementManifest) -> Vec<Value> {
    manifest
        .body
        .get("requirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn has_non_empty_string_array(item: &Value, key: &str) -> bool {
    item.get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|entry| !entry.trim().is_empty()))
        })
}

fn string_array_values<'a>(item: &'a Value, key: &str) -> Vec<&'a str> {
    item.get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn test_anchor_exists(test_name: &str) -> bool {
    let Some(function_name) = test_name.rsplit("::").next() else {
        return false;
    };
    test_sources()
        .iter()
        .any(|source| source.contains(&["fn ", function_name].concat()))
}

fn test_sources() -> [&'static str; 21] {
    [
        include_str!("manifest_tests.rs"),
        include_str!("vectors_tests.rs"),
        include_str!("../../crates/dc-api/src/mdoc.rs"),
        include_str!("../../crates/dc-api/src/request.rs"),
        include_str!("../../crates/dcql/src/evaluate.rs"),
        include_str!("../../crates/formats/src/mdoc.rs"),
        include_str!("../../crates/http/src/resolve_request_uri.rs"),
        include_str!("../../crates/proto/codec/tests/verify_codec.rs"),
        include_str!("../../crates/profiles/src/describe_haip.rs"),
        include_str!("../../crates/runtime/src/verify_runtime.rs"),
        include_str!("../../crates/types/src/client_id.rs"),
        include_str!("../../crates/types/src/define_metadata.rs"),
        include_str!("../../crates/types/src/response.rs"),
        include_str!("../../crates/wallet/src/jar.rs"),
        include_str!("../../crates/wallet/src/metadata_reference.rs"),
        include_str!("../../crates/wallet/src/transport.rs"),
        include_str!("../../crates/wallet/src/verifier_attestation.rs"),
        include_str!("../../crates/wallet/src/verify_nested_request_object_with_jose.rs"),
        include_str!("../../crates/wallet/src/verify_signed_request_object_with_jose.rs"),
        include_str!("../../crates/verifier/src/binding.rs"),
        include_str!("../../crates/verifier/src/response.rs"),
    ]
}

fn manifests() -> [(&'static str, &'static str); 31] {
    [
        (
            "specifications.lock",
            include_str!("../specifications.lock"),
        ),
        (
            "requirements/openid4vp.json",
            include_str!("../requirements/openid4vp.json"),
        ),
        (
            "requirements/haip-presentation.json",
            include_str!("../requirements/haip-presentation.json"),
        ),
        (
            "requirements/eudi-presentation.json",
            include_str!("../requirements/eudi-presentation.json"),
        ),
        ("oidf/suite.lock", include_str!("../oidf/suite.lock")),
        ("oidf/plans.json", include_str!("../oidf/plans.json")),
        ("oidf/modules.json", include_str!("../oidf/modules.json")),
        (
            "oidf/exclusions.json",
            include_str!("../oidf/exclusions.json"),
        ),
        ("eudi/sources.lock", include_str!("../eudi/sources.lock")),
        (
            "eudi/test-cases.json",
            include_str!("../eudi/test-cases.json"),
        ),
        (
            "eudi/upstream-tests.json",
            include_str!("../eudi/upstream-tests.json"),
        ),
        (
            "eudi/exclusions.json",
            include_str!("../eudi/exclusions.json"),
        ),
        (
            "eudi/fixture-inventory.json",
            include_str!("../eudi/fixture-inventory.json"),
        ),
        (
            "vectors/openid4vp-malicious-json.json",
            include_str!("../vectors/openid4vp-malicious-json.json"),
        ),
        (
            "fixtures/eudi/reference-verifier-wallet.json",
            include_str!("../fixtures/eudi/reference-verifier-wallet.json"),
        ),
        (
            "fixtures/eudi/same-device-presentation.json",
            include_str!("../fixtures/eudi/same-device-presentation.json"),
        ),
        (
            "fixtures/eudi/cross-device-presentation.json",
            include_str!("../fixtures/eudi/cross-device-presentation.json"),
        ),
        (
            "fixtures/eudi/negative-nonce-mismatch.json",
            include_str!("../fixtures/eudi/negative-nonce-mismatch.json"),
        ),
        (
            "fixtures/ewc/eudi-wallet-rfcs-presentation.json",
            include_str!("../fixtures/ewc/eudi-wallet-rfcs-presentation.json"),
        ),
        (
            "fixtures/ewc/dc-api-wallet-flow.json",
            include_str!("../fixtures/ewc/dc-api-wallet-flow.json"),
        ),
        (
            "fixtures/dc-api/openid4vp-browser-request.json",
            include_str!("../fixtures/dc-api/openid4vp-browser-request.json"),
        ),
        (
            "fixtures/mdoc/annex-b-handover.json",
            include_str!("../fixtures/mdoc/annex-b-handover.json"),
        ),
        (
            "reports/openid4vp-base.json",
            include_str!("../reports/openid4vp-base.json"),
        ),
        (
            "reports/openid4vp-haip.json",
            include_str!("../reports/openid4vp-haip.json"),
        ),
        (
            "reports/openid4vp-eudi.json",
            include_str!("../reports/openid4vp-eudi.json"),
        ),
        (
            "reports/oidf-manifest.json",
            include_str!("../reports/oidf-manifest.json"),
        ),
        (
            "reports/oidf-verifier.json",
            include_str!("../reports/oidf-verifier.json"),
        ),
        (
            "reports/oidf-wallet.json",
            include_str!("../reports/oidf-wallet.json"),
        ),
        (
            "reports/eudi-interoperability.json",
            include_str!("../reports/eudi-interoperability.json"),
        ),
        (
            "reports/identity-sdk-migration.json",
            include_str!("../reports/identity-sdk-migration.json"),
        ),
        (
            "reports/agents-style-audit.json",
            include_str!("../reports/agents-style-audit.json"),
        ),
    ]
}

fn fixture_path_exists(path: &str) -> bool {
    matches!(
        path,
        "conformance/fixtures/eudi/reference-verifier-wallet.json"
            | "conformance/fixtures/eudi/same-device-presentation.json"
            | "conformance/fixtures/eudi/cross-device-presentation.json"
            | "conformance/fixtures/eudi/negative-nonce-mismatch.json"
            | "conformance/fixtures/ewc/eudi-wallet-rfcs-presentation.json"
            | "conformance/fixtures/ewc/dc-api-wallet-flow.json"
            | "conformance/fixtures/dc-api/openid4vp-browser-request.json"
            | "conformance/fixtures/mdoc/annex-b-handover.json"
    )
}

fn assert_oidf_report_target(report_targets: &[Value], plan: &Value) {
    let plan_id = plan
        .get("plan_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown-plan");
    let target = report_targets
        .iter()
        .find(|item| item.get("plan_id").and_then(Value::as_str) == Some(plan_id));
    assert!(
        target.is_some(),
        "missing OIDF report target for pinned plan: {plan_id}"
    );
    let Some(target) = target else {
        return;
    };

    assert!(
        target.get("role_under_test").and_then(Value::as_str)
            == plan.get("role_under_test").and_then(Value::as_str),
        "OIDF report target must preserve role: {plan_id}"
    );
    assert!(
        target.get("profile").and_then(Value::as_str)
            == plan.get("profile").and_then(Value::as_str),
        "OIDF report target must preserve profile: {plan_id}"
    );
    assert!(
        target
            .get("expected_report_path")
            .and_then(Value::as_str)
            .is_some_and(
                |value| value.starts_with("conformance/reports/oidf/") && value.ends_with(".json")
            ),
        "OIDF report target must have a JSON report path: {plan_id}"
    );
    assert!(
        target.get("status").and_then(Value::as_str) == Some("ready_for_execute_mode_external_run"),
        "OIDF report target must record execute-mode readiness: {plan_id}"
    );
    assert!(
        has_non_empty_string_array(target, "readiness_evidence"),
        "OIDF report target must map readiness evidence: {plan_id}"
    );
    assert!(
        has_non_empty_string_array(target, "required_artifacts"),
        "OIDF report target must declare required artifacts: {plan_id}"
    );
    assert!(
        target
            .get("next_action")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "OIDF report target must document next action: {plan_id}"
    );
}
