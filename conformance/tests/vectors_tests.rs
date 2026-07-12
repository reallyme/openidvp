// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Executes machine-readable conformance vectors against the implementation.

use reallyme_openid4vp_conformance::{
    parse_vectors, run_vector, ConformanceError, ConformanceResult, ConformanceVector,
    ExpectedResult, VectorOutcome,
};

const MALICIOUS_JSON_VECTORS: &str = include_str!("../vectors/openid4vp-malicious-json.json");

#[test]
fn malicious_json_vectors_match_implementation_behavior() -> ConformanceResult<()> {
    let vectors = parse_vectors(MALICIOUS_JSON_VECTORS)?;
    assert!(
        !vectors.is_empty(),
        "expected at least one conformance vector"
    );

    for vector in &vectors {
        let outcome = run_vector(vector)?;
        assert_eq!(
            outcome,
            VectorOutcome::Passed,
            "vector {} ({}) did not behave as expected: {outcome:?}",
            vector.id,
            vector.spec_section
        );
    }
    Ok(())
}

#[test]
fn unknown_target_fails_loudly() {
    let vector = ConformanceVector {
        id: "unknown".to_owned(),
        spec_section: "n/a".to_owned(),
        target: "types::DoesNotExist".to_owned(),
        input: "{}".to_owned(),
        expected: ExpectedResult::Reject,
    };
    assert_eq!(run_vector(&vector), Err(ConformanceError::UnknownTarget));
}

#[test]
fn accept_expectation_is_enforced() -> ConformanceResult<()> {
    let vector = ConformanceVector {
        id: "accept-dcql-query".to_owned(),
        spec_section: "OpenID4VP 1.0 Final DCQL".to_owned(),
        target: "dcql::DcqlQuery".to_owned(),
        input: r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]}}]}"#.to_owned(),
        expected: ExpectedResult::Accept,
    };
    assert_eq!(run_vector(&vector)?, VectorOutcome::Passed);
    Ok(())
}
