// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_dcql::{evaluate_query, CredentialCandidate, DcqlError, Evaluation};
use reallyme_openid4vp_types::AuthorizationRequestObject;

/// Prepare wallet consent data by evaluating the request DCQL query.
pub fn prepare_consent_data(
    request: &AuthorizationRequestObject,
    candidates: &[CredentialCandidate],
) -> Result<Evaluation, DcqlError> {
    evaluate_query(&request.dcql_query, candidates)
}
