// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;

use crate::compare_secret::constant_time_str_eq;
use crate::{RequestBinding, VerifierError, VerifierErrorReason};

/// Decoded holder-binding JWT claims relevant to OpenID4VP binding.
///
/// Signature verification and format-specific JWT parsing live in
/// `reallyme/identity` envelope crates and thin format adapters. This pure
/// validator ports the meproto claim checks that remain valid after the
/// final-spec DCQL rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderBindingClaims {
    /// Audience values from the holder-binding proof.
    #[serde(deserialize_with = "deserialize_audience")]
    pub audience: Vec<String>,
    /// Nonce from the holder-binding proof.
    pub nonce: String,
    /// Optional expiration time in Unix seconds.
    ///
    /// Standard SD-JWT KB-JWT holder binding requires `nonce` and `aud`.
    /// Formats that also supply `exp` get full temporal enforcement; absent
    /// `exp` is represented as `0` to keep the FFI/proto shape stable.
    pub expiration_unix: u64,
    /// Optional issued-at time in Unix seconds.
    #[serde(default)]
    pub issued_at_unix: u64,
    /// Optional SD-JWT KB-JWT `sd_hash` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd_hash: Option<String>,
}

/// Validate decoded holder-binding claims against a verifier request binding.
pub fn validate_holder_binding_claims(
    binding: &RequestBinding,
    claims: &HolderBindingClaims,
    now_unix: u64,
) -> Result<(), VerifierError> {
    if claims.audience.is_empty() || claims.nonce.is_empty() {
        return Err(VerifierError::new(
            VerifierErrorReason::MissingHolderBindingClaim,
        ));
    }

    let expected_audience = binding.client_id.to_wire_value();
    if !claims
        .audience
        .iter()
        .any(|audience| audience == &expected_audience)
    {
        return Err(VerifierError::new(
            VerifierErrorReason::HolderBindingAudienceMismatch,
        ));
    }

    if !constant_time_str_eq(&claims.nonce, &binding.nonce) {
        return Err(VerifierError::new(
            VerifierErrorReason::HolderBindingNonceMismatch,
        ));
    }

    if claims.expiration_unix != 0
        && (claims.expiration_unix <= now_unix || claims.expiration_unix > binding.expiry_unix)
    {
        return Err(VerifierError::new(
            VerifierErrorReason::HolderBindingExpired,
        ));
    }

    Ok(())
}

/// Extract OpenID4VP holder-binding claims from an already verified JWT payload.
///
/// This function does not parse or verify a compact JWT. Callers must pass
/// payload JSON only after the format/JWS layer has verified the holder proof
/// signature and key binding.
pub fn holder_binding_claims_from_verified_payload(
    payload: &JsonValue,
) -> Result<HolderBindingClaims, VerifierError> {
    let audience = payload_audience(payload)?;
    let nonce = payload
        .get("nonce")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| VerifierError::new(VerifierErrorReason::MissingHolderBindingClaim))?
        .to_owned();
    let expiration_unix = payload.get("exp").and_then(JsonValue::as_u64).unwrap_or(0);
    let issued_at_unix = payload.get("iat").and_then(JsonValue::as_u64).unwrap_or(0);
    let sd_hash = payload
        .get("sd_hash")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);

    Ok(HolderBindingClaims {
        audience,
        nonce,
        expiration_unix,
        issued_at_unix,
        sd_hash,
    })
}

fn payload_audience(payload: &JsonValue) -> Result<Vec<String>, VerifierError> {
    match payload.get("aud") {
        Some(JsonValue::String(value)) => Ok(vec![value.clone()]),
        Some(JsonValue::Array(values)) => {
            let mut audience = Vec::with_capacity(values.len());
            for value in values {
                let Some(audience_value) = value.as_str() else {
                    return Err(VerifierError::new(
                        VerifierErrorReason::MissingHolderBindingClaim,
                    ));
                };
                audience.push(audience_value.to_owned());
            }
            if audience.is_empty() {
                return Err(VerifierError::new(
                    VerifierErrorReason::MissingHolderBindingClaim,
                ));
            }
            Ok(audience)
        }
        Some(_) | None => Err(VerifierError::new(
            VerifierErrorReason::MissingHolderBindingClaim,
        )),
    }
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    match Audience::deserialize(deserializer)? {
        Audience::One(value) => Ok(vec![value]),
        Audience::Many(values) => Ok(values),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use reallyme_openid4vp_types::ClientIdentifier;

    use crate::holder_binding::{
        holder_binding_claims_from_verified_payload, validate_holder_binding_claims,
    };
    use crate::{HolderBindingClaims, RequestBinding, VerifierErrorReason};

    fn binding() -> RequestBinding {
        RequestBinding {
            client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
            nonce: "nonce".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            expiry_unix: 100,
            transaction_data_hash: None,
        }
    }

    #[test]
    fn accepts_matching_holder_binding_claims() {
        let claims = HolderBindingClaims {
            audience: vec!["x509_san_dns:verifier.example".to_owned()],
            nonce: "nonce".to_owned(),
            expiration_unix: 90,
            issued_at_unix: 10,
            sd_hash: None,
        };

        validate_holder_binding_claims(&binding(), &claims, 10)
            .expect("matching holder binding claims validate");
    }

    #[test]
    fn accepts_holder_binding_without_expiration() {
        let claims = HolderBindingClaims {
            audience: vec!["x509_san_dns:verifier.example".to_owned()],
            nonce: "nonce".to_owned(),
            expiration_unix: 0,
            issued_at_unix: 10,
            sd_hash: None,
        };

        validate_holder_binding_claims(&binding(), &claims, 10)
            .expect("standard KB-JWT without exp validates when nonce and aud bind");
    }

    #[test]
    fn deserializes_string_audience() {
        let claims: HolderBindingClaims = serde_json::from_str(
            r#"{"audience":"x509_san_dns:verifier.example","nonce":"nonce","expiration_unix":0}"#,
        )
        .expect("string audience deserializes");

        assert_eq!(claims.audience, vec!["x509_san_dns:verifier.example"]);
    }

    #[test]
    fn extracts_claims_from_verified_kb_jwt_payload() {
        let payload = serde_json::json!({
            "aud": "x509_san_dns:verifier.example",
            "nonce": "nonce",
            "iat": 10,
            "sd_hash": "hash"
        });

        let claims = holder_binding_claims_from_verified_payload(&payload)
            .expect("verified payload claims extract");

        assert_eq!(claims.audience, vec!["x509_san_dns:verifier.example"]);
        assert_eq!(claims.nonce, "nonce");
        assert_eq!(claims.expiration_unix, 0);
        assert_eq!(claims.issued_at_unix, 10);
        assert_eq!(claims.sd_hash.as_deref(), Some("hash"));
    }

    #[test]
    fn rejects_holder_binding_expiring_after_request() {
        let claims = HolderBindingClaims {
            audience: vec!["x509_san_dns:verifier.example".to_owned()],
            nonce: "nonce".to_owned(),
            expiration_unix: 101,
            issued_at_unix: 10,
            sd_hash: None,
        };

        let err = validate_holder_binding_claims(&binding(), &claims, 10)
            .expect_err("holder binding must not outlive request binding");

        assert_eq!(err.reason(), VerifierErrorReason::HolderBindingExpired);
    }

    #[test]
    fn rejects_holder_binding_with_wrong_audience() {
        let claims = HolderBindingClaims {
            audience: vec!["x509_san_dns:other.example".to_owned()],
            nonce: "nonce".to_owned(),
            expiration_unix: 90,
            issued_at_unix: 10,
            sd_hash: None,
        };

        let err = validate_holder_binding_claims(&binding(), &claims, 10)
            .expect_err("audience must bind to the verifier client identifier");

        assert_eq!(
            err.reason(),
            VerifierErrorReason::HolderBindingAudienceMismatch
        );
    }

    #[test]
    fn rejects_holder_binding_with_wrong_nonce() {
        let claims = HolderBindingClaims {
            audience: vec!["x509_san_dns:verifier.example".to_owned()],
            nonce: "other-nonce".to_owned(),
            expiration_unix: 90,
            issued_at_unix: 10,
            sd_hash: None,
        };

        let err = validate_holder_binding_claims(&binding(), &claims, 10)
            .expect_err("nonce must bind to the verifier request");

        assert_eq!(
            err.reason(),
            VerifierErrorReason::HolderBindingNonceMismatch
        );
    }

    #[test]
    fn rejects_holder_binding_expired_before_validation() {
        let claims = HolderBindingClaims {
            audience: vec!["x509_san_dns:verifier.example".to_owned()],
            nonce: "nonce".to_owned(),
            expiration_unix: 10,
            issued_at_unix: 10,
            sd_hash: None,
        };

        let err = validate_holder_binding_claims(&binding(), &claims, 10)
            .expect_err("expired holder binding proof is rejected");

        assert_eq!(err.reason(), VerifierErrorReason::HolderBindingExpired);
    }
}
