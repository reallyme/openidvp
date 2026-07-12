// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_openid4vp_dcql::CredentialFormat;
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{
    AlgorithmIdentifier, RequestUriMethod, ResponseMode, VerifierMetadata, WalletMetadata,
};

use crate::map_client_identifier::{
    client_identifier_prefix_to_proto, proto_to_client_identifier_prefix,
};
use crate::report_proto_error::OpenId4VpProtoError;

/// Map Rust verifier metadata capabilities into generated protobuf.
pub fn verifier_metadata_to_proto(metadata: &VerifierMetadata) -> pb::VerifierMetadataCapabilities {
    pb::VerifierMetadataCapabilities {
        response_modes_supported: metadata
            .response_modes_supported
            .iter()
            .copied()
            .map(response_mode_to_proto_enum)
            .collect(),
        client_id_prefixes_supported: metadata
            .client_id_prefixes_supported
            .iter()
            .copied()
            .map(client_identifier_prefix_to_proto)
            .map(buffa::EnumValue::from)
            .collect(),
        vp_formats_supported: credential_formats_to_proto(&metadata.vp_formats_supported),
        request_object_signing_alg_values_supported: algorithm_identifiers_to_proto(
            &metadata.request_object_signing_alg_values_supported,
        ),
        response_encryption_alg_values_supported: algorithm_identifiers_to_proto(
            &metadata.response_encryption_alg_values_supported,
        ),
        response_encryption_enc_values_supported: algorithm_identifiers_to_proto(
            &metadata.response_encryption_enc_values_supported,
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated protobuf verifier metadata capabilities into Rust.
pub fn proto_to_verifier_metadata(
    metadata: &pb::VerifierMetadataCapabilities,
) -> Result<VerifierMetadata, OpenId4VpProtoError> {
    let response_modes_supported = metadata
        .response_modes_supported
        .iter()
        .map(proto_to_response_mode)
        .collect::<Result<Vec<_>, _>>()?;
    let client_id_prefixes_supported = metadata
        .client_id_prefixes_supported
        .iter()
        .map(proto_to_client_identifier_prefix)
        .collect::<Result<Vec<_>, _>>()?;
    let vp_formats_supported = metadata
        .vp_formats_supported
        .iter()
        .map(proto_to_credential_format)
        .collect::<Result<Vec<_>, _>>()?;
    let request_object_signing_alg_values_supported = metadata
        .request_object_signing_alg_values_supported
        .iter()
        .map(proto_to_algorithm_identifier)
        .collect::<Result<Vec<_>, _>>()?;
    let response_encryption_alg_values_supported = metadata
        .response_encryption_alg_values_supported
        .iter()
        .map(proto_to_algorithm_identifier)
        .collect::<Result<Vec<_>, _>>()?;
    let response_encryption_enc_values_supported = metadata
        .response_encryption_enc_values_supported
        .iter()
        .map(proto_to_algorithm_identifier)
        .collect::<Result<Vec<_>, _>>()?;

    VerifierMetadata::new(
        response_modes_supported,
        client_id_prefixes_supported,
        vp_formats_supported,
        request_object_signing_alg_values_supported,
        response_encryption_alg_values_supported,
        response_encryption_enc_values_supported,
    )
    .map_err(Into::into)
}

/// Map Rust wallet metadata capabilities into generated protobuf.
pub fn wallet_metadata_to_proto(metadata: &WalletMetadata) -> pb::WalletMetadataCapabilities {
    pb::WalletMetadataCapabilities {
        response_modes_supported: metadata
            .response_modes_supported
            .iter()
            .copied()
            .map(response_mode_to_proto_enum)
            .collect(),
        request_uri_methods_supported: metadata
            .request_uri_methods_supported
            .iter()
            .copied()
            .map(request_uri_method_to_proto_enum)
            .collect(),
        vp_formats_supported: credential_formats_to_proto(&metadata.vp_formats_supported),
        response_encryption_alg_values_supported: algorithm_identifiers_to_proto(
            &metadata.response_encryption_alg_values_supported,
        ),
        response_encryption_enc_values_supported: algorithm_identifiers_to_proto(
            &metadata.response_encryption_enc_values_supported,
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated protobuf wallet metadata capabilities into Rust.
pub fn proto_to_wallet_metadata(
    metadata: &pb::WalletMetadataCapabilities,
) -> Result<WalletMetadata, OpenId4VpProtoError> {
    let response_modes_supported = metadata
        .response_modes_supported
        .iter()
        .map(proto_to_response_mode)
        .collect::<Result<Vec<_>, _>>()?;
    let request_uri_methods_supported = metadata
        .request_uri_methods_supported
        .iter()
        .map(proto_to_request_uri_method)
        .collect::<Result<Vec<_>, _>>()?;
    let vp_formats_supported = metadata
        .vp_formats_supported
        .iter()
        .map(proto_to_credential_format)
        .collect::<Result<Vec<_>, _>>()?;
    let response_encryption_alg_values_supported = metadata
        .response_encryption_alg_values_supported
        .iter()
        .map(proto_to_algorithm_identifier)
        .collect::<Result<Vec<_>, _>>()?;
    let response_encryption_enc_values_supported = metadata
        .response_encryption_enc_values_supported
        .iter()
        .map(proto_to_algorithm_identifier)
        .collect::<Result<Vec<_>, _>>()?;

    WalletMetadata::new(
        response_modes_supported,
        request_uri_methods_supported,
        vp_formats_supported,
        response_encryption_alg_values_supported,
        response_encryption_enc_values_supported,
    )
    .map_err(Into::into)
}

fn response_mode_to_proto_enum(mode: ResponseMode) -> buffa::EnumValue<pb::ResponseMode> {
    let proto = match mode {
        ResponseMode::Fragment => pb::ResponseMode::Fragment,
        ResponseMode::FormPost => pb::ResponseMode::FormPost,
        ResponseMode::DirectPost => pb::ResponseMode::DirectPost,
        ResponseMode::DirectPostJwt => pb::ResponseMode::DirectPostJwt,
        ResponseMode::DcApi => pb::ResponseMode::DcApi,
        ResponseMode::DcApiJwt => pb::ResponseMode::DcApiJwt,
    };
    buffa::EnumValue::from(proto)
}

fn proto_to_response_mode(
    mode: &buffa::EnumValue<pb::ResponseMode>,
) -> Result<ResponseMode, OpenId4VpProtoError> {
    match mode.as_known() {
        Some(pb::ResponseMode::Fragment) => Ok(ResponseMode::Fragment),
        Some(pb::ResponseMode::FormPost) => Ok(ResponseMode::FormPost),
        Some(pb::ResponseMode::DirectPost) => Ok(ResponseMode::DirectPost),
        Some(pb::ResponseMode::DirectPostJwt) => Ok(ResponseMode::DirectPostJwt),
        Some(pb::ResponseMode::DcApi) => Ok(ResponseMode::DcApi),
        Some(pb::ResponseMode::DcApiJwt) => Ok(ResponseMode::DcApiJwt),
        Some(pb::ResponseMode::Unspecified) | None => Err(OpenId4VpProtoError::InvalidEnumValue),
    }
}

fn request_uri_method_to_proto_enum(
    method: RequestUriMethod,
) -> buffa::EnumValue<pb::RequestUriMethod> {
    let proto = match method {
        RequestUriMethod::Get => pb::RequestUriMethod::Get,
        RequestUriMethod::Post => pb::RequestUriMethod::Post,
    };
    buffa::EnumValue::from(proto)
}

fn proto_to_request_uri_method(
    method: &buffa::EnumValue<pb::RequestUriMethod>,
) -> Result<RequestUriMethod, OpenId4VpProtoError> {
    match method.as_known() {
        Some(pb::RequestUriMethod::Get) => Ok(RequestUriMethod::Get),
        Some(pb::RequestUriMethod::Post) => Ok(RequestUriMethod::Post),
        Some(pb::RequestUriMethod::Unspecified) | None => {
            Err(OpenId4VpProtoError::InvalidEnumValue)
        }
    }
}

fn credential_formats_to_proto(
    formats: &[CredentialFormat],
) -> Vec<pb::CredentialFormatIdentifier> {
    formats
        .iter()
        .map(|format| pb::CredentialFormatIdentifier {
            value: format.as_str().to_owned(),
            __buffa_unknown_fields: Default::default(),
        })
        .collect()
}

fn proto_to_credential_format(
    format: &pb::CredentialFormatIdentifier,
) -> Result<CredentialFormat, OpenId4VpProtoError> {
    CredentialFormat::new(format.value.clone()).map_err(|_| OpenId4VpProtoError::InvalidField)
}

fn algorithm_identifiers_to_proto(
    identifiers: &[AlgorithmIdentifier],
) -> Vec<pb::AlgorithmIdentifier> {
    identifiers
        .iter()
        .map(|identifier| pb::AlgorithmIdentifier {
            value: identifier.as_str().to_owned(),
            __buffa_unknown_fields: Default::default(),
        })
        .collect()
}

fn proto_to_algorithm_identifier(
    identifier: &pb::AlgorithmIdentifier,
) -> Result<AlgorithmIdentifier, OpenId4VpProtoError> {
    AlgorithmIdentifier::new(identifier.value.clone()).map_err(Into::into)
}
