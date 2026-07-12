// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::MessageField;
use reallyme_openid4vp_dc_api::{
    DcApiAuthorizationResponse as DcApiAuthorizationResponseModel,
    DcApiProtocol as DcApiProtocolModel, DcApiRequestKind as DcApiRequestKindModel,
    DigitalCredentialGetRequest as DigitalCredentialGetRequestModel,
    DigitalCredentialGetRequestData as DigitalCredentialGetRequestDataModel,
    DigitalCredentialRequestOptions as DigitalCredentialRequestOptionsModel,
    EncryptedDcApiAuthorizationResponse as EncryptedDcApiAuthorizationResponseModel,
};
use reallyme_openid4vp_proto::generated::proto::openid4vp::v1 as pb;

use crate::convert::{authorization_request_to_proto, proto_to_authorization_request};
use crate::map_authorization_response::{
    authorization_response_to_proto, proto_to_authorization_response,
};
use crate::report_proto_error::OpenId4VpProtoError;

/// Map a DC API protocol identifier into generated protobuf.
pub fn dc_api_protocol_to_proto(protocol: &DcApiProtocolModel) -> pb::DcApiProtocol {
    pb::DcApiProtocol {
        version: u32::from(protocol.version),
        kind: buffa::EnumValue::from(dc_api_request_kind_to_proto(protocol.kind)),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated protobuf DC API protocol into the Rust model.
pub fn proto_to_dc_api_protocol(
    protocol: &pb::DcApiProtocol,
) -> Result<DcApiProtocolModel, OpenId4VpProtoError> {
    let version = u8::try_from(protocol.version).map_err(|_| OpenId4VpProtoError::InvalidField)?;
    Ok(DcApiProtocolModel {
        version,
        kind: proto_to_dc_api_request_kind(&protocol.kind)?,
    })
}

/// Map one Digital Credentials API request entry into generated protobuf.
pub fn digital_credential_get_request_to_proto(
    request: &DigitalCredentialGetRequestModel,
) -> Result<pb::DigitalCredentialGetRequest, OpenId4VpProtoError> {
    let data = match &request.data {
        DigitalCredentialGetRequestDataModel::Unsigned(data) => {
            Some(pb::digital_credential_get_request::Data::UnsignedRequest(
                Box::new(authorization_request_to_proto(data.as_ref())?),
            ))
        }
        DigitalCredentialGetRequestDataModel::Signed { request } => Some(
            pb::digital_credential_get_request::Data::SignedRequest(request.clone()),
        ),
    };
    Ok(pb::DigitalCredentialGetRequest {
        protocol: request.protocol.clone(),
        data,
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map one generated Digital Credentials API request entry into the Rust model.
pub fn proto_to_digital_credential_get_request(
    request: &pb::DigitalCredentialGetRequest,
) -> Result<DigitalCredentialGetRequestModel, OpenId4VpProtoError> {
    let Some(data) = request.data.as_ref() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    let data = match data {
        pb::digital_credential_get_request::Data::UnsignedRequest(data) => {
            DigitalCredentialGetRequestDataModel::Unsigned(Box::new(
                proto_to_authorization_request(data)?,
            ))
        }
        pb::digital_credential_get_request::Data::SignedRequest(request) => {
            DigitalCredentialGetRequestDataModel::Signed {
                request: request.clone(),
            }
        }
    };
    Ok(DigitalCredentialGetRequestModel {
        protocol: request.protocol.clone(),
        data,
    })
}

/// Map browser digital credential request options into generated protobuf.
pub fn digital_credential_request_options_to_proto(
    options: &DigitalCredentialRequestOptionsModel,
) -> Result<pb::DigitalCredentialRequestOptions, OpenId4VpProtoError> {
    Ok(pb::DigitalCredentialRequestOptions {
        requests: options
            .requests
            .iter()
            .map(digital_credential_get_request_to_proto)
            .collect::<Result<Vec<_>, _>>()?,
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map generated browser digital credential request options into the Rust model.
pub fn proto_to_digital_credential_request_options(
    options: &pb::DigitalCredentialRequestOptions,
) -> Result<DigitalCredentialRequestOptionsModel, OpenId4VpProtoError> {
    let requests = options
        .requests
        .iter()
        .map(proto_to_digital_credential_get_request)
        .collect::<Result<Vec<_>, _>>()?;
    DigitalCredentialRequestOptionsModel::new(requests)
        .map_err(|_| OpenId4VpProtoError::InvalidField)
}

/// Map a `response_mode=dc_api` response into generated protobuf.
pub fn dc_api_authorization_response_to_proto(
    response: &DcApiAuthorizationResponseModel,
) -> Result<pb::DcApiAuthorizationResponse, OpenId4VpProtoError> {
    Ok(pb::DcApiAuthorizationResponse {
        data: MessageField::some(authorization_response_to_proto(&response.data)?),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map generated `response_mode=dc_api` response into the Rust model.
pub fn proto_to_dc_api_authorization_response(
    response: &pb::DcApiAuthorizationResponse,
) -> Result<DcApiAuthorizationResponseModel, OpenId4VpProtoError> {
    let Some(data) = response.data.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    Ok(DcApiAuthorizationResponseModel {
        data: proto_to_authorization_response(data)?,
    })
}

/// Map an encrypted `response_mode=dc_api.jwt` response into generated protobuf.
pub fn encrypted_dc_api_authorization_response_to_proto(
    response: &EncryptedDcApiAuthorizationResponseModel,
) -> pb::EncryptedDcApiAuthorizationResponse {
    pb::EncryptedDcApiAuthorizationResponse {
        response: response.response.clone(),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated encrypted DC API response into the Rust model.
pub fn proto_to_encrypted_dc_api_authorization_response(
    response: &pb::EncryptedDcApiAuthorizationResponse,
) -> Result<EncryptedDcApiAuthorizationResponseModel, OpenId4VpProtoError> {
    EncryptedDcApiAuthorizationResponseModel::new(response.response.clone())
        .map_err(|_| OpenId4VpProtoError::InvalidField)
}

fn dc_api_request_kind_to_proto(kind: DcApiRequestKindModel) -> pb::DcApiRequestKind {
    match kind {
        DcApiRequestKindModel::Unsigned => pb::DcApiRequestKind::Unsigned,
        DcApiRequestKindModel::Signed => pb::DcApiRequestKind::Signed,
        DcApiRequestKindModel::Multisigned => pb::DcApiRequestKind::Multisigned,
    }
}

fn proto_to_dc_api_request_kind(
    kind: &buffa::EnumValue<pb::DcApiRequestKind>,
) -> Result<DcApiRequestKindModel, OpenId4VpProtoError> {
    match kind.as_known() {
        Some(pb::DcApiRequestKind::Unsigned) => Ok(DcApiRequestKindModel::Unsigned),
        Some(pb::DcApiRequestKind::Signed) => Ok(DcApiRequestKindModel::Signed),
        Some(pb::DcApiRequestKind::Multisigned) => Ok(DcApiRequestKindModel::Multisigned),
        Some(pb::DcApiRequestKind::Unspecified) | None => {
            Err(OpenId4VpProtoError::InvalidEnumValue)
        }
    }
}
