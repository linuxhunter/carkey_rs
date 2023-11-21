use std::fmt::{Display, Formatter};
use crate::iccoa2::{errors, Serde};
use crate::iccoa2::instructions::auth_0::{CommandApduAuth0, ResponseApduAuth0};
use crate::iccoa2::instructions::auth_1::{CommandApduAuth1, ResponseApduAuth1};
use crate::iccoa2::instructions::enable_disable::{CommandApduEnableDisable, ResponseApduEnableDisable};
use crate::iccoa2::instructions::get_challenge::{CommandApduGetChallenge, ResponseApduGetChallenge};
use crate::iccoa2::instructions::get_dk_certificate::{CommandApduGetDkCert, ResponseApduGetDkCert};
use crate::iccoa2::instructions::get_response::{CommandApduGetResponse, ResponseApduGetResponse};
use crate::iccoa2::instructions::list_dk::{CommandApduListDk, ResponseApduListDk};
use crate::iccoa2::instructions::rke::{CommandApduRke, ResponseApduRke};
use crate::iccoa2::instructions::select::{CommandApduSelect, ResponseApduSelect};
use crate::iccoa2::instructions::sharing_request::{CommandApduSharingRequest, ResponseApduSharingRequest};
use crate::iccoa2::instructions::sign::{CommandApduSign, ResponseApduSign};

pub mod common;
pub mod select;
pub mod list_dk;
pub mod auth_0;
pub mod auth_1;
pub mod get_dk_certificate;
pub mod sharing_request;
pub mod rke;
pub mod sign;
pub mod enable_disable;
pub mod get_challenge;
pub mod get_response;

const VERSION_TAG: u8 = 0x5A;
const RANDOM_TAG: u8 = 0x55;
const RKE_CMD_TAG: u8 = 0x57;
const SIGN_DATA_TAG: u8 = 0x58;
const VEHICLE_TEMP_PUB_KEY_TAG: u8 = 0x81;
const VEHICLE_ID_TAG: u8 = 0x83;
const DEVICE_TEMP_PUB_KEY_TAG: u8 = 0x84;
const CRYPTO_GRAM_TAG: u8 = 0x85;
const KEY_ID_STATUS_TAG: u8 = 0x88;
const KEY_ID_TAG: u8 = 0x89;
const SIGNATURE_TAG: u8 = 0x8F; //origin 0x9F

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum ApduInstructionType {
    CommandSelect = 0x01,
    ResponseSelect = 0x02,
    CommandListDk = 0x03,
    ResponseListDk = 0x04,
    CommandAuth0 = 0x05,
    ResponseAuth0 = 0x06,
    CommandAuth1 = 0x07,
    ResponseAuth1 = 0x08,
    CommandGetDkCert = 0x09,
    ResponseGetDkCert = 0x0A,
    CommandSharingRequest = 0x0B,
    ResponseSharingRequest = 0x0C,
    CommandRke = 0x0D,
    ResponseRke = 0x0E,
    CommandSign = 0x0F,
    ResponseSign = 0x10,
    CommandDisableDk= 0x11,
    ResponseDisableDk= 0x12,
    CommandEnableDk= 0x13,
    ResponseEnableDk= 0x14,
    CommandGetChallenge= 0x15,
    ResponseGetChallenge= 0x16,
    CommandGetResponse= 0x17,
    ResponseGetResponse= 0x18,
}

impl TryFrom<u8> for ApduInstructionType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(ApduInstructionType::CommandSelect),
            0x02 => Ok(ApduInstructionType::ResponseSelect),
            0x03 => Ok(ApduInstructionType::CommandListDk),
            0x04 => Ok(ApduInstructionType::ResponseListDk),
            0x05 => Ok(ApduInstructionType::CommandAuth0),
            0x06 => Ok(ApduInstructionType::ResponseAuth0),
            0x07 => Ok(ApduInstructionType::CommandAuth1),
            0x08 => Ok(ApduInstructionType::ResponseAuth1),
            0x09 => Ok(ApduInstructionType::CommandGetDkCert),
            0x0A => Ok(ApduInstructionType::ResponseGetDkCert),
            0x0B => Ok(ApduInstructionType::CommandSharingRequest),
            0x0C => Ok(ApduInstructionType::ResponseSharingRequest),
            0x0D => Ok(ApduInstructionType::CommandRke),
            0x0E => Ok(ApduInstructionType::ResponseRke),
            0x0F => Ok(ApduInstructionType::CommandSign),
            0x10 => Ok(ApduInstructionType::ResponseSign),
            0x11 => Ok(ApduInstructionType::CommandDisableDk),
            0x12 => Ok(ApduInstructionType::ResponseDisableDk),
            0x13 => Ok(ApduInstructionType::CommandEnableDk),
            0x14 => Ok(ApduInstructionType::ResponseEnableDk),
            0x15 => Ok(ApduInstructionType::CommandGetChallenge),
            0x16 => Ok(ApduInstructionType::ResponseGetChallenge),
            0x17 => Ok(ApduInstructionType::CommandGetResponse),
            0x18 => Ok(ApduInstructionType::ResponseGetResponse),
            _ => Err(format!("Unsupported Apdu Instruction type: {}", value)),
        }
    }
}

impl From<ApduInstructionType> for u8 {
    fn from(value: ApduInstructionType) -> Self {
        match value {
            ApduInstructionType::CommandSelect => 0x01,
            ApduInstructionType::ResponseSelect => 0x02,
            ApduInstructionType::CommandListDk => 0x03,
            ApduInstructionType::ResponseListDk => 0x04,
            ApduInstructionType::CommandAuth0 => 0x05,
            ApduInstructionType::ResponseAuth0 => 0x06,
            ApduInstructionType::CommandAuth1 => 0x07,
            ApduInstructionType::ResponseAuth1 => 0x08,
            ApduInstructionType::CommandGetDkCert => 0x09,
            ApduInstructionType::ResponseGetDkCert => 0x0A,
            ApduInstructionType::CommandSharingRequest => 0x0B,
            ApduInstructionType::ResponseSharingRequest => 0x0C,
            ApduInstructionType::CommandRke => 0x0D,
            ApduInstructionType::ResponseRke => 0x0E,
            ApduInstructionType::CommandSign => 0x0F,
            ApduInstructionType::ResponseSign => 0x10,
            ApduInstructionType::CommandDisableDk => 0x11,
            ApduInstructionType::ResponseDisableDk => 0x12,
            ApduInstructionType::CommandEnableDk => 0x13,
            ApduInstructionType::ResponseEnableDk => 0x14,
            ApduInstructionType::CommandGetChallenge => 0x15,
            ApduInstructionType::ResponseGetChallenge => 0x16,
            ApduInstructionType::CommandGetResponse => 0x17,
            ApduInstructionType::ResponseGetResponse => 0x18,
        }
    }
}

impl Display for ApduInstructionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApduInstructionType::CommandSelect => write!(f, "Command Select"),
            ApduInstructionType::ResponseSelect => write!(f, "Response Select"),
            ApduInstructionType::CommandListDk => write!(f, "Command List Dk"),
            ApduInstructionType::ResponseListDk => write!(f, "Response List Dk"),
            ApduInstructionType::CommandAuth0 => write!(f, "Command Auth 0"),
            ApduInstructionType::ResponseAuth0 => write!(f, "Response Auth 0"),
            ApduInstructionType::CommandAuth1 => write!(f, "Command Auth 1"),
            ApduInstructionType::ResponseAuth1 => write!(f, "Response Auth 1"),
            ApduInstructionType::CommandGetDkCert => write!(f, "Command Get Dk Certificate"),
            ApduInstructionType::ResponseGetDkCert => write!(f, "Response Get Dk Certificate"),
            ApduInstructionType::CommandSharingRequest => write!(f, "Command Sharing Request"),
            ApduInstructionType::ResponseSharingRequest => write!(f, "Response Sharing Request"),
            ApduInstructionType::CommandRke => write!(f, "Command Rke"),
            ApduInstructionType::ResponseRke => write!(f, "Response Rke"),
            ApduInstructionType::CommandSign => write!(f, "Command Sign"),
            ApduInstructionType::ResponseSign => write!(f, "Response Sign"),
            ApduInstructionType::CommandDisableDk => write!(f, "Command Disable Dk"),
            ApduInstructionType::ResponseDisableDk => write!(f, "Response Disable Dk"),
            ApduInstructionType::CommandEnableDk => write!(f, "Command Enable Dk"),
            ApduInstructionType::ResponseEnableDk => write!(f, "Response Enable Dk"),
            ApduInstructionType::CommandGetChallenge => write!(f, "Command Get Challenge"),
            ApduInstructionType::ResponseGetChallenge => write!(f, "Response Get Challenge"),
            ApduInstructionType::CommandGetResponse => write!(f, "Command Get Response"),
            ApduInstructionType::ResponseGetResponse => write!(f, "Response Get Response"),
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum ApduInstructions {
    CommandSelect(CommandApduSelect),
    ResponseSelect(ResponseApduSelect),
    CommandListDk(CommandApduListDk),
    ResponseListDk(ResponseApduListDk),
    CommandAuth0(CommandApduAuth0),
    ResponseAuth0(ResponseApduAuth0),
    CommandAuth1(Vec<u8>),
    ResponseAuth1(Vec<u8>),
    CommandGetDkCert(CommandApduGetDkCert),
    ResponseGetDkCert(ResponseApduGetDkCert),
    CommandSharingRequest(CommandApduSharingRequest),
    ResponseSharingRequest(ResponseApduSharingRequest),
    CommandRke(CommandApduRke),
    ResponseRke(ResponseApduRke),
    CommandSign(CommandApduSign),
    ResponseSign(ResponseApduSign),
    CommandDisableDk(CommandApduEnableDisable),
    ResponseDisableDk(ResponseApduEnableDisable),
    CommandEnableDk(CommandApduEnableDisable),
    ResponseEnableDk(ResponseApduEnableDisable),
    CommandGetChallenge(CommandApduGetChallenge),
    ResponseGetChallenge(ResponseApduGetChallenge),
    CommandGetResponse(CommandApduGetResponse),
    ResponseGetResponse(ResponseApduGetResponse),
}

impl Serde for ApduInstructions {
    type Output = Self;

    fn serialize(&self) -> errors::Result<Vec<u8>> {
        match self {
            ApduInstructions::CommandSelect(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandSelect)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseSelect(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseSelect)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandListDk(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandListDk)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseListDk(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseListDk)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandAuth0(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandAuth0)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseAuth0(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseAuth0)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandAuth1(request) => {
                Ok(request.to_vec())
            },
            ApduInstructions::ResponseAuth1(response) => {
                Ok(response.to_vec())
            },
            ApduInstructions::CommandGetDkCert(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandGetDkCert)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseGetDkCert(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseGetDkCert)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandSharingRequest(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandSharingRequest)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseSharingRequest(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseSharingRequest)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandRke(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandRke)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseRke(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseRke)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandSign(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandSign)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseSign(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseSign)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandDisableDk(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandDisableDk)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseDisableDk(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseDisableDk)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandEnableDk(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandEnableDk)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseEnableDk(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseEnableDk)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandGetChallenge(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandGetChallenge)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseGetChallenge(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseGetChallenge)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::CommandGetResponse(request) => {
                let mut buffer = vec![u8::from(ApduInstructionType::CommandGetResponse)];
                buffer.append(&mut request.serialize()?);
                Ok(buffer)
            },
            ApduInstructions::ResponseGetResponse(response) => {
                let mut buffer = vec![u8::from(ApduInstructionType::ResponseGetResponse)];
                buffer.append(&mut response.serialize()?);
                Ok(buffer)
            },
        }
    }

    fn deserialize(data: &[u8]) -> errors::Result<Self::Output> {
        let apdu_type = ApduInstructionType::try_from(data[0])?;
        let apdu_buffer = &data[1..];
        match apdu_type {
            ApduInstructionType::CommandSelect => Ok(ApduInstructions::CommandSelect(CommandApduSelect::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseSelect => Ok(ApduInstructions::ResponseSelect(ResponseApduSelect::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandListDk => Ok(ApduInstructions::CommandListDk(CommandApduListDk::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseListDk => Ok(ApduInstructions::ResponseListDk(ResponseApduListDk::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandAuth0 => Ok(ApduInstructions::CommandAuth0(CommandApduAuth0::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseAuth0 => Ok(ApduInstructions::ResponseAuth0(ResponseApduAuth0::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandAuth1 => Ok(ApduInstructions::CommandAuth1(CommandApduAuth1::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseAuth1 => Ok(ApduInstructions::ResponseAuth1(ResponseApduAuth1::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandGetDkCert => Ok(ApduInstructions::CommandGetDkCert(CommandApduGetDkCert::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseGetDkCert => Ok(ApduInstructions::ResponseGetDkCert(ResponseApduGetDkCert::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandSharingRequest => Ok(ApduInstructions::CommandSharingRequest(CommandApduSharingRequest::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseSharingRequest => Ok(ApduInstructions::ResponseSharingRequest(ResponseApduSharingRequest::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandRke => Ok(ApduInstructions::CommandRke(CommandApduRke::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseRke => Ok(ApduInstructions::ResponseRke(ResponseApduRke::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandSign => Ok(ApduInstructions::CommandSign(CommandApduSign::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseSign => Ok(ApduInstructions::ResponseSign(ResponseApduSign::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandDisableDk => Ok(ApduInstructions::CommandDisableDk(CommandApduEnableDisable::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseDisableDk => Ok(ApduInstructions::ResponseDisableDk(ResponseApduEnableDisable::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandEnableDk => Ok(ApduInstructions::CommandEnableDk(CommandApduEnableDisable::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseEnableDk => Ok(ApduInstructions::ResponseEnableDk(ResponseApduEnableDisable::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandGetChallenge => Ok(ApduInstructions::CommandGetChallenge(CommandApduGetChallenge::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseGetChallenge => Ok(ApduInstructions::ResponseGetChallenge(ResponseApduGetChallenge::deserialize(apdu_buffer)?)),
            ApduInstructionType::CommandGetResponse => Ok(ApduInstructions::CommandGetResponse(CommandApduGetResponse::deserialize(apdu_buffer)?)),
            ApduInstructionType::ResponseGetResponse => Ok(ApduInstructions::ResponseGetResponse(ResponseApduGetResponse::deserialize(apdu_buffer)?)),
        }
    }
}

impl Display for ApduInstructions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApduInstructions::CommandSelect(command) => write!(f, "{}", command),
            ApduInstructions::ResponseSelect(response) => write!(f, "{}", response),
            ApduInstructions::CommandListDk(command) => write!(f, "{}", command),
            ApduInstructions::ResponseListDk(response) => write!(f, "{}", response),
            ApduInstructions::CommandAuth0(command) => write!(f, "{}", command),
            ApduInstructions::ResponseAuth0(response) => write!(f, "{}", response),
            ApduInstructions::CommandAuth1(command) => write!(f, "{:02X?}", command),
            ApduInstructions::ResponseAuth1(response) => write!(f, "{:02X?}", response),
            ApduInstructions::CommandGetDkCert(command) => write!(f, "{}", command),
            ApduInstructions::ResponseGetDkCert(response) => write!(f, "{}", response),
            ApduInstructions::CommandSharingRequest(command) => write!(f, "{}", command),
            ApduInstructions::ResponseSharingRequest(response) => write!(f, "{}", response),
            ApduInstructions::CommandRke(command) => write!(f, "{}", command),
            ApduInstructions::ResponseRke(response) => write!(f, "{}", response),
            ApduInstructions::CommandSign(command) => write!(f, "{}", command),
            ApduInstructions::ResponseSign(response) => write!(f, "{}", response),
            ApduInstructions::CommandDisableDk(command) => write!(f, "{}", command),
            ApduInstructions::ResponseDisableDk(response) => write!(f, "{}", response),
            ApduInstructions::CommandEnableDk(command) => write!(f, "{}", command),
            ApduInstructions::ResponseEnableDk(response) => write!(f, "{}", response),
            ApduInstructions::CommandGetChallenge(command) => write!(f, "{}", command),
            ApduInstructions::ResponseGetChallenge(response) => write!(f, "{}", response),
            ApduInstructions::CommandGetResponse(command) => write!(f, "{}", command),
            ApduInstructions::ResponseGetResponse(response) => write!(f, "{}", response),
        }
    }
}
