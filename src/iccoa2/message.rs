use std::fmt::{Display, Formatter};
use crate::iccoa2::apdu::Apdu;
use crate::iccoa2::auth::Auth;
use crate::iccoa2::custom::CustomMessage;
use crate::iccoa2::measure::Measure;
use crate::iccoa2::rke::Rke;
use crate::iccoa2::vehicle_status::VehicleStatus;
use super::errors::*;

const MESSAGE_VERSION: u8 = 0x01;
const MESSAGE_LENGTH_MINIMUM: usize = 0x06;
const MESSAGE_TYPE_OFFSET: usize = 0x01;
const MESSAGE_STATUS_OFFSET: usize = 0x02;
const MESSAGE_DATA_LENGTH_OFFSET: usize = 0x04;
const MESSAGE_DATA_OFFSET: usize = 0x06;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MessageType {
    Apdu = 0x00,
    MeasureBroadcastRequest = 0x01,
    Rke = 0x02,
    VehicleStatus = 0x03,
    VehicleAppCustomMessage = 0x04,
    VehicleServerCustomMessage = 0x05,
    Auth = 0x06,
    Custom = 0x81,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::Apdu
    }
}

impl TryFrom<u8> for MessageType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(MessageType::Apdu),
            0x01 => Ok(MessageType::MeasureBroadcastRequest),
            0x02 => Ok(MessageType::Rke),
            0x03 => Ok(MessageType::VehicleStatus),
            0x04 => Ok(MessageType::VehicleAppCustomMessage),
            0x05 => Ok(MessageType::VehicleServerCustomMessage),
            0x06 => Ok(MessageType::Auth),
            0x81 => Ok(MessageType::Custom),
            _ => Err(format!("Unsupported message type")),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Apdu => 0x00,
            MessageType::MeasureBroadcastRequest => 0x01,
            MessageType::Rke => 0x02,
            MessageType::VehicleStatus => 0x03,
            MessageType::VehicleAppCustomMessage => 0x04,
            MessageType::VehicleServerCustomMessage => 0x05,
            MessageType::Auth => 0x06,
            MessageType::Custom => 0x81,
        }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Apdu => write!(f, "Apdu"),
            MessageType::MeasureBroadcastRequest => write!(f, "Measure request"),
            MessageType::Rke => write!(f, "Rke"),
            MessageType::VehicleStatus => write!(f, "Vehicle Status"),
            MessageType::VehicleAppCustomMessage => write!(f, "Get vehicle app custom message"),
            MessageType::VehicleServerCustomMessage => write!(f, "Get vehicle server custom message"),
            MessageType::Auth => write!(f, "Auth"),
            MessageType::Custom => write!(f, "Custom"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MessageStatus {
    NoApplicable = 0x0000,
    Success = 0x2000,
    BeyondMessageLength = 0x2001,
    NoPermission = 0x2002,
    SeInaccessible = 0x2003,
    TlvParseError = 0x2004,
    VehicleNotSupported = 0x2005,
    InstructionVerificationFailed = 0x2006,
    UnknownError = 0x5FFF,
    Custom = 0x6000,
    Reserved = 0x7FFF,
}

impl Default for MessageStatus {
    fn default() -> Self {
        MessageStatus::NoApplicable
    }
}

impl TryFrom<u16> for MessageStatus {
    type Error = String;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(MessageStatus::NoApplicable),
            0x2000 => Ok(MessageStatus::Success),
            0x2001 => Ok(MessageStatus::BeyondMessageLength),
            0x2002 => Ok(MessageStatus::NoPermission),
            0x2003 => Ok(MessageStatus::SeInaccessible),
            0x2004 => Ok(MessageStatus::TlvParseError),
            0x2005 => Ok(MessageStatus::VehicleNotSupported),
            0x2006 => Ok(MessageStatus::InstructionVerificationFailed),
            0x5FFF => Ok(MessageStatus::UnknownError),
            _ => {
                if value >= 0x6000 && value < 0x7FFF {
                    Ok(MessageStatus::Custom)
                } else if value >= 0x7FFF {
                    Ok(MessageStatus::Reserved)
                } else {
                    Err(format!("Unsupported message status"))
                }
            }
        }
    }
}

impl From<MessageStatus> for u16 {
    fn from(value: MessageStatus) -> Self {
        match value {
            MessageStatus::NoApplicable => 0x0000,
            MessageStatus::Success => 0x2000,
            MessageStatus::BeyondMessageLength => 0x2001,
            MessageStatus::NoPermission => 0x2002,
            MessageStatus::SeInaccessible => 0x2003,
            MessageStatus::TlvParseError => 0x2004,
            MessageStatus::VehicleNotSupported => 0x2005,
            MessageStatus::InstructionVerificationFailed => 0x2006,
            MessageStatus::UnknownError => 0x5FFF,
            MessageStatus::Custom => 0x6000,
            MessageStatus::Reserved => 0x7FFF,
        }
    }
}

impl Display for MessageStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageStatus::NoApplicable => write!(f, "No applicable"),
            MessageStatus::Success => write!(f, "Success"),
            MessageStatus::BeyondMessageLength => write!(f, "Beyond message length"),
            MessageStatus::NoPermission => write!(f, "No permission"),
            MessageStatus::SeInaccessible => write!(f, "SE unit inaccessible"),
            MessageStatus::TlvParseError => write!(f, "TLV parse error"),
            MessageStatus::VehicleNotSupported => write!(f, "Vehicle not supported"),
            MessageStatus::InstructionVerificationFailed => write!(f, "Instruction verfication failed"),
            MessageStatus::UnknownError => write!(f, "Unknown error"),
            MessageStatus::Custom => write!(f, "Custom message status"),
            MessageStatus::Reserved => write!(f, "Reserved message status"),
        }
    }
}

#[derive(Debug)]
pub enum MessageData {
    Apdu(Apdu),
    Measure(Measure),
    Rke(Rke),
    VehicleStatus(VehicleStatus),
    VehicleAppCustomMessage(CustomMessage),
    VehicleServerCustomMessage(CustomMessage),
    Auth(Auth),
    Custom(CustomMessage),
}

#[derive(Debug)]
pub struct Message {
    message_version: u8,
    message_type: MessageType,
    message_status: MessageStatus,
    message_data_length: u16,
    message_data: MessageData,
}

impl Message {
    pub fn new(message_type: MessageType, message_status: MessageStatus, message_data_length: u16, message_data: MessageData) -> Self {
        Message {
            message_version: MESSAGE_VERSION,
            message_type,
            message_status,
            message_data_length,
            message_data,
        }
    }
    pub fn set_message_type(&mut self, message_type: MessageType) {
        self.message_type = message_type;
    }
    pub fn get_message_type(&self) -> MessageType {
        self.message_type
    }
    pub fn set_message_status(&mut self, message_status: MessageStatus) {
        self.message_status = message_status;
    }
    pub fn get_message_status(&self) -> MessageStatus {
        self.message_status
    }
    pub fn set_message_data_length(&mut self, message_data_length: u16) {
        self.message_data_length = message_data_length;
    }
    pub fn get_message_data_length(&self) -> u16 {
        self.message_data_length
    }
    pub fn set_message_data(&mut self, message_data: MessageData) {
        self.message_data = message_data;
    }
    pub fn get_message_data(&self) -> &MessageData {
        &self.message_data
    }
    fn serialize(&self) -> crate::iccoa2::errors::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.push(self.message_version);
        buffer.push(u8::from(self.message_type));
        buffer.extend(u16::from(self.message_status).to_be_bytes());
        buffer.extend(self.message_data_length.to_be_bytes());
        let serialized_message_data = match &self.message_data {
            MessageData::Apdu(apdu) => apdu.serialize()?,
            MessageData::Measure(measure) => measure.serialize()?,
            MessageData::Rke(rke) => rke.serialize()?,
            MessageData::VehicleStatus(vehicle_status) => vehicle_status.serialize()?,
            MessageData::VehicleAppCustomMessage(custom_message) => custom_message.serialize()?,
            MessageData::VehicleServerCustomMessage(custom_message) => custom_message.serialize()?,
            MessageData::Auth(auth) => auth.serialize()?,
            MessageData::Custom(custom) => custom.serialize()?,
        };
        buffer.extend(serialized_message_data);
        Ok(buffer)
    }

    fn deserialize(data: &[u8]) -> crate::iccoa2::errors::Result<Self> {
        if data.len() < MESSAGE_LENGTH_MINIMUM {
            return Err(Error::from(ErrorKind::BleMessageError(format!("message length less than {}", MESSAGE_LENGTH_MINIMUM))));
        }
        let message_type = MessageType::try_from(data[MESSAGE_TYPE_OFFSET])
            .map_err(|e| ErrorKind::BleMessageError(format!("deserialize message type error: {:?}", e)))?;
        let origin_message_status = u16::from_be_bytes(
            (&data[MESSAGE_STATUS_OFFSET..MESSAGE_DATA_LENGTH_OFFSET])
                .try_into()
                .map_err(|e| ErrorKind::BleMessageError(format!("{:?}", e)))?);
        let message_status = MessageStatus::try_from(origin_message_status)
            .map_err(|e| ErrorKind::BleMessageError(format!("deserialize message status error: {:?}", e)))?;
        let message_data_length = u16::from_be_bytes(
            (&data[MESSAGE_DATA_LENGTH_OFFSET..MESSAGE_DATA_OFFSET])
                .try_into()
                .map_err(|e| ErrorKind::BleMessageError(format!("deserialize message data length error: {:?}", e)))?);
        let message_data = match message_type {
            MessageType::Apdu => MessageData::Apdu(Apdu::deserialize(&data[MESSAGE_DATA_OFFSET..])?),
            MessageType::MeasureBroadcastRequest => {
                MessageData::Measure(Measure::deserialize(&data[MESSAGE_DATA_OFFSET..])?)
            },
            MessageType::Rke => MessageData::Rke(Rke::deserialize(&data[MESSAGE_DATA_OFFSET..])?),
            MessageType::VehicleStatus => MessageData::VehicleStatus(VehicleStatus::deserialize(&data[MESSAGE_DATA_OFFSET..])?),
            MessageType::VehicleAppCustomMessage => MessageData::VehicleAppCustomMessage(CustomMessage::deserialize(&data[MESSAGE_DATA_OFFSET..])?),
            MessageType::VehicleServerCustomMessage => MessageData::VehicleServerCustomMessage(CustomMessage::deserialize(&data[MESSAGE_DATA_OFFSET..])?),
            MessageType::Auth => MessageData::Auth(Auth::deserialize(&data[MESSAGE_DATA_OFFSET..])?),
            MessageType::Custom => MessageData::Custom(CustomMessage::deserialize(&data[MESSAGE_DATA_OFFSET..])?),
        };
        Ok(Message::new(message_type, message_status, message_data_length, message_data))
    }
}