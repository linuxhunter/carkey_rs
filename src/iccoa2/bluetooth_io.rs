use crate::iccoa2::message::{Message, MessageStatus};
use crate::iccoa2::{message, Serde};
use super::errors::*;

#[allow(dead_code)]
pub fn handle_data_package_from_mobile(data_package: &[u8]) -> Result<Message> {
    let message = Message::deserialize(data_package)?;
    match message.get_message_status() {
        MessageStatus::NoApplicable => message::handle_request_from_mobile(&message),
        MessageStatus::Success => message::handle_response_from_mobile(&message),
        MessageStatus::BeyondMessageLength |
        MessageStatus::NoPermission |
        MessageStatus::SeInaccessible |
        MessageStatus::TlvParseError |
        MessageStatus::VehicleNotSupported |
        MessageStatus::InstructionVerificationFailed |
        MessageStatus::UnknownError |
        MessageStatus::Custom |
        MessageStatus::Reserved => {
            Err(format!("Unsupported Error Message Type: {}", message.get_message_status()).into())
        }
    }
}
