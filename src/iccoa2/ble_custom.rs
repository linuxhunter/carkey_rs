use log::info;
use crate::iccoa2::ble::custom::{CustomMessage, VehicleAppCustomRequest, VehicleAppCustomResponse, VehicleServerCustomRequest, VehicleServerCustomResponse};
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::Serde;
use crate::iccoa2::errors::*;

#[derive(Debug)]
pub struct BleCustom();

#[allow(dead_code)]
impl BleCustom {
    pub fn new() -> Self {
        BleCustom()
    }
    pub fn handle_app_custom_request(&self, request: &VehicleAppCustomRequest) {
        info!("[Vehicle App Custom Request]: ");
        info!("\tData = {:02X?}", request.get_custom_data());
    }
    pub fn create_app_custom_response(&self, response: &VehicleAppCustomResponse) -> Result<Message> {
        Ok(Message::new(
            MessageType::VehicleAppCustomMessage,
            MessageStatus::Success,
            response.serialize()?.len() as u16,
            MessageData::VehicleAppCustomMessage(CustomMessage::AppCustomResponse(response.clone()))
        ))
    }
    pub fn create_server_custom_request(&self, request: VehicleServerCustomRequest) -> Result<Message> {
        Ok(Message::new(
            MessageType::VehicleServerCustomMessage,
            MessageStatus::NoApplicable,
            request.serialize()?.len() as u16,
            MessageData::VehicleServerCustomMessage(CustomMessage::ServerCustomRequest(request))
        ))
    }
    pub fn handle_server_custom_response(&self, response: &VehicleServerCustomResponse) {
        info!("[Vehicle Server Custom Response]: ");
        info!("\tData = {:02X?}", response.get_custom_data());
    }
}
