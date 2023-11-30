use log::info;
use crate::iccoa2::{ble, Serde};
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::ble::vehicle_status::{VehicleStatus, VehicleStatusRequest, VehicleStatusResponse};
use crate::iccoa2::errors::*;

#[derive(Debug, Default)]
pub struct BleVehicleStatus {
    random: Option<Vec<u8>>,
    request: Option<ble::vehicle_status::VehicleStatusRequest>,
    response: Option<ble::vehicle_status::VehicleStatusResponse>,
}

#[allow(dead_code)]
impl BleVehicleStatus {
    pub fn new() -> Self {
        BleVehicleStatus {
            random: None,
            request: None,
            response: None,
        }
    }
    pub fn get_random(&self) -> Option<&[u8]> {
        if let Some(ref random) = self.random {
            Some(random)
        } else {
            None
        }
    }
    pub fn set_random(&mut self, random: &[u8]) {
        self.random = Some(random.to_vec());
    }
    pub fn get_request(&self) -> Option<&ble::vehicle_status::VehicleStatusRequest> {
        if let Some(ref request) = self.request {
            Some(request)
        } else {
            None
        }
    }
    pub fn set_request(&mut self, request: ble::vehicle_status::VehicleStatusRequest) {
        self.request = Some(request);
    }
    pub fn get_response(&self) -> Option<&ble::vehicle_status::VehicleStatusResponse> {
        if let Some(ref response) = self.response {
            Some(response)
        } else {
            None
        }
    }
    pub fn set_response(&mut self, response: ble::vehicle_status::VehicleStatusResponse) {
        self.response = Some(response)
    }
    pub fn handle_vehicle_status_request(&self, request: &VehicleStatusRequest) {
        info!("[Vehicle Status Request]: ");
        info!("\tOption = {}", request.get_operation());
        info!("\tEntity = {}", request.get_entity_id());
    }
    pub fn create_vehicle_status_verification_response(&self) -> Result<Message> {
        if let Some(random) = self.get_random() {
            let subscribe_verification_response = ble::vehicle_status::SubscribeVerificationResponse::new(random);
            Ok(Message::new(
                MessageType::VehicleStatus,
                MessageStatus::Success,
                subscribe_verification_response.serialize()?.len() as u16,
                MessageData::VehicleStatus(VehicleStatus::SubscribeVerificationResponse(subscribe_verification_response))
            ))
        } else {
            Err(ErrorKind::BleVehicleStatusError("random number is NULL".to_string()).into())
        }
    }
    pub fn create_vehicle_status_response(&self, message_status: MessageStatus, response: VehicleStatusResponse) -> Result<Message> {
        Ok(Message::new(
            MessageType::VehicleStatus,
            message_status,
            response.serialize()?.len() as u16,
            MessageData::VehicleStatus(VehicleStatus::Response(response)),
        ))
    }
}
