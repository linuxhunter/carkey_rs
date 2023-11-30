use log::info;
use crate::iccoa2::{ble, Serde};
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::ble::rke::{Rke, RkeResponse};
use crate::iccoa2::errors::*;

#[derive(Debug, Default)]
pub struct BleRke {
    random: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl BleRke {
    pub fn new() -> Self {
        BleRke {
            random: None,
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
    pub fn handle_rke_request(&self, request: &ble::rke::RkeRequest) {
        info!("[Rke Request]: ");
        info!("\tFunction = {}", request.get_rke_function());
        info!("\tAction = {}", request.get_rke_action());
    }
    pub fn handle_rke_continued_request(&self, request: &ble::rke::RkeContinuedRequest) {
        info!("[Rke Continued Request]: ");
        info!("\tRequest = {}", request.get_rke_request());
        info!("\tCustom = {:02X?}", request.get_rke_custom());
    }
    pub fn create_rke_verification_response(&self, message_status: MessageStatus) -> Result<Message> {
        if let Some(random) = self.get_random() {
            let rke_verification_response = ble::rke::RkeVerificationResponse::new(random);
            Ok(Message::new(
                MessageType::Rke,
                message_status,
                rke_verification_response.serialize()?.len() as u16,
                MessageData::Rke(Rke::VerificationResponse(rke_verification_response)),
            ))
        } else {
            Err(ErrorKind::BleRkeError("random number is NULL".to_string()).into())
        }
    }
    pub fn create_ble_rke_response(&self, message_status: MessageStatus, response: RkeResponse) -> Result<Message> {
        Ok(Message::new(
            MessageType::Rke,
            message_status,
            response.serialize()?.len() as u16,
            MessageData::Rke(Rke::Response(response)),
        ))
    }
}
