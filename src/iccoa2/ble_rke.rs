use log::info;
use crate::iccoa2::{ble, Serde};
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::ble::rke::Rke;
use crate::iccoa2::errors::*;

#[derive(Debug, Default)]
pub struct BleRke {
    random: Option<Vec<u8>>,
    request: Option<ble::rke::RkeRequest>,
    continued_request: Option<ble::rke::RkeContinuedRequest>,
    response: Option<ble::rke::RkeResponse>,
}

#[allow(dead_code)]
impl BleRke {
    pub fn new() -> Self {
        BleRke {
            random: None,
            request: None,
            continued_request: None,
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
    pub fn get_request(&self) -> Option<&ble::rke::RkeRequest> {
        if let Some(ref request) = self.request {
            Some(request)
        } else {
            None
        }
    }
    pub fn set_request(&mut self, request: ble::rke::RkeRequest) {
        self.request = Some(request);
    }
    pub fn get_continued_request(&self) -> Option<&ble::rke::RkeContinuedRequest> {
        if let Some(ref request) = self.continued_request {
            Some(request)
        } else {
            None
        }
    }
    pub fn set_continued_request(&mut self, request: ble::rke::RkeContinuedRequest) {
        self.continued_request = Some(request);
    }
    pub fn get_response(&self) -> Option<&ble::rke::RkeResponse> {
        if let Some(ref response) = self.response {
            Some(response)
        } else {
            None
        }
    }
    pub fn set_response(&mut self, response: ble::rke::RkeResponse) {
        self.response = Some(response);
    }
    pub fn handle_rke_continued_request(&mut self, request: &ble::rke::RkeContinuedRequest) {
        info!("[Rke Continued Request]: ");
        info!("\tRequest = {}", request.get_rke_request());
        info!("\tCustom = {:02X?}", request.get_rke_custom());
        self.set_continued_request(request.clone());
    }
    pub fn create_rke_verification_response(&self) -> Result<Message> {
        if let Some(random) = self.get_random() {
            let rke_verification_response = ble::rke::RkeVerificationResponse::new(random);
            Ok(Message::new(
                MessageType::Rke,
                MessageStatus::Success,
                rke_verification_response.serialize()?.len() as u16,
                MessageData::Rke(Rke::VerificationResponse(rke_verification_response)),
            ))
        } else {
            Err(ErrorKind::BleRkeError("random number is NULL".to_string()).into())
        }
    }
    pub fn create_ble_rke_response(&self) -> Result<Message> {
        if let Some(response) = self.get_response() {
            Ok(Message::new(
                MessageType::Rke,
                MessageStatus::Success,
                response.serialize()?.len() as u16,
                MessageData::Rke(Rke::Response(*response)),
            ))
        } else {
            Err(ErrorKind::BleRkeError("rke response is NULL".to_string()).into())
        }
    }
}
