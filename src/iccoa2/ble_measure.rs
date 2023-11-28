use log::info;
use crate::iccoa2::{ble, Serde};
use crate::iccoa2::ble::measure::Measure;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::errors::*;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct BleMeasure {
    request: ble::measure::MeasureRequest,
    response: Option<ble::measure::MeasureResponse>,
}

#[allow(dead_code)]
impl BleMeasure {
    pub fn new(
        request: ble::measure::MeasureRequest) -> Self {
        BleMeasure {
            request,
            response: None,
        }
    }
    pub fn get_request(&self) -> &ble::measure::MeasureRequest {
        &self.request
    }
    pub fn set_request(&mut self, request: ble::measure::MeasureRequest) {
        self.request = request;
    }
    pub fn get_response(&self) -> Option<&ble::measure::MeasureResponse> {
        if let Some(ref response) = self.response {
            Some(response)
        } else {
            None
        }
    }
    pub fn set_response(&mut self, response: ble::measure::MeasureResponse) {
        self.response = Some(response);
    }
    pub fn create_ble_measure_request(&self) -> Result<Message> {
        Ok(Message::new(
            MessageType::MeasureBroadcastRequest,
            MessageStatus::NoApplicable,
            self.get_request().serialize()?.len() as u16,
            MessageData::Measure(Measure::Request(self.get_request().clone())),
        ))
    }
    pub fn handle_ble_measure_response(&mut self, response: &ble::measure::MeasureResponse) -> Result<()> {
        info!("[BLE Measure Response]: ");
        info!("\tResult = {}", response.get_response_action());
        info!("\tDuration = {}", response.get_response_duration());
        self.set_response(response.clone());
        Ok(())
    }
}
