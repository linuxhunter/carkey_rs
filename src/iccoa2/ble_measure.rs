use log::info;
use crate::iccoa2::{ble, Serde};
use crate::iccoa2::ble::measure::Measure;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::errors::*;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct BleMeasure();

#[allow(dead_code)]
impl BleMeasure {
    pub fn new() -> Self {
        BleMeasure()
    }
    pub fn create_ble_measure_request(&self, request: ble::measure::MeasureRequest) -> Result<Message> {
        Ok(Message::new(
            MessageType::MeasureBroadcastRequest,
            MessageStatus::NoApplicable,
            request.serialize()?.len() as u16,
            MessageData::Measure(Measure::Request(request)),
        ))
    }
    pub fn handle_ble_measure_response(&mut self, response: &ble::measure::MeasureResponse) -> Result<()> {
        info!("[BLE Measure Response]: ");
        info!("\tResult = {}", response.get_response_action());
        info!("\tDuration = {}", response.get_response_duration());
        Ok(())
    }
}
