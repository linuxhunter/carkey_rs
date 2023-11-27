use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use log::info;
use crate::iccoa2::{create_tlv_with_constructed_value, create_tlv_with_primitive_value, get_tlv_primitive_value, Serde};
use crate::iccoa2::errors::*;

#[allow(dead_code)]
const MEASURE_TYPE_TAG: u8 = 0x50;
#[allow(dead_code)]
const MEASURE_ACTION_TAG: u8 = 0x51;
#[allow(dead_code)]
const MEASURE_DURATION_TAG: u8 = 0x52;
#[allow(dead_code)]
const MEASURE_REQUEST_TAG: u16 = 0x7F2E;
#[allow(dead_code)]
const MEASURE_RESPONSE_TAG: u16 = 0x7F30;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum MeasureType {
    BtRssi = 0x00,
    BtCS = 0x01,
    Uwb = 0x02,
}

impl TryFrom<u8> for MeasureType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(MeasureType::BtRssi),
            0x01 => Ok(MeasureType::BtCS),
            0x02 => Ok(MeasureType::Uwb),
            _ => Err("Unsupported measure type value".to_string()),
        }
    }
}

impl From<MeasureType> for u8 {
    fn from(value: MeasureType) -> Self {
        match value {
            MeasureType::BtRssi => 0x00,
            MeasureType::BtCS => 0x01,
            MeasureType::Uwb => 0x02,
        }
    }
}


impl Display for MeasureType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureType::BtRssi => write!(f, "Bluetooth RSSI"),
            MeasureType::BtCS => write!(f, "Bluetooth CS"),
            MeasureType::Uwb => write!(f, "UWB"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum MeasureAction {
    Start = 0x01,
    Stop = 0x02,
}

impl TryFrom<u8> for MeasureAction {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MeasureAction::Start),
            0x02 => Ok(MeasureAction::Stop),
            _ => Err("Unsupported measure action value".to_string()),
        }
    }
}

impl From<MeasureAction> for u8 {
    fn from(value: MeasureAction) -> Self {
        match value {
            MeasureAction::Start => 0x01,
            MeasureAction::Stop => 0x02,
        }
    }
}

impl Display for MeasureAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureAction::Start => write!(f, "Start"),
            MeasureAction::Stop => write!(f, "Stop"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum MeasureActionResult {
    MeasureRequestSuccess = 0x00,
    MeasureStop = 0x01,
    Unsupported = 0xFF,
}

impl TryFrom<u8> for MeasureActionResult {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(MeasureActionResult::MeasureRequestSuccess),
            0x01 => Ok(MeasureActionResult::MeasureStop),
            0xFF => Ok(MeasureActionResult::Unsupported),
            _ => Err(format!("Invalid Measure action result value: {}", value)),
        }
    }
}

impl From<MeasureActionResult> for u8 {
    fn from(value: MeasureActionResult) -> Self {
        match value {
            MeasureActionResult::MeasureRequestSuccess => 0x00,
            MeasureActionResult::MeasureStop => 0x01,
            MeasureActionResult::Unsupported => 0xFF,
        }
    }
}

impl Display for MeasureActionResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureActionResult::MeasureRequestSuccess => write!(f, "Measure Request Success"),
            MeasureActionResult::MeasureStop => write!(f, "Measure Stopped"),
            MeasureActionResult::Unsupported => write!(f, "Unsupported"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct MeasureDuration {
    duration: u8,
}

impl MeasureDuration {
    pub fn new(duration: u8) -> Self {
        MeasureDuration {
            duration,
        }
    }
    pub fn get_duration(&self) -> u8 {
        self.duration
    }
    pub fn set_duration(&mut self, duration: u8) {
        self.duration = duration;
    }
}

impl From<u8> for MeasureDuration {
    fn from(value: u8) -> Self {
        MeasureDuration::new(value)
    }
}

impl From<MeasureDuration> for u8 {
    fn from(value: MeasureDuration) -> Self {
        value.duration
    }
}

impl Display for MeasureDuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} seconds", self.duration)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct MeasureRequest {
    request_type: MeasureType,
    request_action: MeasureAction,
    request_duration: MeasureDuration,
}

#[allow(dead_code)]
impl MeasureRequest {
    pub fn new(request_type: MeasureType, request_action: MeasureAction, request_duration: MeasureDuration) -> Self {
        MeasureRequest {
            request_type,
            request_action,
            request_duration,
        }
    }
    pub fn get_request_type(&self) -> MeasureType {
        self.request_type
    }
    pub fn set_request_type(&mut self, request_type: MeasureType) {
        self.request_type = request_type;
    }
    pub fn get_request_action(&self) -> MeasureAction {
        self.request_action
    }
    pub fn set_request_action(&mut self, request_action: MeasureAction) {
        self.request_action = request_action;
    }
    pub fn get_request_duration(&self) -> MeasureDuration {
        self.request_duration
    }
    pub fn set_request_duration(&mut self, request_duration: MeasureDuration) {
        self.request_duration = request_duration;
    }
}

impl Serde for MeasureRequest {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let type_tlv = create_tlv_with_primitive_value(MEASURE_TYPE_TAG, &[self.get_request_type().into()])
            .map_err(|e| ErrorKind::MeasureError(format!("create measure request type tlv error: {:?}", e)))?;
        let action_tlv = create_tlv_with_primitive_value(MEASURE_ACTION_TAG, &[self.get_request_action().into()])
            .map_err(|e| ErrorKind::MeasureError(format!("create measure request action tlv error: {:?}", e)))?;
        let duration_tlv = create_tlv_with_primitive_value(MEASURE_DURATION_TAG, &[self.get_request_duration().into()])
            .map_err(|e| ErrorKind::MeasureError(format!("create measure request duration tlv error: {:?}", e)))?;
        let measure_tlv = create_tlv_with_constructed_value(MEASURE_REQUEST_TAG, &[type_tlv, action_tlv, duration_tlv])
            .map_err(|e| ErrorKind::MeasureError(format!("create measure tlv error: {:?}", e)))?;
        Ok(measure_tlv.to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let tlv_data = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize measure tlv error: {:?}", e)))?;
        if tlv_data.tag().to_bytes() != MEASURE_REQUEST_TAG.to_be_bytes() {
            return Err(ErrorKind::MeasureError("deserialize measure tlv tag error".to_string()).into());
        }
        if !tlv_data.value().is_constructed() {
            return Err(ErrorKind::MeasureError("deserialize measure tlv value type error".to_string()).into());
        }
        let type_tag = ber::Tag::try_from(MEASURE_TYPE_TAG)
            .map_err(|e| ErrorKind::MeasureError(format!("create measure request type tag error: {:?}", e)))?;
        let request_type = get_tlv_primitive_value(&tlv_data, &type_tag)
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize measure type error: {:?}", e)))?;
        let request_type = MeasureType::try_from(request_type[0])
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize message type invalid: {:?}", e)))?;
        let action_tag = ber::Tag::try_from(MEASURE_ACTION_TAG)
            .map_err(|e| ErrorKind::MeasureError(format!("create measure request action tag error: {:?}", e)))?;
        let request_action = get_tlv_primitive_value(&tlv_data, &action_tag)
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize measure action error: {:?}", e)))?;
        let request_action = MeasureAction::try_from(request_action[0])
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize message action invalid: {:?}", e)))?;
        let duration_tag = ber::Tag::try_from(MEASURE_DURATION_TAG)
            .map_err(|e| ErrorKind::MeasureError(format!("create measure request duration tag error: {:?}", e)))?;
        let request_duration = get_tlv_primitive_value(&tlv_data, &duration_tag)
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize measure duration error: {:?}", e)))?;
        let request_duration = MeasureDuration::try_from(request_duration[0])
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize message duration invalid: {:?}", e)))?;
        Ok(MeasureRequest::new(request_type, request_action, request_duration))
    }
}

impl Display for MeasureRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "request type: {}, request action: {}, request duration: {}",
        self.request_type, self.request_action, self.request_duration)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct MeasureResponse {
    response_action: MeasureActionResult,
    response_duration: MeasureDuration,
}

#[allow(dead_code)]
impl MeasureResponse {
    pub fn new(response_action: MeasureActionResult, response_duration: MeasureDuration) -> Self {
        MeasureResponse {
            response_action,
            response_duration
        }
    }
    pub fn get_response_action(&self) -> MeasureActionResult {
        self.response_action
    }
    pub fn set_response_action(&mut self, response_action: MeasureActionResult) {
        self.response_action = response_action;
    }
    pub fn get_response_duration(&self) -> MeasureDuration {
        self.response_duration
    }
    pub fn set_response_duration(&mut self, response_duration: MeasureDuration) {
        self.response_duration = response_duration;
    }
}

impl Serde for MeasureResponse {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let action_tlv = create_tlv_with_primitive_value(MEASURE_ACTION_TAG, &[self.get_response_action().into()])
            .map_err(|e| ErrorKind::MeasureError(format!("create measure response action tlv error: {:?}", e)))?;
        let duration_tlv = create_tlv_with_primitive_value(MEASURE_DURATION_TAG, &[self.get_response_duration().into()])
            .map_err(|e| ErrorKind::MeasureError(format!("create measure response duration tlv error: {:?}", e)))?;
        let measure_tlv = create_tlv_with_constructed_value(MEASURE_RESPONSE_TAG, &[action_tlv, duration_tlv])
            .map_err(|e| ErrorKind::MeasureError(format!("create measure tlv error: {:?}", e)))?;
        Ok(measure_tlv.to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let tlv_data = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize measure tlv error: {:?}", e)))?;
        if tlv_data.tag().to_bytes() != MEASURE_RESPONSE_TAG.to_be_bytes() {
            return Err(ErrorKind::MeasureError("deserialize measure tlv tag error".to_string()).into());
        }
        if !tlv_data.value().is_constructed() {
            return Err(ErrorKind::MeasureError("deserialize measure tlv value type error".to_string()).into());
        }
        let action_tag = ber::Tag::try_from(MEASURE_ACTION_TAG)
            .map_err(|e| ErrorKind::MeasureError(format!("create measure response action tag error: {:?}", e)))?;
        let response_action = get_tlv_primitive_value(&tlv_data, &action_tag)
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize measure action error: {:?}", e)))?;
        let response_action = MeasureActionResult::try_from(response_action[0])
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize message action invalid: {:?}", e)))?;
        let duration_tag = ber::Tag::try_from(MEASURE_DURATION_TAG)
            .map_err(|e| ErrorKind::MeasureError(format!("create measure response duration tag error: {:?}", e)))?;
        let response_duration = get_tlv_primitive_value(&tlv_data, &duration_tag)
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize measure duration error: {:?}", e)))?;
        let response_duration = MeasureDuration::try_from(response_duration[0])
            .map_err(|e| ErrorKind::MeasureError(format!("deserialize message duration invalid: {:?}", e)))?;
        Ok(MeasureResponse::new(response_action, response_duration))
    }
}

impl Display for MeasureResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "response action: {}, response duration: {}",
               self.response_action, self.response_duration)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum Measure {
    Request(MeasureRequest),
    Response(MeasureResponse),
}

impl Serde for Measure {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        match self {
            Measure::Request(request) => {
                request.serialize()
            },
            Measure::Response(response) => {
                response.serialize()
            }
        }
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let tag = u16::from_be_bytes(
            (&data[0..2])
                .try_into()
                .map_err(|e| ErrorKind::RkeError(format!("deserialize rke tag error: {}", e)))?
        );
        match tag {
            MEASURE_REQUEST_TAG => Ok(Measure::Request(MeasureRequest::deserialize(data)?)),
            MEASURE_RESPONSE_TAG => Ok(Measure::Response(MeasureResponse::deserialize(data)?)),
            _ => Err(ErrorKind::MeasureError("deserialize measure tag is invalid".to_string()).into())
        }
    }
}

impl Display for Measure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Measure::Request(request) => {
                write!(f, "{}", request)
            },
            Measure::Response(response) => {
                write!(f, "{}", response)
            }
        }
    }
}

#[allow(dead_code)]
pub fn create_measure_request(measure_type: MeasureType, measure_action: MeasureAction, measure_duration: MeasureDuration) -> MeasureRequest {
    MeasureRequest::new(
        measure_type,
        measure_action,
        measure_duration,
    )
}

pub fn handle_measure_response_from_mobile(response: &MeasureResponse) -> Result<()> {
    info!("[Measure]:");
    info!("\tResult: {}", response.get_response_action());
    info!("\tDuration: {}", response.get_response_duration());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_measure_request_tlv() {
        let request_type = MeasureType::BtRssi;
        let request_action = MeasureAction::Start;
        let request_duration = MeasureDuration::new(0x20);

        let mut request_tlv = MeasureRequest::new(request_type, request_action, request_duration);
        request_tlv.set_request_type(MeasureType::BtCS);
        request_tlv.set_request_action(MeasureAction::Stop);
        request_tlv.set_request_duration(MeasureDuration::new(0x30));
        assert_eq!(request_tlv, MeasureRequest::new(
            MeasureType::BtCS,
            MeasureAction::Stop,
            MeasureDuration::new(0x30),
        ));
    }
    #[test]
    fn test_create_measure_response_tlv() {
        let response_action = MeasureActionResult::MeasureRequestSuccess;
        let response_duration = MeasureDuration::new(0x20);

        let mut response_tlv = MeasureResponse::new(response_action, response_duration);
        response_tlv.set_response_action(MeasureActionResult::MeasureRequestSuccess);
        response_tlv.set_response_duration(MeasureDuration::new(0x30));
        assert_eq!(response_tlv, MeasureResponse::new(
            MeasureActionResult::MeasureRequestSuccess,
            MeasureDuration::new(0x30)
        ));
    }
    #[test]
    fn test_measure_request_tlv_serialize() {
        let request_type = MeasureType::BtRssi;
        let request_action = MeasureAction::Start;
        let request_duration = MeasureDuration::new(0x20);

        let request_tlv = MeasureRequest::new(request_type, request_action, request_duration);
        let serialized_request_tlv = request_tlv.serialize();
        assert!(serialized_request_tlv.is_ok());
        let serialized_request_tlv = serialized_request_tlv.unwrap();
        assert_eq!(serialized_request_tlv, vec![0x7F, 0x2E, 0x09, 0x50, 0x01, 0x00, 0x51, 0x01, 0x01, 0x52, 0x01, 0x20]);
    }
    #[test]
    fn test_measure_response_tlv_serialize() {
        let response_action = MeasureActionResult::MeasureStop;
        let response_duration = MeasureDuration::new(0x30);

        let response_tlv = MeasureResponse::new(response_action, response_duration);
        let serialized_response_tlv = response_tlv.serialize();
        assert!(serialized_response_tlv.is_ok());
        let serialized_response_tlv = serialized_response_tlv.unwrap();
        assert_eq!(serialized_response_tlv, vec![0x7F, 0x30, 0x06, 0x51, 0x01, 0x01, 0x52, 0x01, 0x30]);
    }
    #[test]
    fn test_measure_tlv_serialize() {
        let request_type = MeasureType::BtRssi;
        let request_action = MeasureAction::Start;
        let request_duration = MeasureDuration::new(0x20);

        let measure_tlv = Measure::Request(MeasureRequest::new(request_type, request_action, request_duration));
        let serialized_measure_tlv = measure_tlv.serialize();
        assert!(serialized_measure_tlv.is_ok());
        let serialized_measure_tlv =serialized_measure_tlv.unwrap();
        assert_eq!(serialized_measure_tlv, vec![0x7F, 0x2E, 0x09, 0x50, 0x01, 0x00, 0x51, 0x01, 0x01, 0x52, 0x01, 0x20]);
    }
    #[test]
    fn test_measure_request_tlv_deserialize() {
        let serialized_request_tlv = vec![0x7F, 0x2E, 0x09, 0x50, 0x01, 0x00, 0x51, 0x01, 0x01, 0x52, 0x01, 0x20];
        let request_tlv = MeasureRequest::deserialize(serialized_request_tlv.as_ref());
        assert!(request_tlv.is_ok());
        let request_tlv = request_tlv.unwrap();
        assert_eq!(request_tlv, MeasureRequest::new(
            MeasureType::BtRssi,
            MeasureAction::Start,
            MeasureDuration::new(0x20)
        ));
    }
    #[test]
    fn test_measure_response_tlv_deserialize() {
        let serialized_response_tlv = vec![0x7F, 0x30, 0x06, 0x51, 0x01, 0x01, 0x52, 0x01, 0x30];
        let response_tlv = MeasureResponse::deserialize(serialized_response_tlv.as_ref());
        assert!(response_tlv.is_ok());
        let response_tlv = response_tlv.unwrap();
        assert_eq!(response_tlv, MeasureResponse::new(
            MeasureActionResult::MeasureStop,
            MeasureDuration::new(0x30)
        ));
    }
    #[test]
    fn test_measure_tlv_deserialize() {
        let serialized_request_tlv = vec![0x7F, 0x2E, 0x09, 0x50, 0x01, 0x00, 0x51, 0x01, 0x01, 0x52, 0x01, 0x20];
        let measure_tlv = Measure::deserialize(serialized_request_tlv.as_ref());
        assert!(measure_tlv.is_ok());
        let measure_tlv = measure_tlv.unwrap();
        assert_eq!(measure_tlv, Measure::Request(MeasureRequest::new(
            MeasureType::BtRssi,
            MeasureAction::Start,
            MeasureDuration::new(0x20)
        )));


        let serialized_response_tlv = vec![0x7F, 0x30, 0x06, 0x51, 0x01, 0x01, 0x52, 0x01, 0x30];
        let measure_tlv = Measure::deserialize(serialized_response_tlv.as_ref());
        assert!(measure_tlv.is_ok());
        let measure_tlv = measure_tlv.unwrap();
        assert_eq!(measure_tlv, Measure::Response(MeasureResponse::new(
            MeasureActionResult::MeasureStop,
            MeasureDuration::new(0x30)
        )));
    }
    #[test]
    fn test_get_measure_tlv_type() {
        let request_type = MeasureType::BtRssi;
        let request_action = MeasureAction::Start;
        let request_duration = MeasureDuration::new(0x20);
        let mut request_tlv = MeasureRequest::new(request_type, request_action, request_duration);
        assert_eq!(request_tlv.get_request_type(), MeasureType::BtRssi);
        request_tlv.set_request_type(MeasureType::BtCS);
        assert_eq!(request_tlv.get_request_type(), MeasureType::BtCS);
        request_tlv.set_request_type(MeasureType::Uwb);
        assert_eq!(request_tlv.get_request_type(), MeasureType::Uwb);
    }
    #[test]
    fn test_get_measure_tlv_action() {
        let request_type = MeasureType::BtRssi;
        let request_action = MeasureAction::Start;
        let request_duration = MeasureDuration::new(0x20);
        let mut request_tlv = MeasureRequest::new(request_type, request_action, request_duration);
        assert_eq!(request_tlv.get_request_action(), MeasureAction::Start);
        request_tlv.set_request_action(MeasureAction::Stop);
        assert_eq!(request_tlv.get_request_action(), MeasureAction::Stop);

        let response_action = MeasureActionResult::MeasureRequestSuccess;
        let response_duration = MeasureDuration::new(0x30);
        let mut response_tlv = MeasureResponse::new(response_action, response_duration);
        assert_eq!(response_tlv.get_response_action(), MeasureActionResult::MeasureRequestSuccess);
        response_tlv.set_response_action(MeasureActionResult::MeasureStop);
        assert_eq!(response_tlv.get_response_action(), MeasureActionResult::MeasureStop);
    }
    #[test]
    fn test_get_measure_tlv_duration() {
        let request_type = MeasureType::BtRssi;
        let request_action = MeasureAction::Start;
        let request_duration = MeasureDuration::new(0x20);
        let mut request_tlv = MeasureRequest::new(request_type, request_action, request_duration);
        assert_eq!(request_tlv.get_request_duration(), MeasureDuration::new(0x20));
        request_tlv.set_request_duration(MeasureDuration::new(0x30));
        assert_eq!(request_tlv.get_request_duration(), MeasureDuration::new(0x30));

        let response_action = MeasureActionResult::MeasureRequestSuccess;
        let response_duration = MeasureDuration::new(0x20);
        let mut response_tlv = MeasureResponse::new(response_action, response_duration);
        assert_eq!(response_tlv.get_response_duration(), MeasureDuration::new(0x20));
        response_tlv.set_response_duration(MeasureDuration::new(0x30));
        assert_eq!(response_tlv.get_response_duration(), MeasureDuration::new(0x30));
    }
}