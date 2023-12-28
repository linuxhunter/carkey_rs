use std::fmt::{Display, Formatter};
use log::info;
use super::{MessageType, objects};
use crate::icce::errors::*;

const COMMAND_RESPONSE_STATUS_TAG: u8 = 0x00;
const MEASURE_REQUEST_TYPE_TAG: u8 = 0x01;
const ANTI_RELAY_REQUEST_MEASURE_TYPE_TAG: u8 = 0x01;
const ANTI_RELAY_REQUEST_VEHICLE_INFO_TAG: u8 = 0x02;
const RKE_RESPONSE_DATA_TAG: u8 = 0x01;
const RKE_CHALLENGE_RESPONSE_RANDOM_TAG: u8 = 0x01;
const GET_MOBILE_INFO_REQUEST_TYPE_TAG: u8 = 0x01;
const GET_MOBILE_INFO_RESPONSE_INFO_TAG: u8 = 0x01;
const GET_VERSION_REQUEST_VEHICLE_VERSION_TAG: u8 = 0x01;

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum InstructionCommandId {
    #[default]
    Measure = 0x01,
    AntiRelay = 0x02,
    Rke = 0x03,
    RkeChallenge = 0x04,
    GetVehicleInfo = 0x05,
    GetMobileInfo = 0x06,
    Calibrate = 0x07,
    GetVehicleVersion = 0x08,
}

impl TryFrom<u8> for InstructionCommandId {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(InstructionCommandId::Measure),
            0x02 => Ok(InstructionCommandId::AntiRelay),
            0x03 => Ok(InstructionCommandId::Rke),
            0x04 => Ok(InstructionCommandId::RkeChallenge),
            0x05 => Ok(InstructionCommandId::GetVehicleInfo),
            0x06 => Ok(InstructionCommandId::GetMobileInfo),
            0x07 => Ok(InstructionCommandId::Calibrate),
            0x08 => Ok(InstructionCommandId::GetVehicleVersion),
            _ => Err(format!("Unsupported Command ID {}", value))
        }
    }
}

impl From<InstructionCommandId> for u8 {
    fn from(value: InstructionCommandId) -> Self {
        match value {
            InstructionCommandId::Measure => 0x01,
            InstructionCommandId::AntiRelay => 0x02,
            InstructionCommandId::Rke => 0x03,
            InstructionCommandId::RkeChallenge => 0x04,
            InstructionCommandId::GetVehicleInfo => 0x05,
            InstructionCommandId::GetMobileInfo => 0x06,
            InstructionCommandId::Calibrate => 0x07,
            InstructionCommandId::GetVehicleVersion => 0x08,
        }
    }
}

impl Display for InstructionCommandId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InstructionCommandId::Measure => write!(f, "Measure"),
            InstructionCommandId::AntiRelay => write!(f, "Anti-Relay"),
            InstructionCommandId::Rke => write!(f, "RKE"),
            InstructionCommandId::RkeChallenge => write!(f, "RKE Challenge"),
            InstructionCommandId::GetVehicleInfo => write!(f, "Get Vehicle Info"),
            InstructionCommandId::GetMobileInfo => write!(f, "Get Mobile Info"),
            InstructionCommandId::Calibrate => write!(f, "Calibrate"),
            InstructionCommandId::GetVehicleVersion => write!(f, "Get Vehicle Version"),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum MeasureType {
    #[default]
    Rssi = 0x01,
    Uwb = 0x02,
    Hadm = 0x03,
    Rfu = 0x04,
}

impl TryFrom<u8> for MeasureType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MeasureType::Rssi),
            0x02 => Ok(MeasureType::Uwb),
            0x03 => Ok(MeasureType::Hadm),
            _ => Ok(MeasureType::Rfu),
        }
    }
}

impl From<MeasureType> for u8 {
    fn from(value: MeasureType) -> Self {
        match value {
            MeasureType::Rssi => 0x01,
            MeasureType::Uwb => 0x02,
            MeasureType::Hadm => 0x03,
            MeasureType::Rfu => 0x04,
        }
    }
}

impl Display for MeasureType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureType::Rssi => write!(f, "RSSI"),
            MeasureType::Uwb => write!(f, "UWB"),
            MeasureType::Hadm => write!(f, "HADM"),
            MeasureType::Rfu => write!(f, "RFU"),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum MobileInfoType {
    #[default]
    CalibrateData = 0x01,
    AntiRelayResult = 0x02,
    CustomData = 0x03,
    Rfu = 0x04,
}

impl TryFrom<u8> for MobileInfoType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MobileInfoType::CalibrateData),
            0x02 => Ok(MobileInfoType::AntiRelayResult),
            0x03 => Ok(MobileInfoType::CustomData),
            _ => Ok(MobileInfoType::Rfu),
        }
    }
}

impl From<MobileInfoType> for u8 {
    fn from(value: MobileInfoType) -> Self {
        match value {
            MobileInfoType::CalibrateData => 0x01,
            MobileInfoType::AntiRelayResult => 0x02,
            MobileInfoType::CustomData => 0x03,
            MobileInfoType::Rfu => 0x04,
        }
    }
}

impl Display for MobileInfoType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MobileInfoType::CalibrateData => write!(f, "Calibrate Data"),
            MobileInfoType::AntiRelayResult => write!(f, "Anti-Relay Result"),
            MobileInfoType::CustomData => write!(f, "Custom Data"),
            MobileInfoType::Rfu => write!(f, "RFU"),
        }
    }
}

pub fn create_icce_measure_request(measure_type: MeasureType) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let measure_payload = objects::create_icce_body_payload(MEASURE_REQUEST_TYPE_TAG, &[u8::from(measure_type)]);
    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::Measure),
        &[measure_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_measure_response(status: u8, timeout: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+timeout.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let timeout_payload = objects::create_icce_body_payload(0x01, timeout);
    let body = objects::create_icce_body(0x02, 0x01, &[status_payload, timeout_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_anti_relay_request(measure_type: MeasureType, vehicle_info: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3+2+vehicle_info.len() as u16);
    icce.set_header(header);

    let measure_payload = objects::create_icce_body_payload(ANTI_RELAY_REQUEST_MEASURE_TYPE_TAG, &[u8::from(measure_type)]);
    let vehicle_info_payload = objects::create_icce_body_payload(ANTI_RELAY_REQUEST_VEHICLE_INFO_TAG, vehicle_info);
    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::AntiRelay),
        &[measure_payload, vehicle_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_anti_relay_response(status: u8, check_result: u8, device_info: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+3+2+device_info.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let check_result_payload = objects::create_icce_body_payload(0x01, &[check_result]);
    let device_info_payload = objects::create_icce_body_payload(0x02, device_info);
    let body = objects::create_icce_body(0x02, 0x02, &[status_payload, check_result_payload, device_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_rke_control_request(rke_type: u8, rke_cmd: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, true, false, 0, 0, 4+2+rke_cmd.len() as u16);
    icce.set_header(header);

    let rke_cmd_payload = objects::create_icce_body_payload(rke_type, rke_cmd);
    let body = objects::create_icce_body(0x02, 0x03, &[rke_cmd_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_control_response(status: u8, rke_result: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, true, false, 0, 0, 4+3+2+rke_result.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(COMMAND_RESPONSE_STATUS_TAG, &[status]);
    let rke_result_payload = objects::create_icce_body_payload(RKE_RESPONSE_DATA_TAG, rke_result);
    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::Rke),
        &[status_payload, rke_result_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_rke_challege_request(rke_type: u8) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let rke_type_payload = objects::create_icce_body_payload(0x01, &[rke_type]);
    let body = objects::create_icce_body(0x02, 0x04, &[rke_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_challege_response(status: u8, random_value: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+random_value.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(COMMAND_RESPONSE_STATUS_TAG, &[status]);
    let random_value_payload = objects::create_icce_body_payload(RKE_CHALLENGE_RESPONSE_RANDOM_TAG, random_value);
    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::RkeChallenge),
        &[status_payload, random_value_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_get_vehicle_info_request(request_type: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let request_type_payload = objects::create_icce_body_payload(0x01, request_type);
    let body = objects::create_icce_body(0x02, 0x05, &[request_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_vehicle_info_response(status: u8, vehicle_info: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+vehicle_info.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(COMMAND_RESPONSE_STATUS_TAG, &[status]);
    let vehicle_info_payload = objects::create_icce_body_payload(GET_MOBILE_INFO_RESPONSE_INFO_TAG, vehicle_info);
    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::GetMobileInfo),
        &[status_payload, vehicle_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_mobile_info_request(request_type: MobileInfoType) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let request_type_payload = objects::create_icce_body_payload(GET_MOBILE_INFO_REQUEST_TYPE_TAG, &[u8::from(request_type)]);
    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::GetMobileInfo),
        &[request_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_get_mobile_info_response(status: u8, mobile_info: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+mobile_info.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let mobile_info_payload = objects::create_icce_body_payload(0x01, mobile_info);
    let body = objects::create_icce_body(0x02, 0x06, &[status_payload, mobile_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_calibrate_clock_request() -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4);
    icce.set_header(header);

    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::Calibrate),
        &[]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_calibrate_clock_response(status: u8, clock: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+clock.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let clock_payload = objects::create_icce_body_payload(0x01, clock);
    let body = objects::create_icce_body(0x02, 0x07, &[status_payload, clock_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_protocol_request(protocol: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+protocol.len() as u16);
    icce.set_header(header);

    let protocol_payload = objects::create_icce_body_payload(GET_VERSION_REQUEST_VEHICLE_VERSION_TAG, protocol);
    let body = objects::create_icce_body(
        u8::from(MessageType::Command),
        u8::from(InstructionCommandId::GetVehicleVersion),
        &[protocol_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_get_protocol_response(status: u8, protocol: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+protocol.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let protocol_payload = objects::create_icce_body_payload(0x01, protocol);
    let body = objects::create_icce_body(0x02, 0x08, &[status_payload, protocol_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn handle_measure_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err(ErrorKind::CommandError("Measure Response Status Error".to_string()).into());
                }
            },
            0x01 => {
                info!("[Measure Response]");
                info!("\tLast Time(ms): {:02X?}", payload.get_payload_value());
            },
            _ => {
                return Err(ErrorKind::CommandError("RFU".to_string()).into());
            }
        }
    }
    Ok(response)
}

pub fn handle_anti_relay_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err(ErrorKind::CommandError("Anti-Relay Response Status Error".to_string()).into());
                }
            },
            0x01 => {
                info!("[Anti-Relay Response]");
                info!("\tResult: {:02X?}", payload.get_payload_value());
            },
            0x02 => {
                info!("\tDevice Info: {:02X?}", payload.get_payload_value());
            },
            _ => {
                return Err(ErrorKind::CommandError("RFU".to_string()).into());
            }
        }
    }
    Ok(response)
}

pub fn handle_mobile_info_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err(ErrorKind::CommandError("Get Mobile Info Response Status Error".to_string()).into());
                }
            },
            0x01 => {
                info!("[Mobile Info Response]");
                info!("\tInfo: {:02X?}", payload.get_payload_value());
            },
            _ => {
                return Err(ErrorKind::CommandError("RFU".to_string()).into());
            }
        }
    }
    Ok(response)
}

pub fn handle_calbriate_time_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err(ErrorKind::CommandError("Calbriate Time Response Status Error".to_string()).into());
                }
            },
            0x01 => {
                info!("[Calibrate Response]");
                info!("\tTime: {:02X?}", payload.get_payload_value());
            },
            _ => {
                return Err(ErrorKind::CommandError("RFU".to_string()).into());
            }
        }
    }
    Ok(response)
}

pub fn handle_protocol_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err(ErrorKind::CommandError("Protocol Response Status Error".to_string()).into());
                }
            },
            0x01 => {
                info!("[Protocol Version Response]");
                info!("\tVersion: {:02X?}", payload.get_payload_value());
            },
            _ => {
                return Err(ErrorKind::CommandError("RFU".to_string()).into());
            }
        }
    }
    Ok(response)
}

pub fn test_create_rssi_measure_request() -> Vec<u8> {
    create_icce_measure_request(MeasureType::Rssi).serialize()
}

pub fn test_create_uwb_measure_request() -> Vec<u8> {
    create_icce_measure_request(MeasureType::Uwb).serialize()
}

pub fn test_create_hadm_measure_request() -> Vec<u8> {
    create_icce_measure_request(MeasureType::Hadm).serialize()
}

pub fn test_create_rssi_anti_relay_request() -> Vec<u8> {
    let vehicle_info = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    create_icce_anti_relay_request(MeasureType::Rssi, &vehicle_info).serialize()
}

pub fn test_create_uwb_anti_relay_request() -> Vec<u8> {
    let vehicle_info = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    create_icce_anti_relay_request(MeasureType::Uwb, &vehicle_info).serialize()
}

pub fn test_create_hadm_anti_replay_request() -> Vec<u8> {
    let vehicle_info = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    create_icce_anti_relay_request(MeasureType::Hadm, &vehicle_info).serialize()
}

pub fn test_create_get_calibrate_data_mobile_info_request() -> Vec<u8> {
    create_icce_get_mobile_info_request(MobileInfoType::CalibrateData).serialize()
}

pub fn test_create_get_anti_relay_result_mobile_info_request() -> Vec<u8> {
    create_icce_get_mobile_info_request(MobileInfoType::AntiRelayResult).serialize()
}

pub fn test_create_get_custom_data_mobile_info_request() -> Vec<u8> {
    create_icce_get_mobile_info_request(MobileInfoType::CustomData).serialize()
}

pub fn test_create_calbriate_time_request() -> Vec<u8> {
    create_icce_calibrate_clock_request().serialize()
}

pub fn test_create_protocol_request() -> Vec<u8> {
    let vehicle_protocol = vec![0x01, 0x02, 0x03, 0x04];
    let icce = create_icce_get_protocol_request(&vehicle_protocol);
    icce.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rke_control_request() {
        let rke_type = 0x01;
        let rke_cmd = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

        let icce = create_icce_rke_control_request(rke_type, &rke_cmd);
        let _origin_icce = objects::Icce::deserialize(&icce.serialize()).unwrap();
    }
    #[test]
    fn test_create_get_vehicle_info_request() {
        let get_vehicle_info_type = vec![0x01];
        let icce = create_icce_get_vehicle_info_request(&get_vehicle_info_type);
        println!("Get Vehicle Info Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_rke_control_response() {
        let status = 0x00;
        let rke_response= vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

        let _icce = create_icce_rke_control_response(status, &rke_response);
    }
    #[test]
    fn test_create_rke_challege_request() {
        let rke_type = 0x01;
        let icce = create_icce_rke_challege_request(rke_type);
        println!("RKE Challege Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_measure_response() {
        let status = 0x00;
        let measure_times = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_measure_response(status, &measure_times);
        println!("Measure Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_anti_relay_response() {
        let status = 0x00;
        let check_result = 0x01;
        let device_info = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_anti_relay_response(status, check_result, &device_info);
        println!("Anti-Relay Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_mobile_info_response() {
        let status = 0x00;
        let mobile_info = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_get_mobile_info_response(status, &mobile_info);
        println!("Mobile Info Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_calbriate_time_response() {
        let status = 0x00;
        let calbriate_time = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_calibrate_clock_response(status, &calbriate_time);
        println!("Calbriate Time Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_protocol_response() {
        let status = 0x00;
        let protocol = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_get_protocol_response(status, &protocol);
        println!("Protocol Response is {:02X?}", icce.serialize());
    }
}
