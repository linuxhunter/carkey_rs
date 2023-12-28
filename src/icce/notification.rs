use std::fmt::{Display, Formatter};
use super::{MessageType, objects};
use crate::icce::errors::*;

const NOTIFICATION_RESPONSE_STATUS_TAG: u8 = 0x00;
const NOTIFICATION_VEHICLE_EVENT_TAG: u8 = 0x01;
const NOTIFICATION_VEHICLE_ASYNC_RESPONSE_TAG: u8 = 0x02;
const NOTIFICATION_VEHICLE_STATE_INFO_TAG: u8 = 0x03;
const NOTIFICATION_VEHICLE_TO_APP_TAG: u8 = 0x01;
const NOTIFICATION_VEHICLE_TO_SERVER_TAG: u8 = 0x01;

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum NotificationCommandId {
    #[default]
    MobileStateToVehicleEvent = 0x01,
    VehicleStateToMobileEvent = 0x02,
    VehicleStateToAppEvent = 0x03,
    VehicleStateToServerEvent = 0x04,
    ServerStateToVehicleEvent = 0x05,
    Rfu = 0x06,
}

impl TryFrom<u8> for NotificationCommandId {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(NotificationCommandId::MobileStateToVehicleEvent),
            0x02 => Ok(NotificationCommandId::VehicleStateToMobileEvent),
            0x03 => Ok(NotificationCommandId::VehicleStateToAppEvent),
            0x04 => Ok(NotificationCommandId::VehicleStateToServerEvent),
            0x05 => Ok(NotificationCommandId::ServerStateToVehicleEvent),
            _ => Ok(NotificationCommandId::Rfu),
        }
    }
}

impl From<NotificationCommandId> for u8 {
    fn from(value: NotificationCommandId) -> Self {
        match value {
            NotificationCommandId::MobileStateToVehicleEvent => 0x01,
            NotificationCommandId::VehicleStateToMobileEvent => 0x02,
            NotificationCommandId::VehicleStateToAppEvent => 0x03,
            NotificationCommandId::VehicleStateToServerEvent => 0x04,
            NotificationCommandId::ServerStateToVehicleEvent => 0x05,
            NotificationCommandId::Rfu => 0x06,
        }
    }
}

impl Display for NotificationCommandId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationCommandId::MobileStateToVehicleEvent => write!(f, "Mobile State to Vehicle Event"),
            NotificationCommandId::VehicleStateToMobileEvent => write!(f, "Vehicle State to Mobile Event"),
            NotificationCommandId::VehicleStateToAppEvent => write!(f, "Vehicle State to App Event"),
            NotificationCommandId::VehicleStateToServerEvent => write!(f, "Vehicle State to Server Event"),
            NotificationCommandId::ServerStateToVehicleEvent => write!(f, "Server State to Vehicle Event"),
            NotificationCommandId::Rfu => write!(f, "RFU"),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum VehicleStateEvent {
    #[default]
    InstructionSuccess = 0x00,
    InstructionFailed = 0x01,
    Resend = 0x02,
    Locked = 0x03,
    Unlocked = 0x04,
    EngineStopped = 0x05,
    EngineStarted = 0x06,
    ClockReset = 0x07,
    BluetoothDisconnected = 0x08,
}

impl TryFrom<u8> for VehicleStateEvent {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(VehicleStateEvent::InstructionSuccess),
            0x01 => Ok(VehicleStateEvent::InstructionFailed),
            0x02 => Ok(VehicleStateEvent::Resend),
            0x03 => Ok(VehicleStateEvent::Locked),
            0x04 => Ok(VehicleStateEvent::Unlocked),
            0x05 => Ok(VehicleStateEvent::EngineStopped),
            0x06 => Ok(VehicleStateEvent::EngineStarted),
            0x07 => Ok(VehicleStateEvent::ClockReset),
            0x08 => Ok(VehicleStateEvent::BluetoothDisconnected),
            _ => Err(format!("Unsupported Vehicle State Event {}", value))
        }
    }
}

impl From<VehicleStateEvent> for u8 {
    fn from(value: VehicleStateEvent) -> Self {
        match value {
            VehicleStateEvent::InstructionSuccess => 0x00,
            VehicleStateEvent::InstructionFailed => 0x01,
            VehicleStateEvent::Resend => 0x02,
            VehicleStateEvent::Locked => 0x03,
            VehicleStateEvent::Unlocked => 0x04,
            VehicleStateEvent::EngineStopped => 0x05,
            VehicleStateEvent::EngineStarted => 0x06,
            VehicleStateEvent::ClockReset => 0x07,
            VehicleStateEvent::BluetoothDisconnected => 0x08,
        }
    }
}

impl Display for VehicleStateEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VehicleStateEvent::InstructionSuccess => write!(f, "Instruction Success"),
            VehicleStateEvent::InstructionFailed => write!(f, "Instruction Failed"),
            VehicleStateEvent::Resend => write!(f, "Resend"),
            VehicleStateEvent::Locked => write!(f, "Locked"),
            VehicleStateEvent::Unlocked => write!(f, "Unlocked"),
            VehicleStateEvent::EngineStopped => write!(f, "Engine Stopped"),
            VehicleStateEvent::EngineStarted => write!(f, "Engine Started"),
            VehicleStateEvent::ClockReset => write!(f, "Clock Reset"),
            VehicleStateEvent::BluetoothDisconnected => write!(f, "Bluetooth Disconnected"),
        }
    }
}

#[allow(dead_code)]
pub fn create_icce_mobile_state_event_request(mobile_event: u8) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let mobile_event_payload = objects::create_icce_body_payload(0x01, &[mobile_event]);
    let body = objects::create_icce_body(0x03, 0x01, &[mobile_event_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_state_event_response(status: u8) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(NOTIFICATION_RESPONSE_STATUS_TAG, &[status]);
    let body = objects::create_icce_body(
        u8::from(MessageType::Notification),
        u8::from(NotificationCommandId::MobileStateToVehicleEvent),
        &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_state_event_request(vehicle_event: VehicleStateEvent, async_result: &[u8], vehicle_state: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3+2+async_result.len() as u16 + 2+vehicle_state.len() as u16);
    icce.set_header(header);

    let vehicle_event_payload = objects::create_icce_body_payload(NOTIFICATION_VEHICLE_EVENT_TAG, &[u8::from(vehicle_event)]);
    let async_result_payload = objects::create_icce_body_payload(NOTIFICATION_VEHICLE_ASYNC_RESPONSE_TAG, async_result);
    let vehicle_state_payload = objects::create_icce_body_payload(NOTIFICATION_VEHICLE_STATE_INFO_TAG, vehicle_state);
    let body = objects::create_icce_body(
        u8::from(MessageType::Notification),
        u8::from(NotificationCommandId::VehicleStateToMobileEvent),
        &[vehicle_event_payload, async_result_payload, vehicle_state_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_vehicle_state_event_response(status: u8) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x02, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_app_event_request(data: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(NOTIFICATION_VEHICLE_TO_APP_TAG, data);
    let body = objects::create_icce_body(
        u8::from(MessageType::Notification),
        u8::from(NotificationCommandId::VehicleStateToAppEvent),
        &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_vehicle_to_app_event_response(status: u8) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x03, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_server_event_request(data: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(NOTIFICATION_VEHICLE_TO_SERVER_TAG, data);
    let body = objects::create_icce_body(
        u8::from(MessageType::Notification),
        u8::from(NotificationCommandId::VehicleStateToServerEvent),
        &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_vehicle_to_server_event_response(status: u8) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x04, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

#[allow(dead_code)]
pub fn create_icce_mobile_to_vehicle_event_request(data: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(0x01, data);
    let body = objects::create_icce_body(0x03, 0x05, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_to_vehicle_event_response(status: u8) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(NOTIFICATION_RESPONSE_STATUS_TAG, &[status]);
    let body = objects::create_icce_body(
        u8::from(MessageType::Notification),
        u8::from(NotificationCommandId::ServerStateToVehicleEvent),
        &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn handle_get_vehicle_state_event_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err(ErrorKind::NotificationError("Get Mobile State Event Status Error".to_string()).into());
            }
        } else {
            return Err(ErrorKind::NotificationError("RFU".to_string()).into());
        }
    }
    Ok(response)
}

pub fn handle_get_app_state_event_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err(ErrorKind::NotificationError("Get App State Event Status Error".to_string()).into());
            }
        } else {
            return Err(ErrorKind::NotificationError("RFU".to_string()).into());
        }
    }
    Ok(response)
}

pub fn handle_get_server_state_event_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err(ErrorKind::NotificationError("Get Server State Event Status Error".to_string()).into());
            }
        } else {
            return Err(ErrorKind::NotificationError("RFU".to_string()).into());
        }
    }
    Ok(response)
}

pub fn test_create_vehicle_instruction_success_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::InstructionSuccess;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_instruction_failed_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::InstructionFailed;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_resend_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::Resend;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_locked_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::Locked;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_unlocked_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::Unlocked;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_engine_stopped_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::EngineStopped;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_engine_started_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::EngineStarted;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_clock_reset_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::ClockReset;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_vehicle_bluetooth_disconnect_event_request() -> Vec<u8> {
    let vehicle_event = VehicleStateEvent::BluetoothDisconnected;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state).serialize()
}

pub fn test_create_app_event_request() -> Vec<u8> {
    let app_data = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let icce = create_icce_vehicle_to_app_event_request(&app_data);
    icce.serialize()
}

pub fn test_create_server_event_request() -> Vec<u8> {
    let server_data = vec![0xff, 0xee, 0xdd, 0xcc];
    let icce = create_icce_vehicle_to_server_event_request(&server_data);
    icce.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mobile_event_request() {
        let mobile_event = 0x01;
        let icce = create_icce_mobile_state_event_request(mobile_event);
        println!("Mobile Event Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_framework_to_vehicle_event_request() {
        let framework_to_vehicle_data = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_mobile_to_vehicle_event_request(&framework_to_vehicle_data);
        println!("Framework to Vehicle Event Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_get_vehicle_state_event_response() {
        let status = 0x00;
        let icce = create_icce_vehicle_state_event_response(status);
        println!("Get Vehicle State Event Response is {:02X?}", icce.serialize())
    }
    #[test]
    fn test_create_get_app_state_event_response() {
        let status = 0x00;
        let icce = create_icce_vehicle_to_app_event_response(status);
        println!("Get App State Event Response is {:02X?}", icce.serialize())
    }
    #[test]
    fn test_create_get_server_state_event_response() {
        let status = 0x00;
        let icce = create_icce_vehicle_to_server_event_response(status);
        println!("Get Server State Event Response is {:02X?}", icce.serialize())
    }
}
