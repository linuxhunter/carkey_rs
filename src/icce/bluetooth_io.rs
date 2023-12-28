use log::{debug, info};
use rand::Rng;
use crate::icce::{command, MessageType, notification};
use crate::icce::command::InstructionCommandId;

use super::{objects, auth};
use crate::icce::errors::*;
use crate::icce::notification::NotificationCommandId;

const RKE_CHALLENGE_RANDOM_LENGTH: usize = 0x08;

fn generate_random(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random = Vec::with_capacity(length);
    for _ in 0..length {
        random.push(rng.gen::<u8>());
    }
    random
}

pub fn handle_icce_mobile_request(icce_object: &objects::Icce) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let body = icce_object.get_body();

    match MessageType::try_from(body.get_message_id()) {
        Ok(MessageType::Command) => {
            match InstructionCommandId::try_from(body.get_command_id()) {
                Ok(InstructionCommandId::Rke) => {
                    //test for print decrypted RKE Commands
                    for payload in body.get_payloads() {
                        info!("[RKE Command]");
                        info!("\tType: {}", payload.get_payload_type());
                        info!("\tContent: {:02X?}", payload.get_payload_value());
                    }
                    //test for reply RKE Command Response
                    let status = 0x00;
                    let rke_response = vec![0x04, 0x03, 0x02, 0x01];
                    let icce = command::create_icce_rke_control_response(status, &rke_response);
                    response.append(&mut icce.serialize());
                    debug!("RKE Response is {:02X?}", response.clone());
                },
                Ok(InstructionCommandId::RkeChallenge) => {
                    for payload in body.get_payloads() {
                        info!("[RKE Challenge]");
                        info!("\tType: {}", payload.get_payload_type());
                        info!("\tContent: {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let rke_challenge_random_numbers = generate_random(RKE_CHALLENGE_RANDOM_LENGTH);
                    let icce = command::create_icce_rke_challege_response(status, &rke_challenge_random_numbers);
                    response.append(&mut icce.serialize());
                    debug!("RKE Challenge Response is {:02X?}", response.clone());
                },
                Ok(InstructionCommandId::GetVehicleInfo) => {
                    for payload in body.get_payloads(){
                        info!("[Vehicle Info]");
                        info!("\tType: {}", payload.get_payload_type());
                        info!("\tValue: {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let vehicle_info = vec![0x01];
                    let icce = command::create_icce_get_vehicle_info_response(status, &vehicle_info);
                    response.append(&mut icce.serialize());
                    debug!("Get Vehicle Info Response is {:02X?}", response.clone());
                },
                _ => {
                    return Err(ErrorKind::BluetoothIOError("RFU".to_string()).into());
                }
            }
        },
        Ok(MessageType::Notification) => {
            match NotificationCommandId::try_from(body.get_command_id()) {
                Ok(NotificationCommandId::MobileStateToVehicleEvent) => {
                    for payload in body.get_payloads() {
                        info!("[Mobile Event Notification]");
                        info!("\tType: {}", payload.get_payload_type());
                        info!("\tValue: {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let icce = notification::create_icce_mobile_state_event_response(status);
                    response.append(&mut icce.serialize());
                    debug!("Mobile Event Response is {:02X?}", response.clone());
                },
                Ok(NotificationCommandId::ServerStateToVehicleEvent) => {
                    for payload in body.get_payloads() {
                        info!("[Server Event Notification]");
                        info!("\tType: {}", payload.get_payload_type());
                        info!("\tValue: {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let icce = notification::create_icce_mobile_to_vehicle_event_response(status);
                    response.append(&mut icce.serialize());
                    debug!("Framework to Vehicle Response is {:02X?}", response.clone());
                },
                _ => {
                    return Err(ErrorKind::BluetoothIOError("RFU".to_string()).into());
                }
            }
        },
        _ => {
            return Err(ErrorKind::BluetoothIOError("RFU".to_string()).into());
        }
    }

    Ok(response)
}

pub fn handle_icce_mobile_response(icce_object: &objects::Icce) -> Result<Vec<u8>> {
    let _header = icce_object.get_header();
    let body = icce_object.get_body();
    match MessageType::try_from(body.get_message_id()) {
        Ok(MessageType::Auth) => {
            match body.get_command_id() {
                0x01 => {
                    auth::handle_icce_auth_response(body)
                },
                _ => {
                    Err(ErrorKind::BluetoothIOError("RFU".to_string()).into())
                }
            }
        },
        Ok(MessageType::Command) => {
            match InstructionCommandId::try_from(body.get_command_id()) {
                Ok(InstructionCommandId::Measure) => {
                    command::handle_measure_response(body)
                },
                Ok(InstructionCommandId::AntiRelay) => {
                    command::handle_anti_relay_response(body)
                },
                Ok(InstructionCommandId::GetMobileInfo) => {
                    command::handle_mobile_info_response(body)
                },
                Ok(InstructionCommandId::Calibrate) => {
                    command::handle_calbriate_time_response(body)
                },
                Ok(InstructionCommandId::GetVehicleVersion) => {
                    command::handle_protocol_response(body)
                },
                _ => {
                    Err(ErrorKind::BluetoothIOError("RFU".to_string()).into())
                }
            }
        },
        Ok(MessageType::Notification) => {
            match NotificationCommandId::try_from(body.get_command_id()) {
                Ok(NotificationCommandId::VehicleStateToMobileEvent) => {
                    notification::handle_get_vehicle_state_event_response(body)
                },
                Ok(NotificationCommandId::VehicleStateToAppEvent) => {
                    notification::handle_get_app_state_event_response(body)
                },
                Ok(NotificationCommandId::VehicleStateToServerEvent) => {
                    notification::handle_get_server_state_event_response(body)
                },
                _ => {
                    Err(ErrorKind::BluetoothIOError("RFU".to_string()).into())
                }
            }
        },
        _ => {
            Err(ErrorKind::BluetoothIOError("RFU".to_string()).into())
        }
    }
}


pub fn handle_data_package_from_mobile(icce_package: &[u8]) -> Result<objects::Icce> {
    if let Ok(mut icce_object) = objects::Icce::deserialize(icce_package) {
        debug!("icce_object is {:?}", icce_object.clone());
        let icce_header_control = icce_object.get_header().get_control();
        if icce_header_control.is_first_frag() || icce_header_control.is_conti_frag() {
            objects::collect_icce_fragments(icce_object);
            return Err(ErrorKind::BluetoothIOError("fragment".to_string()).into());
        }
        if icce_header_control.is_last_frag() {
            objects::collect_icce_fragments(icce_object);
            icce_object = objects::reassemble_icce_fragments();
        }
        if icce_header_control.is_request() {
            if let Ok(response_message) = handle_icce_mobile_request(&icce_object) {
                if response_message.len() > 1 {
                    let icce = objects::Icce::deserialize(&response_message)?;
                    Ok(icce)
                } else {
                    Err(ErrorKind::BluetoothIOError("not to send response".to_string()).into())
                }
            } else {
                Err(ErrorKind::BluetoothIOError("handle icce mobile request error".to_string()).into())
            }
        } else if let Ok(response_message) = handle_icce_mobile_response(&icce_object) {
                if !response_message.is_empty() {
                    let icce = objects::Icce::deserialize(&response_message)?;
                    Ok(icce)
                } else {
                    Err(ErrorKind::BluetoothIOError("not to send response".to_string()).into())
                }
        } else {
            Err(ErrorKind::BluetoothIOError("handle icce mobile response error".to_string()).into())
        }
    } else {
        Err(ErrorKind::BluetoothIOError("deserialize original icce data package error".to_string()).into())
    }
}

