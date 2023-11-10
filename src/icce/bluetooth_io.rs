use crate::icce::{command, notification};

use super::{objects, auth};

type Result<T> = std::result::Result<T, String>;

pub fn handle_icce_mobile_request(icce_object: &objects::Icce) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let body = icce_object.get_body();

    match body.get_message_id() {
        0x02 => {
            match body.get_command_id() {
                0x03 => {
                    //test for print decrypted RKE Commands
                    for payload in body.get_payloads() {
                        dbg!("RKE Command Type is {}", payload.get_payload_type());
                        dbg!("RKE Command Content Length is {}", payload.get_payload_length());
                        dbg!("RKE Comamnd Content is {:02X?}", payload.get_payload_value());
                    }
                    //test for reply RKE Command Response
                    let status = 0x00;
                    let rke_response = vec![0x04, 0x03, 0x02, 0x01];
                    let icce = command::create_icce_rke_control_response(status, &rke_response);
                    response.append(&mut icce.serialize());
                    dbg!("RKE Response is {:02X?}", response.clone());
                },
                0x04 => {
                    for payload in body.get_payloads() {
                        dbg!("RKE Challege Type is {}", payload.get_payload_type());
                        dbg!("RKE Challege Content Length is {}", payload.get_payload_length());
                        dbg!("RKE Challege Content is {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let rke_challege_random_numbers = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
                    let icce = command::create_icce_rke_challege_response(status, &rke_challege_random_numbers);
                    response.append(&mut icce.serialize());
                    dbg!("RKE Challege Response is {:02X?}", response.clone());
                },
                0x05 => {
                    for payload in body.get_payloads(){
                        dbg!("Get Vehicle Info Type is {}", payload.get_payload_type());
                        dbg!("Get Vehicle Info Length is {}", payload.get_payload_length());
                        dbg!("Get Vehicle Info Value is {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let vehicle_info = vec![0x01];
                    let icce = command::create_icce_get_vehicle_info_response(status, &vehicle_info);
                    response.append(&mut icce.serialize());
                    dbg!("Get Vehicle Info Response is {:02X?}", response.clone());
                },
                _ => {
                    return Err("RFU".to_string());
                }
            }
        },
        0x03 => {
            match body.get_command_id() {
                0x01 => {
                    for payload in body.get_payloads() {
                        dbg!("Mobile Event Type is {}", payload.get_payload_type());
                        dbg!("Mobile Event Length is {}", payload.get_payload_length());
                        dbg!("Mobild Event Value is {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let icce = notification::create_icce_mobile_state_event_response(status);
                    response.append(&mut icce.serialize());
                    dbg!("Mobile Event Response is {:02X?}", response.clone());
                },
                0x05 => {
                    for payload in body.get_payloads() {
                        dbg!("Framework to Vehicle Type is {}", payload.get_payload_type());
                        dbg!("Framework to Vehicle Length is {}", payload.get_payload_length());
                        dbg!("Framework to Vehicle Value is {:02X?}", payload.get_payload_value());
                    }
                    let status = 0x00;
                    let icce = notification::create_icce_mobile_to_vehicle_event_response(status);
                    response.append(&mut icce.serialize());
                    dbg!("Framework to Vehicle Response is {:02X?}", response.clone());
                },
                _ => {
                    return Err("RFU".to_string());
                }
            }
        },
        _ => {
            return Err("RFU".to_string());
        }
    }

    Ok(response)
}

pub fn handle_icce_mobile_response(icce_object: &objects::Icce) -> Result<Vec<u8>> {
    let _header = icce_object.get_header();
    let body = icce_object.get_body();
    match body.get_message_id() {
        0x01 => {
            match body.get_command_id() {
                0x01 => {
                    auth::handle_icce_auth_response(body)
                },
                _ => {
                    Err("RFU".to_string())
                }
            }
        },
        0x02 => {
            match body.get_command_id() {
                0x01 => {
                    command::handle_measure_response(body)
                },
                0x02 => {
                    command::handle_anti_relay_response(body)
                },
                0x06 => {
                    command::handle_mobile_info_response(body)
                },
                0x07 => {
                    command::handle_calbriate_time_response(body)
                },
                0x08 => {
                    command::handle_protocol_response(body)
                },
                _ => {
                    Err("RFU".to_string())
                }
            }
        },
        0x03 => {
            match body.get_command_id() {
                0x02 => {
                    notification::handle_get_vehicle_state_event_response(body)
                },
                0x03 => {
                    notification::handle_get_app_state_event_response(body)
                },
                0x04 => {
                    notification::handle_get_server_state_event_response(body)
                },
                _ => {
                    Err("RFU".to_string())
                }
            }
        },
        _ => {
            Err("RFU".to_string())
        }
    }
}


pub fn handle_data_package_from_mobile(icce_package: &[u8]) -> Result<objects::Icce> {
    if let Ok(mut icce_object) = objects::Icce::deserialize(icce_package) {
        dbg!("icce_object is {:?}", icce_object.clone());
        let icce_header_control = icce_object.get_header().get_control();
        if icce_header_control.is_first_frag() || icce_header_control.is_conti_frag() {
            objects::collect_icce_fragments(icce_object);
            return Err("fragment".to_string())
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
                    Err("not to send response".to_string())
                }
            } else {
                Err("handle icce mobile request error".to_string())
            }
        } else if let Ok(response_message) = handle_icce_mobile_response(&icce_object) {
                if !response_message.is_empty() {
                    let icce = objects::Icce::deserialize(&response_message)?;
                    Ok(icce)
                } else {
                    Err("not to send response".to_string())
                }
        } else {
            Err("handle icce mobile response error".to_string())
        }
    } else {
        Err("deserialize original icce data package error".to_string())
    }
}

