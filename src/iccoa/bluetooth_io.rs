use std::io::Write;

use openssl::pkey::PKey;

use super::command::ranging::create_iccoa_ranging_request;
use super::{errors::*, objects, utils};
use super::objects::{ICCOA, PacketType, MessageType};
use super::status::{StatusTag, StatusBuilder, Status};
use super::pairing;
use super::{TLVPayloadBuilder, TLVPayload};
use super::auth;
use super::command::rke::{create_iccoa_rke_response, RKECommandRequest};

pub fn create_iccoa_pairing_data_request_package() -> Result<Vec<u8>> {
    let transaction_id = 0x0000;
    let p_b = pairing::calculate_pB();
    let p_b_payload = TLVPayloadBuilder::new().set_tag(0x51).set_value(&p_b).build();
    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let salt_payload = TLVPayloadBuilder::new().set_tag(0xC0).set_value(&salt).build();
    let nscrypt = [0x01, 0x02, 0x03, 0x04];
    let nscrypt_payload = TLVPayloadBuilder::new().set_tag(0xC1).set_value(&nscrypt).build();
    let r = [0x01, 0x02];
    let r_payload = TLVPayloadBuilder::new().set_tag(0xC2).set_value(&r).build();
    let p = [0x02, 0x01];
    let p_payload = TLVPayloadBuilder::new().set_tag(0xC3).set_value(&p).build();
    let iccoa = pairing::create_iccoa_pairing_data_request(
        transaction_id,
        &[p_b_payload, salt_payload, nscrypt_payload, r_payload, p_payload])?;
    Ok(iccoa.serialize())
}

pub fn create_iccoa_standard_auth_pubkey_exchange_request_package() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let mut auth_sign_object = utils::get_auth_sign_object();
    auth_sign_object.create_vehicle_temp_keypair("rsa")?;
    let vehicle_temp_pubkey = auth_sign_object.get_vehicle_temp_public_key_pem()?;
    let vehicle_id = auth_sign_object.get_vehicle_id()?;
    utils::set_auth_sign_object(&auth_sign_object);
    let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
    let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
    let iccoa = auth::create_iccoa_standard_auth_pubkey_exchange_request(
        transaction_id,
        &[vehicle_temp_pubkey_payload, vehicle_id_payload])?;
    Ok(iccoa)
}

pub fn create_iccoa_fast_auth_pubkey_exchange_request_package() -> Result<ICCOA> {
    /*
    let transaction_id = 0x0000;
    let vehicle_temp_rsa = utils::create_temp_rsa().unwrap();
    let keypair = PKey::from_rsa(vehicle_temp_rsa).unwrap();
    let vehicle_temp_pubkey = keypair.public_key_to_pem().unwrap();
    let vehicle_id = utils::get_vehicle_id();
    let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
    let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
    let iccoa = auth::create_iccoa_fast_auth_pubkey_exchange_request(
        transaction_id,
        &[vehicle_temp_pubkey_payload, vehicle_id_payload])?;
    Ok(iccoa)
    */
    Ok(ICCOA::new())
}

pub fn create_iccoa_ranging_request_package() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let ranging_type = 0x01;
    let ranging_type_payload = TLVPayloadBuilder::new().set_tag(0x01).set_value(&[ranging_type]).build();
    let iccoa = create_iccoa_ranging_request(transaction_id, 0x02, &[ranging_type_payload])?;
    Ok(iccoa)
}

pub fn handle_iccoa_pairing_p_a_payload(iccoa: &ICCOA) -> Status {
    //handle pA
    StatusBuilder::new().success().build()
}

pub fn handle_iccoa_pairing_c_a_payload(iccoa: &ICCOA) -> Status {
    //handle cA
    StatusBuilder::new().success().build()
}

pub fn handle_iccoa_pairing_read_response_payload(iccoa: &ICCOA) -> Result<()> {
    //handle read response payload
    let message_data = iccoa.get_body().get_message_data();
    if message_data.get_status().get_tag() == StatusTag::SUCCESS {
        let cert_payload = TLVPayload::deserialize(&message_data.get_value()).unwrap();
        match cert_payload.get_tag() {
            0x01 => {
                let mut file = std::fs::File::create("/etc/certs/mobile_server_ca.crt")
                    .map_err(|_| ErrorKind::ICCOAPairingError("create mobile server ca cert file error".to_string()))
                    .unwrap();
                file.write_all(&cert_payload.value)
                    .map_err(|_| ErrorKind::ICCOAPairingError("write cert data to mobile server ca cert file error".to_string()))
                    .unwrap();
            },
            0x02 => {
                let mut file = std::fs::File::create("/etc/certs/mobile_tee_ca.crt")
                    .map_err(|_| ErrorKind::ICCOAPairingError("create mobile tee ca cert file error".to_string()))
                    .unwrap();
                file.write_all(&cert_payload.value)
                    .map_err(|_| ErrorKind::ICCOAPairingError("write cert data to moile tee ca cert file error".to_string()))
                    .unwrap();
            },
            0x03 => {
                let mut file = std::fs::File::create("/etc/certs/carkey_public.crt")
                    .map_err(|_| ErrorKind::ICCOAPairingError("create carkey public cert file error".to_string()))
                    .unwrap();
                file.write_all(&cert_payload.value)
                    .map_err(|_| ErrorKind::ICCOAPairingError("write cert data to carkey public cert file error".to_string()))
                    .unwrap();
            },
            _ => {},
        }
        Ok(())
    } else {
        return Err(ErrorKind::ICCOAPairingError("pairing read response error".to_string()).into());
    }
}

pub fn handle_iccoa_standard_auth_data_exchange_response_payload(iccoa: &ICCOA) -> Result<Vec<u8>> {
    //handle standard auth data exchange payload
    let message_data = iccoa.get_body().get_message_data();
    if message_data.status != StatusBuilder::new().success().build() {
        return Err(ErrorKind::ICCOAAuthError("standard auth data exchnage response error".to_string()).into());
    }
    if message_data.get_tag() != 0x01 {
        return Err(ErrorKind::ICCOAAuthError("standard auth data exchange response tag error".to_string()).into());
    }
    let total_payload = message_data.get_value();
    let total_length = total_payload.len() as usize;
    let mut index = 0x00;
    let mut carkey_temp_pubkey = Vec::new();
    let mut carkey_id = Vec::new();
    while index < total_length {
        let payload = TLVPayload::deserialize(&total_payload[index..]).unwrap();
        if payload.get_tag() == 0x84 {
            carkey_temp_pubkey.append(&mut payload.value.to_vec());
        } else if payload.get_tag() == 0x89 {
            carkey_id.append(&mut payload.value.to_vec());
        }
        let payload_length = payload.value.len();
        if payload_length < 128 {
            index += 1+1+payload_length;
        } else if payload_length < 256 {
            index += 1+2+payload_length;
        } else {
            index += 1+3+payload_length;
        }
    }
    let mut auth_sign_object = utils::get_auth_sign_object();
    auth_sign_object.set_mobile_temp_public_key_pem(&carkey_temp_pubkey)?;
    auth_sign_object.set_mobile_id(&carkey_id);
    utils::set_auth_sign_object(&auth_sign_object);
    auth_sign_object.signature()
}

pub fn handle_iccoa_standard_auth_response_payload(iccoa: &ICCOA) -> Result<()> {
    //handle standard auth response payload
    let message_data = iccoa.get_body().get_message_data();
    if message_data.status != StatusBuilder::new().success().build() {
        return Err(ErrorKind::ICCOAAuthError("standard auth response error".to_string()).into());
    }
    if message_data.get_tag() != 0x02 {
        return Err(ErrorKind::ICCOAAuthError("standard auth response tag error".to_string()).into());
    }
    let total_payload = message_data.get_value();
    let total_length = total_payload.len() as usize;
    let mut index = 0x00;
    let mut mobile_auth_info = Vec::new();
    while index < total_length {
        let payload = TLVPayload::deserialize(&total_payload[index..]).unwrap();
        if payload.get_tag() == 0x87 {
            mobile_auth_info.append(&mut payload.value.to_vec());
        }
        let payload_length = payload.value.len();
        if payload_length < 128 {
            index += 1+1+payload_length;
        } else if payload_length < 256 {
            index += 1+2+payload_length;
        } else {
            index += 1+3+payload_length;
        }
    }
    let auth_sign_object = utils::get_auth_sign_object();
    match auth_sign_object.verify(&mobile_auth_info)  {
        Ok(result) => {
            if result {
                println!("OK");
                Ok(())
            } else {
                println!("Failed");
                return Err(ErrorKind::ICCOAAuthError("mobile auth info signature verify error".to_string()).into());
            }
        },
        Err(_) => {
            return Err(ErrorKind::ICCOAAuthError("mobile auth info signature verify error".to_string()).into());
        }
    }
}

pub fn handle_iccoa_fast_auth_data_exchange_response_payload(iccoa: &ICCOA) -> Status {
    //handle fast auth data exchange payload
    StatusBuilder::new().success().build()
}

pub fn handle_iccoa_fast_auth_response_payload(iccoa: &ICCOA) -> Status {
    //handle fast auth response payload
    StatusBuilder::new().success().build()
}

pub fn handle_iccoa_rke_command(iccoa: &ICCOA) -> TLVPayload {
    //handle rke command from iccoa object
    TLVPayloadBuilder::new().set_tag(0x00).set_value(&[0x00]).build()
}

pub fn handle_iccoa_rke_command_request_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    //handle rke command with request
    let rke_command_response = handle_iccoa_rke_command(iccoa);
    //create rke command response
    let transaction_id = 0x0000;
    let event_id = RKECommandRequest::deserialize(iccoa.body.message_data.get_value())?.get_event_id();
    let tag = rke_command_response.get_tag();
    let value = rke_command_response.value;
    //set status according to tag and value
    let status = match tag {
        0x00 => StatusBuilder::new().success().build(),
        _ => StatusBuilder::new().rfu().build(),
    };
    let response = create_iccoa_rke_response(transaction_id, status, event_id, tag, &value)?;
    Ok(response)
}

pub fn handle_iccoa_pairing_response_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    let transaction_id = 0x00000;
    let message_data = &iccoa.body.message_data;
    match message_data.get_tag() {
        0x01 => {
            return Err(ErrorKind::ICCOAPairingError("getting paired password is not implemented".to_string()).into());
        },
        0x02 => {   //get pA
            //handle pA
            let _status = handle_iccoa_pairing_p_a_payload(iccoa);
            //create spake2+ auth request cB
            let c_b = pairing::calculate_cB();
            let c_b_payload = TLVPayloadBuilder::new().set_tag(0x53).set_value(&c_b).build();
            let response = pairing::create_iccoa_paring_auth_request(transaction_id, &[c_b_payload])?;
            return Ok(response)
        },
        0x03 => {   //get cA
            //handle cA
            let _status = handle_iccoa_pairing_c_a_payload(iccoa);
            //create spake2+ pairing certificate write request
            let vehicle_pubkey_cert = pairing::get_vehicle_certificate();
            let vehicle_pubkey_cert_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_pubkey_cert).build();
            let response = pairing::create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_pubkey_cert_payload])?;
            Ok(response)
        },
        0x04 => {   //get write command status
            //handle write command status
            //create spake2+ pairing certificate read request
            let device_ca_cert_payload = TLVPayloadBuilder::new().set_tag(0x01).build();
            let response = pairing::create_iccoa_pairing_certificate_read_request(transaction_id, &[device_ca_cert_payload])?;
            Ok(response)
        },
        0x05 => {   //get read command data(TLV)
            //handle read command data
            handle_iccoa_pairing_read_response_payload(iccoa)?;
            //create spake2+ pairing certificate read request
            let payload = TLVPayload::deserialize(message_data.get_value())?;
            let response = match payload.get_tag() {
                0x01 => {
                    let mobile_tee_cert_payload = TLVPayloadBuilder::new().set_tag(0x02).build();
                    pairing::create_iccoa_pairing_certificate_read_request(transaction_id, &[mobile_tee_cert_payload])?
                },
                0x02 => {
                    let carkey_pubkey_cert_payload= TLVPayloadBuilder::new().set_tag(0x03).build();
                    pairing::create_iccoa_pairing_certificate_read_request(transaction_id, &[carkey_pubkey_cert_payload])?
                },
                _ => {
                    //test create standard auth request
                    create_iccoa_standard_auth_pubkey_exchange_request_package()?
                    //create_iccoa_fast_auth_pubkey_exchange_request_package()?
                    //return Err(ErrorKind::ICCOAPairingError("Pairing Completed".to_string()).into());
                }
            };
            Ok(response)
        },
        0x07 => {
            return Err(ErrorKind::ICCOAPairingError("Tag 0x07 is not implemented".to_string()).into());
        },
        0xC0 => {
            return Err(ErrorKind::ICCOAPairingError("Tag 0xC0 is not implemented".to_string()).into());
        },
        _ => {      //RFU
            return Err(ErrorKind::ICCOAPairingError("RFU is not implemented".to_string()).into());
        },
    }
}

pub fn handle_iccoa_auth_response_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let message_data = &iccoa.body.message_data;
    match message_data.get_tag() {
        0x01 => {
            //handle standard auth vehicle temp pubkey response
            let vehicle_signature = handle_iccoa_standard_auth_data_exchange_response_payload(iccoa)?;
            //create standard auth request
            let vehicle_signature_payload = TLVPayloadBuilder::new().set_tag(0x86).set_value(&vehicle_signature).build();
            let response = auth::create_iccoa_standard_auth_request(transaction_id, &[vehicle_signature_payload])?;
            Ok(response)
        },
        0x02 => {
            //handle standard auth response
            handle_iccoa_standard_auth_response_payload(iccoa)?;
            return Err(ErrorKind::ICCOAAuthError("standard auth completed".to_string()).into());
        },
        0xC1 => {
            //handle fast auth vehicle temp pubkey response
            let _status = handle_iccoa_fast_auth_data_exchange_response_payload(iccoa);
            //create fast auth request
            let vehicle_fast_auth_data = [0x08; 16];
            let vehicle_fast_auth_data_payload = TLVPayloadBuilder::new().set_tag(0x88).set_value(&vehicle_fast_auth_data).build();
            let response = auth::create_iccoa_fast_auth_request(transaction_id, &[vehicle_fast_auth_data_payload]).unwrap();
            Ok(response)
        },
        0xC2 => {
            //handle fast auth response
            let _status = handle_iccoa_fast_auth_response_payload(iccoa);
            return Err(ErrorKind::ICCOAAuthError("fast auth completed".to_string()).into());
        },
        _ => {
            return Err(ErrorKind::ICCOAPairingError("RFU is not implemented".to_string()).into());
        },
    }
}

pub fn handle_iccoa_ranging_command_response_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    let ranging_result= TLVPayload::deserialize(&iccoa.body.message_data.get_value())?;
    if ranging_result.get_tag() == 0x00 {
        println!("Ranging Success!");
    } else {
        println!("Ranging Failure");
    }
    return Err(ErrorKind::ICCOACommandError("Ranging Command completed".to_string()).into());
}

pub fn handle_iccoa_request_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    match iccoa.body.message_type {
        MessageType::OEM_DEFINED => {
            return Err(ErrorKind::ICCOAObjectError("OEM defined message type is not implemented".to_string()).into());
        },
        MessageType::VEHICLE_PAIRING => {
            return Err(ErrorKind::ICCOAObjectError("Request Pairing message from mobile is not implemented".to_string()).into());
        },
        MessageType::AUTH => {
            return Err(ErrorKind::ICCOAObjectError("Request Auth message from mobile is not implemented".to_string()).into());
        },
        MessageType::COMMAND => {
            return handle_iccoa_rke_command_request_from_mobile(iccoa);
        },
        MessageType::NOTIFICATION => {
            return Err(ErrorKind::ICCOAObjectError("Notification message from mobile is not implemented".to_string()).into());
        },
        MessageType::RFU => {
            return Err(ErrorKind::ICCOAObjectError("RFU message type is not implemented".to_string()).into());
        },
    }
}

pub fn handle_iccoa_response_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    let status = iccoa.body.message_data.status;
    match status.get_tag() {
        StatusTag::SUCCESS => {
            match iccoa.body.message_type {
                MessageType::OEM_DEFINED => {
                    return Err(ErrorKind::ICCOAObjectError("OEM defined message type is not implemented".to_string()).into());
                },
                MessageType::VEHICLE_PAIRING => {
                    return handle_iccoa_pairing_response_from_mobile(iccoa);
                },
                MessageType::AUTH => {
                    return handle_iccoa_auth_response_from_mobile(iccoa);
                },
                MessageType::COMMAND => {
                    return handle_iccoa_ranging_command_response_from_mobile(iccoa);
                },
                MessageType::NOTIFICATION => {
                    return Err(ErrorKind::ICCOAObjectError("Notification message type is not implemented".to_string()).into());
                },
                MessageType::RFU => {
                    return Err(ErrorKind::ICCOAObjectError("RFU message type is not implemented".to_string()).into());
                },
            }
        },
        StatusTag::COMMUNICATION_PROTOCOL_ERROR => {
            match status.get_code() {
                0x01 => {
                    return Err(ErrorKind::ICCOAObjectError("frame number error".to_string()).into());
                },
                0x02 => {
                    return Err(ErrorKind::ICCOAObjectError("package length error".to_string()).into());
                },
                _ => {
                    return Err(ErrorKind::ICCOAObjectError("rfu".to_string()).into());
                },
            }
        },
        StatusTag::DATA_ERROR => {
            match status.get_code() {
                0x01 => {
                    return Err(ErrorKind::ICCOAObjectError("data format error".to_string()).into());
                },
                0x02 => {
                    return Err(ErrorKind::ICCOAObjectError("invalid message type".to_string()).into());
                },
                _ => {
                    return Err(ErrorKind::ICCOAObjectError("rfu".to_string()).into());
                },
            }
        },
        StatusTag::REQUEST_ERROR => {
            match status.get_code() {
                0x01 => {
                    return Err(ErrorKind::ICCOAObjectError("running, do not call frequently".to_string()).into());
                },
                0x02 => {
                    return Err(ErrorKind::ICCOAObjectError("running timetout".to_string()).into());
                },
                _ => {
                    return Err(ErrorKind::ICCOAObjectError("rfu".to_string()).into());
                },
            }
        },
        StatusTag::BUSINESS_ERROR => {
            match status.get_code() {
                0x01 => {
                    return Err(ErrorKind::ICCOAObjectError("vehicle is not paired".to_string()).into());
                },
                0x02 => {
                    return Err(ErrorKind::ICCOAObjectError("vehicle already paired".to_string()).into());
                },
                0x03 => {
                    return Err(ErrorKind::ICCOAObjectError("car key authentication failure".to_string()).into());
                }
                _ => {
                    return Err(ErrorKind::ICCOAObjectError("rfu".to_string()).into());
                },
            }
        },
        StatusTag::RFU => {
            return Err(ErrorKind::ICCOAObjectError("rfu".to_string()).into());
        },
    }

}

pub fn handle_data_package_from_mobile(data_package: &[u8]) -> Result<ICCOA> {
    if let Ok(mut iccoa) = ICCOA::deserialize(data_package) {
        let mark = iccoa.get_header().get_mark();
        if mark.get_more_fragment() == true {
            objects::collect_iccoa_fragments(iccoa);
            return Err(ErrorKind::ICCOAObjectError("receive fragments".to_string()).into());
        }
        if mark.get_more_fragment() == false && mark.get_fragment_offset() != 0x00 {
            objects::collect_iccoa_fragments(iccoa);
            iccoa = objects::reassemble_iccoa_fragments();
        }
        match iccoa.header.packet_type {
            PacketType::REQUEST_PACKET => {
                return handle_iccoa_request_from_mobile(&iccoa)
            },
            PacketType::REPLY_PACKET => {
                return handle_iccoa_response_from_mobile(&iccoa)
            },
            _ => {
                return Err(ErrorKind::ICCOAObjectError("not supported packet type".to_string()).into());
            },
        }
    } else {
        return Err(ErrorKind::ICCOAObjectError("data package deserialize error".to_string()).into());
    }
}

#[cfg(test)]
mod tests {
    use crate::iccoa::{command::{rke::create_iccoa_rke_central_lock_request, ranging::create_iccoa_ranging_response}, objects::{Header, Body, Mark, MessageData, create_iccoa_header, EncryptType, create_iccoa_body_message_data, create_iccoa_body, create_iccoa}, pairing::{create_iccoa_pairing_data_request, calculate_pB, calculate_pA, create_iccoa_pairing_data_response, calculate_cA, create_iccoa_pairing_auth_response, create_iccoa_pairing_certificate_write_response, get_mobile_device_server_ca_certificate, get_mobile_device_tee_ca_certificate, get_carkey_certificate, create_iccoa_pairing_certificate_read_response}, auth::{create_iccoa_standard_auth_pubkey_exchange_response, create_iccoa_standard_auth_response, create_iccoa_fast_auth_pubkey_exchange_response, create_iccoa_fast_auth_response}};
    use super::*;

    #[test]
    fn test_rke_command_request_from_mobile() {
        let transaction_id = 0x0000;
        let event_id = 0xFFFF;
        let rke_request = create_iccoa_rke_central_lock_request(transaction_id, event_id).unwrap();
        let rke_response = handle_data_package_from_mobile(&rke_request.serialize()).unwrap();
        assert_eq!(rke_response, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: rke_response.get_header().get_source_transaction_id(),
                pdu_length: 12+1+2+3+4+1+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_AFTER_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000, 
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::COMMAND,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x01,
                    value: vec![
                        0xFF, 0xFF, 0x00, 0x01, 0x00
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_pairing_response_from_mobile() {
        //1st receive pA response
        let transaction_id = 0x0000;
        let status = StatusBuilder::new().success().build();
        let p_a = calculate_pA();
        let p_a_payload = TLVPayloadBuilder::new().set_tag(0x52).set_value(&p_a).build();
        let p_a_response = create_iccoa_pairing_data_response(transaction_id, status, &[p_a_payload]).unwrap();
        //create auth request cB
        let auth_request = handle_data_package_from_mobile(&p_a_response.serialize()).unwrap();
        let dest_transaction_id = auth_request.get_header().get_dest_transaction_id();
        assert_eq!(auth_request, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: dest_transaction_id,
                pdu_length: 12+1+3+2+16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x03,
                    value: vec![
                        0x53, 0x10,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
        //2nd receive auth response cA
        let c_a = calculate_cA();
        let c_a_payload = TLVPayloadBuilder::new().set_tag(0x54).set_value(&c_a).build();
        let iccoa = create_iccoa_pairing_auth_response(transaction_id, status, &[c_a_payload]).unwrap();
        //create pairing certificate write request
        let pairing_cert_write_request = handle_data_package_from_mobile(&iccoa.serialize()).unwrap();
        let dest_transaction_id = pairing_cert_write_request.get_header().get_dest_transaction_id();
        assert_eq!(pairing_cert_write_request, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: dest_transaction_id,
                pdu_length: 12+1+3+2+16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x04,
                    value: vec![
                        0x55, 0x10,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
        //3rd receive paring write response
        let status = StatusBuilder::new().success().build();
        let iccoa = create_iccoa_pairing_certificate_write_response(transaction_id, status).unwrap();
        //crate pairing certificate read request
        let pairing_cert_read_request = handle_data_package_from_mobile(&iccoa.serialize()).unwrap();
        let dest_transaction_id = pairing_cert_read_request.get_header().get_dest_transaction_id();
        assert_eq!(pairing_cert_read_request, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: dest_transaction_id,
                pdu_length: 12+1+3+2+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x05,
                    value: vec![
                        0x01, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
        //4th receive pairing read response 1
        let mobile_device_certificate = get_mobile_device_server_ca_certificate();
        let payload1 = TLVPayloadBuilder::new().set_tag(0x01).set_value(&mobile_device_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_read_response(transaction_id, status, &[payload1]).unwrap();
        //crate pairing certificate read request
        let pairing_cert_read_request_2 = handle_data_package_from_mobile(&iccoa.serialize()).unwrap();
        let dest_transaction_id = pairing_cert_read_request_2.get_header().get_dest_transaction_id();
        assert_eq!(pairing_cert_read_request_2, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: dest_transaction_id,
                pdu_length: 12+1+3+2+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x05,
                    value: vec![
                        0x02, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
        //5th receive pairing read response 2
        let mobile_tee_certificate = get_mobile_device_tee_ca_certificate();
        let payload2 = TLVPayloadBuilder::new().set_tag(0x02).set_value(&mobile_tee_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_read_response(transaction_id, status, &[payload2]).unwrap();
        //crate pairing certificate read request
        let pairing_cert_read_request_3 = handle_data_package_from_mobile(&iccoa.serialize()).unwrap();
        let dest_transaction_id = pairing_cert_read_request_3.get_header().get_dest_transaction_id();
        assert_eq!(pairing_cert_read_request_3, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: dest_transaction_id,
                pdu_length: 12+1+3+2+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x05,
                    value: vec![
                        0x03, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
        //6th receive pairing read response 3
        let carkey_certificate = get_carkey_certificate();
        let payload3 = TLVPayloadBuilder::new().set_tag(0x03).set_value(&carkey_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_read_response(transaction_id, status, &[payload3]).unwrap();
        let _ = handle_data_package_from_mobile(&iccoa.serialize()).unwrap();
    }
    #[test]
    fn test_standard_auth_response_from_mobile() {
        //create standard auth pubkey exchange response
        let transaction_id = 0x0000;
        let status = StatusBuilder::new().success().build();
        let mobile_temp_pubkey = [0x02; 65];
        let mobile_id = [0x20; 16];
        let mobile_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x84).set_value(&mobile_temp_pubkey).build();
        let mobile_id_payload = TLVPayloadBuilder::new().set_tag(0x89).set_value(&mobile_id).build();
        let iccoa = create_iccoa_standard_auth_pubkey_exchange_response(transaction_id, status, &[mobile_temp_pubkey_payload, mobile_id_payload]).unwrap();
        //create standard auth request
        let auth_request = handle_data_package_from_mobile(&iccoa.serialize()).unwrap();
        assert_eq!(auth_request, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: auth_request.get_header().get_dest_transaction_id(),
                pdu_length: 12+1+3+2+64+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x86, 0x40,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
        //create standard auth response
        let status = StatusBuilder::new().success().build();
        let mobile_signature = [0x30; 64];
        let mobile_signature_payload = TLVPayloadBuilder::new().set_tag(0x87).set_value(&mobile_signature).build();
        let iccoa = create_iccoa_standard_auth_response(transaction_id, status, &[mobile_signature_payload]).unwrap();
        if let Ok(_) = handle_data_package_from_mobile(&iccoa.serialize()) {
        }
    }
    #[test]
    fn test_fast_auth_response_from_mobile() {
        //create fast auth exchange data response
        let transaction_id = 0x0000;
        let status = StatusBuilder::new().success().build();
        let mobile_temp_pubkey = [0x07; 65];
        let mobile_id = [0x70; 16];
        let mobile_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x84).set_value(&mobile_temp_pubkey).build();
        let mobile_id_payload = TLVPayloadBuilder::new().set_tag(0x89).set_value(&mobile_id).build();
        let iccoa = create_iccoa_fast_auth_pubkey_exchange_response(transaction_id, status, &[mobile_temp_pubkey_payload, mobile_id_payload]).unwrap();
        let fast_auth_request = handle_data_package_from_mobile(&iccoa.serialize()).unwrap();
        assert_eq!(fast_auth_request, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: fast_auth_request.get_header().get_dest_transaction_id(),
                pdu_length: 12+1+3+2+16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    tag: 0xC2,
                    value: vec![
                        0x88, 0x10,
                        0x08, 0x08, 0x08, 0x08,0x08, 0x08, 0x08, 0x08,
                        0x08, 0x08, 0x08, 0x08,0x08, 0x08, 0x08, 0x08
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
        //create fast auth response
        let status = StatusBuilder::new().success().build();
        let iccoa = create_iccoa_fast_auth_response(transaction_id, status).unwrap();
        if let Ok(_) = handle_data_package_from_mobile(&iccoa.serialize()) {
        }
    }
    #[test]
    fn test_ranging_command_response_success_from_mobile() {
        let transaction_id = 0x0010;
        let status = StatusBuilder::new().success().build();
        let ranging_value = 0x00;
        let ranging_value_payload = TLVPayloadBuilder::new().set_tag(0x00).set_value(&[ranging_value]).build();
        let ranging_response = create_iccoa_ranging_response(transaction_id, status, 0x02, &[ranging_value_payload]).unwrap();
        if let Ok(_) = handle_data_package_from_mobile(&ranging_response.serialize()) {
        }
    }
    #[test]
    fn test_ranging_command_response_failure_from_mobile() {
        let transaction_id = 0x0010;
        let status = StatusBuilder::new().success().build();
        let ranging_tag = 0x01;
        let ranging_value = 0x01;
        let ranging_value_payload = TLVPayloadBuilder::new().set_tag(ranging_tag).set_value(&[ranging_value]).build();
        let ranging_response = create_iccoa_ranging_response(transaction_id, status, 0x02, &[ranging_value_payload]).unwrap();
        if let Ok(_) = handle_data_package_from_mobile(&ranging_response.serialize()) {
        }
    }
    #[test]
    fn test_fragments_from_mobile() {
        let transaction_id = 0x0011;
        let header = create_iccoa_header(
            PacketType::REQUEST_PACKET,
            transaction_id,
            1+3+3,
            Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: true,
                fragment_offset: 0x0000,
            }
        );
        let payload = create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            &[0x01, 0x02, 0x03]
        );
        let body = create_iccoa_body(
            MessageType::VEHICLE_PAIRING,
            payload
        );
        let request = create_iccoa(header, body);
        println!("request serialized is {:02X?}", request.serialize());
        let result = handle_data_package_from_mobile(&request.serialize());
        println!("result = {:?}", result);

        let header2 = create_iccoa_header(
            PacketType::REQUEST_PACKET,
            transaction_id,
            3,
            Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: true,
                fragment_offset: 0x0003,
            }
        );
        let payload2 = create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            &[0x04, 0x05, 0x06]
        );
        let body2 = create_iccoa_body(
            MessageType::VEHICLE_PAIRING,
            payload2
        );
        let request2= create_iccoa(header2, body2);
        println!("request2 serialized is {:02X?}", request2.serialize());
        let result2 = handle_data_package_from_mobile(&request2.serialize());
        println!("result2 = {:?}", result2);

        let header3 = create_iccoa_header(
            PacketType::REQUEST_PACKET,
            transaction_id,
            3,
            Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0006,
            }
        );
        let payload3 = create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            &[0x07, 0x08, 0x09]
        );
        let body3 = create_iccoa_body(
            MessageType::VEHICLE_PAIRING,
            payload3
        );
        let request3= create_iccoa(header3, body3);
        println!("request3 serialized is {:02X?}", request3.serialize());
        let result3 = handle_data_package_from_mobile(&request3.serialize());
        println!("result3 = {:?}", result3);
    }
    #[test]
    fn test_split_request_iccoa() {
        let transaction_id = 0x0012;
        let header = create_iccoa_header(
            PacketType::REQUEST_PACKET,
            transaction_id,
            1+3+1024,
            Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            }
        );
        let payload = create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            &vec![0x01; 1024],
        );
        let body = create_iccoa_body(
            MessageType::VEHICLE_PAIRING,
            payload
        );
        let request = create_iccoa(header, body);
        println!("request serialized is {:02X?}", request.serialize());
        println!("request seriallized length is {}", request.serialize().len());
        match objects::split_iccoa(&request) {
            Some(splitted_iccoa) => {
                println!("splitted_iccoa size = {}", splitted_iccoa.len());
                splitted_iccoa.iter().for_each(|item| {
                    println!("{:?}", item);
                });
            },
            None => {
                println!("No need split!!!");
            }
        }
    }
    #[test]
    fn test_split_response_iccoa() {
        let transaction_id = 0x0013;
        let header = create_iccoa_header(
            PacketType::REPLY_PACKET,
            transaction_id,
            1+2+3+1024,
            Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            }
        );
        let payload = create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            &vec![0x01; 1024],
        );
        let body = create_iccoa_body(
            MessageType::VEHICLE_PAIRING,
            payload
        );
        let response = create_iccoa(header, body);
        println!("response serialized is {:02X?}", response.serialize());
        println!("response seriallized length is {}", response.serialize().len());
    }
}
