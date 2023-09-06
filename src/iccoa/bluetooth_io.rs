use super::command::{rke, self};
use super::{errors::*, objects};
use super::objects::{ICCOA, PacketType, MessageType};
use super::status::StatusTag;
use super::pairing;
use super::auth;

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
            return rke::handle_iccoa_rke_command_request_from_mobile(iccoa);
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
                    return pairing::handle_iccoa_pairing_response_from_mobile(iccoa);
                },
                MessageType::AUTH => {
                    return auth::handle_iccoa_auth_response_from_mobile(iccoa);
                },
                MessageType::COMMAND => {
                    return command::ranging::handle_iccoa_ranging_command_response_from_mobile(iccoa);
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
    use crate::iccoa::{command::{rke::create_iccoa_rke_central_lock_request, ranging::create_iccoa_ranging_response}, objects::{Header, Body, Mark, MessageData, create_iccoa_header, EncryptType, create_iccoa_body_message_data, create_iccoa_body, create_iccoa}, pairing::{calculate_p_a, create_iccoa_pairing_data_response, calculate_c_a, create_iccoa_pairing_auth_response, create_iccoa_pairing_certificate_write_response, get_mobile_device_server_ca_certificate, get_mobile_device_tee_ca_certificate, get_carkey_certificate, create_iccoa_pairing_certificate_read_response}, auth::{create_iccoa_standard_auth_pubkey_exchange_response, create_iccoa_standard_auth_response, create_iccoa_fast_auth_pubkey_exchange_response, create_iccoa_fast_auth_response}, status::StatusBuilder, TLVPayloadBuilder};
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
        let p_a = calculate_p_a();
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
        let c_a = calculate_c_a();
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
