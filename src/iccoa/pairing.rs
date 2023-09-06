use std::io::{Read, Write};
use std::sync::Mutex;

use crate::iccoa::utils::CipherKey;

use super::objects::{ICCOA, Mark, create_iccoa_header, create_iccoa_body_message_data, create_iccoa_body, create_iccoa};
use super::{errors::*, TLVPayload, TLVPayloadBuilder, auth};
use super::status::{StatusBuilder, Status, StatusTag};

lazy_static! {
    static ref SPAKE2_PLUS_P_A_LENGTH: usize = 0x41;
    static ref SPAKE2_PLUS_C_A_LENGTH: usize = 0x12;
    static ref SPAKE2_PLUS_C_B_LENGTH: usize = 0x12;
    static ref PAIRING_PAYLOAD_LENGTH_MINIMUM: usize = 0x02;
    static ref PAIRING_KEY: Mutex<CipherKey> = Mutex::new(CipherKey::new());
}

pub fn calculate_p_b() -> [u8; 65] {
    [0x00; 65]
}

pub fn calculate_p_a() -> [u8; 65] {
    [0x00; 65]
}

pub fn calculate_c_b() -> [u8; 16] {
    [0x00; 16]
}

pub fn calculate_c_a() -> [u8; 16] {
    [0x00; 16]
}

pub fn get_pairing_key_mac() -> Vec<u8> {
    let pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.get_key_mac()
}

pub fn get_pairing_key_enc() -> Vec<u8> {
    let pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.get_key_enc()
}

pub fn get_vehicle_certificate() -> Vec<u8> {
    let mut cert = Vec::new();
    if let Ok(mut file) = std::fs::File::open("/etc/certs/vehicle_public.crt") {
        let metadata = std::fs::metadata("/etc/certs/vehicle_public.crt").unwrap();
        cert = vec![0; metadata.len() as usize];
        file.read(&mut cert).unwrap();
    } else {
        cert = [0x01; 16].to_vec();
    }
    cert
}

pub fn get_mobile_device_server_ca_certificate() -> Vec<u8> {
    let mut cert = Vec::new();
    if let Ok(mut file) = std::fs::File::open("/etc/certs/mobile_server_ca.crt") {
        file.read(&mut cert).unwrap();
    } else {
        cert = [0x02; 16].to_vec();
    }
    cert
}

pub fn get_mobile_device_tee_ca_certificate() -> Vec<u8> {
    let mut cert = Vec::new();
    if let Ok(mut file) = std::fs::File::open("/etc/certs/mobile_tee_ca.crt") {
        file.read(&mut cert).unwrap();
    } else {
        cert = [0x03; 16].to_vec();
    }
    cert
}

pub fn get_carkey_certificate() -> Vec<u8> {
    [0x04; 16].to_vec()
}

pub fn create_iccoa_pairing_data_request_package() -> Result<Vec<u8>> {
    let transaction_id = 0x0000;
    let p_b = calculate_p_b();
    let p_b_payload = TLVPayloadBuilder::new().set_tag(0x51).set_value(&p_b).build();
    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let salt_payload = TLVPayloadBuilder::new().set_tag(0xC0).set_value(&salt).build();
    let nscrypt = [0x01, 0x02, 0x03, 0x04];
    let nscrypt_payload = TLVPayloadBuilder::new().set_tag(0xC1).set_value(&nscrypt).build();
    let r = [0x01, 0x02];
    let r_payload = TLVPayloadBuilder::new().set_tag(0xC2).set_value(&r).build();
    let p = [0x02, 0x01];
    let p_payload = TLVPayloadBuilder::new().set_tag(0xC3).set_value(&p).build();
    let iccoa = create_iccoa_pairing_data_request(
        transaction_id,
        &[p_b_payload, salt_payload, nscrypt_payload, r_payload, p_payload])?;
    Ok(iccoa.serialize())
}

fn create_iccoa_pairing_request(transaction_id: u16, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += p.get_total_length();
        payload_data.append(&mut p.serialize());
    });

    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+payload_length as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

fn create_iccoa_pairing_response(transaction_id: u16, status: Status, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += p.get_total_length();
        payload_data.append(&mut p.serialize());
    });

    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+payload_length as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_data_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x02, payloads)
}

pub fn create_iccoa_pairing_data_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x02, payloads)
}

pub fn create_iccoa_paring_auth_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x03, payloads)
}

pub fn create_iccoa_pairing_auth_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x03, payloads)
}

pub fn create_iccoa_pairing_certificate_write_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x04, payloads)
}

pub fn create_iccoa_pairing_certificate_write_response(transaction_id: u16, status: Status) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x04, &[])
}

pub fn create_iccoa_pairing_certificate_read_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x05, payloads)
}

pub fn create_iccoa_pairing_certificate_read_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x05, payloads)
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
            let c_b = calculate_c_b();
            let c_b_payload = TLVPayloadBuilder::new().set_tag(0x53).set_value(&c_b).build();
            let response = create_iccoa_paring_auth_request(transaction_id, &[c_b_payload])?;
            return Ok(response)
        },
        0x03 => {   //get cA
            //handle cA
            let _status = handle_iccoa_pairing_c_a_payload(iccoa);
            //create spake2+ pairing certificate write request
            let vehicle_pubkey_cert = get_vehicle_certificate();
            let vehicle_pubkey_cert_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_pubkey_cert).build();
            let response = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_pubkey_cert_payload])?;
            Ok(response)
        },
        0x04 => {   //get write command status
            //handle write command status
            //create spake2+ pairing certificate read request
            let device_ca_cert_payload = TLVPayloadBuilder::new().set_tag(0x01).build();
            let response = create_iccoa_pairing_certificate_read_request(transaction_id, &[device_ca_cert_payload])?;
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
                    create_iccoa_pairing_certificate_read_request(transaction_id, &[mobile_tee_cert_payload])?
                },
                0x02 => {
                    let carkey_pubkey_cert_payload= TLVPayloadBuilder::new().set_tag(0x03).build();
                    create_iccoa_pairing_certificate_read_request(transaction_id, &[carkey_pubkey_cert_payload])?
                },
                _ => {
                    //test create standard auth request
                    auth::create_iccoa_standard_auth_pubkey_exchange_request_package()?
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


#[cfg(test)]
mod tests {
    use crate::iccoa::{objects::{Header, Body, MessageData}, TLVPayloadBuilder};

    use super::*;

    #[test]
    fn test_little_size_pairing_payload() {
        let transaction_id = 0x0004;
        let vehicle_certificate = [0x01; 16];
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap();
        println!("seialized iccoa = {:02X?}", iccoa.serialize());
        let deserialized_iccoa = ICCOA::deserialize(&iccoa.serialize()).unwrap();
        assert_eq!(iccoa, deserialized_iccoa);
    }
    #[test]
    fn test_middle_size_pairing_payload() {
        let transaction_id = 0x0004;
        let vehicle_certificate = [0x01; 250];
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap();
        println!("seialized iccoa = {:02X?}", iccoa.serialize());
        let deserialized_iccoa = ICCOA::deserialize(&iccoa.serialize()).unwrap();
        assert_eq!(iccoa, deserialized_iccoa);
    }
    #[test]
    fn test_large_size_pairing_payload() {
        let transaction_id = 0x0004;
        let vehicle_certificate = [0x01; 1024];
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap();
        println!("seialized iccoa = {:02X?}", iccoa.serialize());
        let deserialized_iccoa = ICCOA::deserialize(&iccoa.serialize()).unwrap();
        assert_eq!(iccoa, deserialized_iccoa);
    }
    #[test]
    fn test_spake2_plus_data_request() {
        let transaction_id = 0x0001;
        let p_b = calculate_p_b();
        let p_b_payload = TLVPayloadBuilder::new().set_tag(0x51).set_value(&p_b).build();
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let salt_payload = TLVPayloadBuilder::new().set_tag(0xC0).set_value(&salt).build();
        let nscrypt = [0x01, 0x02, 0x03, 0x04];
        let nscrypt_payload = TLVPayloadBuilder::new().set_tag(0xC1).set_value(&nscrypt).build();
        let r = [0x01, 0x02];
        let r_payload = TLVPayloadBuilder::new().set_tag(0xC2).set_value(&r).build();
        let p = [0x02, 0x01];
        let p_payload = TLVPayloadBuilder::new().set_tag(0xC3).set_value(&p).build();
        let iccoa = create_iccoa_pairing_data_request(transaction_id, &[p_b_payload, salt_payload, nscrypt_payload, r_payload, p_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0001,
                pdu_length: 12+1+102+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        81, 65, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 192, 16, 0, 1, 2,
                        3, 4, 5, 6, 7, 8, 9, 10,
                        11, 12, 13, 14, 15, 193, 4, 1,
                        2, 3, 4, 194, 2, 1, 2, 195, 2,
                        2, 1],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_data_response() {
        let transaction_id = 0x0002;
        let status = StatusBuilder::new().success().build();
        let p_a = calculate_p_a();
        let p_a_payload = TLVPayloadBuilder::new().set_tag(0x52).set_value(&p_a).build();
        let iccoa = create_iccoa_pairing_data_response(transaction_id, status, &[p_a_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0002,
                pdu_length: 12+73+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x02,
                    value: vec![
                        82, 65, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0
                    ]
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_auth_request() {
        let transaction_id = 0x0002;
        let c_b = calculate_c_b();
        let c_b_payload = TLVPayloadBuilder::new().set_tag(0x53).set_value(&c_b).build();
        let iccoa = create_iccoa_paring_auth_request(transaction_id, &[c_b_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0002,
                pdu_length: 12+1+21+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment:false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x03,
                    value: vec![
                        0x53, 0x10,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ],
                    ..Default::default()
                }

            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_auth_response() {
        let transaction_id= 0x0003;
        let status = StatusBuilder::new().success().build();
        let c_a = calculate_c_a();
        let c_a_payload = TLVPayloadBuilder::new().set_tag(0x54).set_value(&c_a).build();
        let iccoa = create_iccoa_pairing_auth_response(transaction_id, status, &[c_a_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0003,
                pdu_length: 12+1+23+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x03,
                    value: vec![
                        0x54, 0x10,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ],
                },
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_spake2_plus_certificate_write_request() {
        let transaction_id = 0x0004;
        let vehicle_certificate = get_vehicle_certificate();
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap(); 
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+21+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
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
        })       
    }
    #[test]
    fn test_spake2_plus_certificate_write_response() {
        let transaction_id = 0x0004;
        let status = StatusBuilder::new().success().build();
        let iccoa = create_iccoa_pairing_certificate_write_response(transaction_id, status).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0004,
                pdu_length: 12+1+5+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x04,
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_spake2_plus_certificate_read_request() {
        let transaction_id = 0x0005;
        let cert_type_payload1 = TLVPayloadBuilder::new().set_tag(0x01).build();
        let cert_type_payload2 = TLVPayloadBuilder::new().set_tag(0x02).build();
        let cert_type_payload3 = TLVPayloadBuilder::new().set_tag(0x03).build();
        let iccoa = create_iccoa_pairing_certificate_read_request(transaction_id, &[cert_type_payload1, cert_type_payload2, cert_type_payload3]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+6+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x05,
                    value: vec![
                        0x01, 0x00,
                        0x02, 0x00,
                        0x03, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_certificate_read_response() {
        let transaction_id = 0x0005;
        let status = StatusBuilder::new().success().build();
        let mobile_device_certificate = get_mobile_device_server_ca_certificate();
        let mobile_tee_certificate = get_mobile_device_tee_ca_certificate();
        let carkey_certificate = get_carkey_certificate();
        let payload1 = TLVPayloadBuilder::new().set_tag(0x01).set_value(&mobile_device_certificate).build();
        let payload2 = TLVPayloadBuilder::new().set_tag(0x02).set_value(&mobile_tee_certificate).build();
        let payload3 = TLVPayloadBuilder::new().set_tag(0x03).set_value(&carkey_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_read_response(transaction_id, status, &[payload1, payload2, payload3]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0005,
                pdu_length: 12+1+2+3+18*3+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x05,
                    value: vec![
                        0x01, 0x10,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x10,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x10,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
                    ],
                },
            },
            mac: [0x00; 8],
        })
    }
}