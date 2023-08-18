use super::objects::{ICCOA, Mark, create_iccoa_header, create_iccoa_body_message_data, create_iccoa_body, create_iccoa};
use super::{errors::*, TLVPayload};
use super::status::{StatusBuilder, Status};

lazy_static! {
    static ref VEHICLE_TEMP_PUBKEY_LENGTH: usize = 65;
    static ref VEHICLE_ID_LENGTH: usize = 16;
    static ref MOBILE_TEMP_PUBKEY_LENGTH: usize = 65;
    static ref MOBILE_ID_LENGTH: usize = 16;
    static ref VEHICLE_SIGNATURE_LENGTH: usize = 64;
    static ref MOBILE_SIGNATURE_LENGTH: usize = 64;
    static ref VEHICLE_FAST_AUTH_DATA_LENGTH: usize = 16;
    static ref AUTH_PAYLOAD_LENGTH_MINIMUM: usize = 2;
}

fn create_iccoa_auth_request(transaction_id: u16, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += 2+p.value.len();
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
        super::objects::MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

fn create_iccoa_auth_response(transaction_id: u16, status: Status, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += 2+p.value.len();
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
        super::objects::MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}


pub fn create_iccoa_standard_auth_pubkey_exchange_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_request(transaction_id, 0x01, payloads)
}

pub fn create_iccoa_standard_auth_pubkey_exchange_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_response(transaction_id, status, 0x01, payloads)
}

pub fn create_iccoa_standard_auth_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_request(transaction_id, 0x02, payloads)
}

pub fn create_iccoa_standard_auth_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_response(transaction_id, status, 0x02, payloads)
}

pub fn create_iccoa_standard_auth_friend_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_request(transaction_id, 0x03, payloads)
}

pub fn create_iccoa_standard_auth_friend_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_response(transaction_id, status, 0x03, payloads)
}

pub fn create_iccoa_standard_auth_write_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_request(transaction_id, 0x04, payloads)
}

pub fn create_iccoa_standard_auth_write_response(transaction_id: u16, status: Status) -> Result<ICCOA> {
    return create_iccoa_auth_response(transaction_id, status, 0x04, &[])
}

pub fn create_iccoa_standard_auth_read_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_request(transaction_id, 0x05, payloads)
}

pub fn create_iccoa_standard_auth_read_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_response(transaction_id, status, 0x05, payloads)
}

pub fn create_iccoa_fast_auth_pubkey_exchange_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_request(transaction_id, 0xC1, payloads)
}

pub fn create_iccoa_fast_auth_pubkey_exchange_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_response(transaction_id, status, 0xC1, payloads)
}

pub fn create_iccoa_fast_auth_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_auth_request(transaction_id, 0xC2, payloads)
}

pub fn create_iccoa_fast_auth_response(transaction_id: u16, status: Status) -> Result<ICCOA> {
    return create_iccoa_auth_response(transaction_id, status, 0xC2, &[])
}

#[cfg(test)]
mod tests {
    use crate::iccoa::{objects::{Header, Body, MessageData, PacketType, EncryptType, MessageType}, TLVPayloadBuilder};
    use super::*;

    #[test]
    fn test_standard_auth_data_exchange_request() {
        let transaction_id = 0x0001;
        let vehicle_temp_pubkey = [0x01; 65];
        let vehicle_id = [0x10; 16];
        let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
        let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
        let iccoa = create_iccoa_standard_auth_pubkey_exchange_request(transaction_id, &[vehicle_temp_pubkey_payload, vehicle_id_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0001,
                pdu_length: 12+1+88+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    tag: 0x01,
                    value: vec![
                        0x81, 0x41,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01,
                        0x83, 0x10,
                        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_standard_auth_data_exchange_response() {
        let transaction_id = 0x0001;
        let status = StatusBuilder::new().success().build();
        let mobile_temp_pubkey = [0x02; 65];
        let mobile_id = [0x20; 16];
        let mobile_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x84).set_value(&mobile_temp_pubkey).build();
        let mobile_id_payload = TLVPayloadBuilder::new().set_tag(0x89).set_value(&mobile_id).build();
        let iccoa = create_iccoa_standard_auth_pubkey_exchange_response(transaction_id, status, &[mobile_temp_pubkey_payload, mobile_id_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0001,
                pdu_length: 12+1+2+88+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x01,
                    value: vec![
                        0x84, 0x41,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02,
                        0x89, 0x10,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_standard_auth_request() {
        let transaction_id = 0x0002;
        let vehicle_signature = [0x03; 64];
        let vehicle_signature_payload = TLVPayloadBuilder::new().set_tag(0x86).set_value(&vehicle_signature).build();
        let iccoa = create_iccoa_standard_auth_request(transaction_id, &[vehicle_signature_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0002,
                pdu_length: 12+1+69+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
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
    }
    #[test]
    fn test_standard_auth_response() {
        let transaction_id = 0x0002;
        let status = StatusBuilder::new().success().build();
        let mobile_signature = [0x30; 64];
        let mobile_signature_payload = TLVPayloadBuilder::new().set_tag(0x87).set_value(&mobile_signature).build();
        let iccoa = create_iccoa_standard_auth_response(transaction_id, status, &[mobile_signature_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0002,
                pdu_length: 12+1+2+69+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x02,
                    value: vec![
                        0x87, 0x40,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_friend_key_data_request() {
        let transaction_id = 0x0003;
        let friend_key_data = [0x04; 64];
        let friend_key_data_payload = TLVPayloadBuilder::new().set_tag(0x71).set_value(&friend_key_data).build();
        let iccoa = create_iccoa_standard_auth_friend_request(transaction_id, &[friend_key_data_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0003,
                pdu_length: 12+1+3+2+friend_key_data.len() as u16+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    tag: 0x03,
                    value: vec![
                        0x71, 0x40,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
                    ],
                    ..Default::default()
                }
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_friend_key_data_response() {
        let transaction_id = 0x0003;
        let status = StatusBuilder::new().success().build();
        let friend_key_shared_info = [0x40; 64];
        let friend_key_shared_info_payload = TLVPayloadBuilder::new().set_tag(0x71).set_value(&friend_key_shared_info).build();
        let iccoa = create_iccoa_standard_auth_friend_response(transaction_id, status, &[friend_key_shared_info_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0003,
                pdu_length: 12+1+2+3+2+friend_key_shared_info.len() as u16+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x03,
                    value: vec![
                        0x71, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_write_request() {
        let transaction_id = 0x0004;
        let write_data = [0x05; 32];
        let write_data_payload = TLVPayloadBuilder::new().set_tag(0x72).set_value(&write_data).build();
        let iccoa = create_iccoa_standard_auth_write_request(transaction_id, &[write_data_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+3+2+write_data.len() as u16+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    tag: 0x04,
                    value: vec![
                        0x72, 0x20,
                        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
                    ],
                    ..Default::default()
                }
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_write_response() {
        let transaction_id = 0x0004;
        let status = StatusBuilder::new().success().build();
        let iccoa = create_iccoa_standard_auth_write_response(transaction_id, status).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0004,
                pdu_length: 12+1+2+3+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x04,
                    value: vec![],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_read_request() {
        let transaction_id = 0x0005;
        let read_list = vec![0x01, 0x02, 0x03];
        let payload1 = TLVPayloadBuilder::new().set_tag(0x01).build();
        let payload2 = TLVPayloadBuilder::new().set_tag(0x02).build();
        let payload3 = TLVPayloadBuilder::new().set_tag(0x03).build();
        let iccoa = create_iccoa_standard_auth_read_request(transaction_id, &[payload1, payload2, payload3]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+2*3+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    tag: 0x05,
                    value: vec![
                        0x01, 0x00,
                        0x02, 0x00,
                        0x03, 0x00
                    ],
                    ..Default::default()
                }
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_read_response() {
        let transaction_id = 0x0005;
        let status = StatusBuilder::new().success().build();
        let data1 = [0x50; 16];
        let data2 = [0x60; 16];
        let data3 = [0x70; 16];
        let payload1 = TLVPayloadBuilder::new().set_tag(0x01).set_value(&data1).build();
        let payload2 = TLVPayloadBuilder::new().set_tag(0x02).set_value(&data2).build();
        let payload3 = TLVPayloadBuilder::new().set_tag(0x03).set_value(&data3).build();
        let iccoa = create_iccoa_standard_auth_read_response(transaction_id, status, &[payload1, payload2, payload3]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0005,
                pdu_length: 12+1+2+3+18*3+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x05,
                    value: vec![
                        0x01, 0x10,
                        0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
                        0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
                        0x02, 0x10,
                        0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
                        0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
                        0x03, 0x10,
                        0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70,
                        0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_fast_auth_data_exchange_request() {
        let transaction_id = 0x0006;
        let vehicle_temp_pubkey = [0x06; 65];
        let vehicle_id = [0x60; 16];
        let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
        let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
        let iccoa = create_iccoa_fast_auth_pubkey_exchange_request(transaction_id, &[vehicle_temp_pubkey_payload, vehicle_id_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0006,
                pdu_length: 12+1+3+67+18+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    tag: 0xC1,
                    value: vec![
                        0x81, 0x41,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                        0x06,
                        0x83, 0x10,
                        0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
                        0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60
                    ],
                    ..Default::default()
                }
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_fast_auth_data_exchange_response() {
        let transaction_id = 0x0006;
        let status = StatusBuilder::new().success().build();
        let mobile_temp_pubkey = [0x07; 65];
        let mobile_id = [0x70; 16];
        let mobile_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x84).set_value(&mobile_temp_pubkey).build();
        let mobile_id_payload = TLVPayloadBuilder::new().set_tag(0x89).set_value(&mobile_id).build();
        let iccoa = create_iccoa_fast_auth_pubkey_exchange_response(transaction_id, status, &[mobile_temp_pubkey_payload, mobile_id_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0006,
                pdu_length: 12+1+2+3+67+18+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0xC1,
                    value: vec![
                        0x84, 0x41,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        0x07,
                        0x89, 0x10,
                        0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70,
                        0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_fast_auth_request() {
        let transaction_id = 0x0007;
        let vehicle_fast_auth_data = [0x08; 16];
        let vehicle_fast_auth_data_payload = TLVPayloadBuilder::new().set_tag(0x88).set_value(&vehicle_fast_auth_data).build();
        let iccoa = create_iccoa_fast_auth_request(transaction_id, &[vehicle_fast_auth_data_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0007,
                pdu_length: 12+1+3+18+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
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
                        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
                        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_fast_auth_response() {
        let transaction_id = 0x0007;
        let status = StatusBuilder::new().success().build();
        let iccoa = create_iccoa_fast_auth_response(transaction_id, status).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0007,
                pdu_length: 12+1+2+3+8,
                mark: Mark {
                    encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::AUTH,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0xC2,
                    value: vec![],
                },
            },
            mac: [0x00; 8],
        });
    }
}