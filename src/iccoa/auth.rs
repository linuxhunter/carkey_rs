use super::objects::{ICCOA, Mark, PacketType, MessageType, EncryptType, create_iccoa_header, create_iccoa_body_message_data, create_iccoa_body, create_iccoa};
use super::errors::*;

lazy_static! {
    static ref VEHICLE_TEMP_PUBKEY_LENGTH: usize = 65;
    static ref VEHICLE_ID_LENGTH: usize = 16;
    static ref MOBILE_TEMP_PUBKEY_LENGTH: usize = 65;
    static ref MOBILE_ID_LENGTH: usize = 16;
    static ref VEHICLE_SIGNATURE_LENGTH: usize = 64;
    static ref MOBILE_SIGNATURE_LENGTH: usize = 64;
    static ref VEHICLE_FAST_AUTH_DATA_LENGTH: usize = 16;
}

pub fn create_iccoa_standard_auth_pubkey_exchange_request(transaction_id: u16, vehicle_temp_pubkey: &[u8], vehicle_id: &[u8]) -> Result<ICCOA> {
    if vehicle_temp_pubkey.len() != *VEHICLE_TEMP_PUBKEY_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("vehicle temp pubkey length error".to_string()).into());
    }
    if vehicle_id.len() != *VEHICLE_ID_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("vehicle id length error".to_string()).into());
    }
    let header = create_iccoa_header(
        PacketType::REQUEST_PACKET,
        transaction_id,
        1+88,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut pubkey_exchange_data = Vec::new();
    pubkey_exchange_data.push(0x81);
    pubkey_exchange_data.push(0x43);
    pubkey_exchange_data.append(&mut vehicle_temp_pubkey.to_vec());
    pubkey_exchange_data.push(0x83);
    pubkey_exchange_data.push(0x10);
    pubkey_exchange_data.append(&mut vehicle_id.to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x01,
        &pubkey_exchange_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_pubkey_exchange_response(transaction_id: u16, status: u16, mobile_temp_pubkey: &[u8], mobile_id: &[u8]) -> Result<ICCOA> {
    if mobile_temp_pubkey.len() != *MOBILE_TEMP_PUBKEY_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("mobile temp pubkey length error".to_string()).into());
    }
    if mobile_id.len() != *MOBILE_ID_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("mobile id length error".to_string()).into());
    }
    let header = create_iccoa_header(
        PacketType::REPLY_PACKET,
        transaction_id,
        1+2+88,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut pubkey_exchange_data = Vec::new();
    pubkey_exchange_data.push(0x84);
    pubkey_exchange_data.push(0x43);
    pubkey_exchange_data.append(&mut mobile_temp_pubkey.to_vec());
    pubkey_exchange_data.push(0x89);
    pubkey_exchange_data.push(0x10);
    pubkey_exchange_data.append(&mut mobile_id.to_vec());
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x01,
        &pubkey_exchange_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_request(transaction_id: u16, vehicle_signature: &[u8]) -> Result<ICCOA> {
    if vehicle_signature.len() != *VEHICLE_SIGNATURE_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("vehicle signature length error".to_string()).into());
    }
    let header = create_iccoa_header(
        PacketType::REQUEST_PACKET,
        transaction_id,
        1+69,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut auth_data = Vec::new();
    auth_data.push(0x86);
    auth_data.push(0x40);
    auth_data.append(&mut vehicle_signature.to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x02,
        &auth_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_response(transaction_id: u16, status: u16, mobile_signature: &[u8]) -> Result<ICCOA> {
    if mobile_signature.len() != *MOBILE_SIGNATURE_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("mobile signature length error".to_string()).into());
    }
    let header = create_iccoa_header(
        PacketType::REPLY_PACKET,
        transaction_id,
        1+2+69,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut auth_data = Vec::new();
    auth_data.push(0x87);
    auth_data.push(0x40);
    auth_data.append(&mut mobile_signature.to_vec());
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x02,
        &auth_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_friend_request(transaction_id: u16, friend_key_data_request: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+friend_key_data_request.len() as u16,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut friend_key_data = Vec::new();
    friend_key_data.push(0x71);
    friend_key_data.push(friend_key_data_request.len() as u8);
    friend_key_data.append(&mut friend_key_data_request.to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x03,
        &friend_key_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_friend_response(transaction_id: u16, status: u16, friend_key_shared_info: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+friend_key_shared_info.len() as u16,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut friend_key_data = Vec::new();
    friend_key_data.push(0x71);
    friend_key_data.push(friend_key_shared_info.len() as u8);
    friend_key_data.append(&mut friend_key_shared_info.to_vec());
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x03,
        &friend_key_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_write_request(transaction_id: u16, tag: u8, write_data: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+write_data.len() as u16,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut auth_write_data = Vec::new();
    auth_write_data.push(tag);
    auth_write_data.push(write_data.len() as u8);
    auth_write_data.append(&mut write_data.to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x04,
        &auth_write_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_write_response(transaction_id: u16, status: u16) -> Result<ICCOA> {
    let header = create_iccoa_header(
        PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x04,
        &[],
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_read_request(transaction_id: u16, tag: u8, read_list: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+read_list.len() as u16,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut read_data = Vec::new();
    read_data.push(tag);
    read_data.push(read_list.len() as u8);
    read_data.append(&mut read_list.to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x05,
        &read_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_standard_auth_read_response(transaction_id: u16, status: u16, tag: u8, read_data: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+read_data.len() as u16,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut read_data_buffer = Vec::new();
    read_data_buffer.push(tag);
    read_data_buffer.push(read_data.len() as u8);
    read_data_buffer.append(&mut read_data.to_vec());
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x05,
        &read_data_buffer,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_fast_auth_pubkey_exchange_request(transaction_id: u16, vehicle_temp_pubkey: &[u8], vehicle_id: &[u8]) -> Result<ICCOA> {
    if vehicle_temp_pubkey.len() != *VEHICLE_TEMP_PUBKEY_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("vehicle temp pubkey length error".to_string()).into());
    }
    if vehicle_id.len() != *VEHICLE_ID_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("vehicle id length error".to_string()).into());
    }
    let header = create_iccoa_header(
        PacketType::REQUEST_PACKET,
        transaction_id,
        1+88,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        },
    );

    let mut pubkey_exchange_data = Vec::new();
    pubkey_exchange_data.push(0x81);
    pubkey_exchange_data.push(0x41);
    pubkey_exchange_data.append(&mut vehicle_temp_pubkey.to_vec());
    pubkey_exchange_data.push(0x83);
    pubkey_exchange_data.push(0x10);
    pubkey_exchange_data.append(&mut vehicle_id.to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0xC1,
        &pubkey_exchange_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_fast_auth_pubkey_exchange_response(transaction_id: u16, status: u16, mobile_temp_pubkey: &[u8], mobile_id: &[u8]) -> Result<ICCOA> {
    if mobile_temp_pubkey.len() != *MOBILE_TEMP_PUBKEY_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("mobile temp pubkey length error".to_string()).into());
    }
    if mobile_id.len() != *MOBILE_ID_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("mobile id length error".to_string()).into());
    }
    let header = create_iccoa_header(
        PacketType::REPLY_PACKET,
        transaction_id,
        1+2+88,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut pubkey_exchange_data = Vec::new();
    pubkey_exchange_data.push(0x84);
    pubkey_exchange_data.push(0x43);
    pubkey_exchange_data.append(&mut mobile_temp_pubkey.to_vec());
    pubkey_exchange_data.push(0x89);
    pubkey_exchange_data.push(0x10);
    pubkey_exchange_data.append(&mut mobile_id.to_vec());
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0xC1,
        &pubkey_exchange_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_fast_auth_request(transaction_id: u16, vehicle_fast_auth_data: &[u8]) -> Result<ICCOA> {
    if vehicle_fast_auth_data.len() != *VEHICLE_FAST_AUTH_DATA_LENGTH {
        return Err(ErrorKind::ICCOAAuthError("fast auth data length error".to_string()).into());
    }
    let header = create_iccoa_header(
        PacketType::REQUEST_PACKET,
        transaction_id,
        1+19,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );
    let mut fast_auth_data = Vec::new();
    fast_auth_data.push(0x88);
    fast_auth_data.push(vehicle_fast_auth_data.len() as u8);
    fast_auth_data.append(&mut vehicle_fast_auth_data.to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0xC2,
        &fast_auth_data,
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_fast_auth_response(transaction_id: u16, status: u16) -> Result<ICCOA> {
    let header = create_iccoa_header(
        PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3,
        Mark {
            encrypt_type: EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0xC2,
        &[],
    );
    let body = create_iccoa_body(
        MessageType::AUTH,
        message_data,
    );
    
    Ok(create_iccoa(header, body))
}

#[cfg(test)]
mod tests {
    use crate::iccoa::objects::{Header, Body, MessageData};
    use super::*;

    #[test]
    fn test_standard_auth_data_exchange_request() {
        let transaction_id = 0x0001;
        let vehicle_temp_pubkey = [0x01; 65];
        let vehicle_id = [0x10; 16];
        let iccoa = create_iccoa_standard_auth_pubkey_exchange_request(transaction_id, &vehicle_temp_pubkey, &vehicle_id).unwrap();
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
                        129, 67, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 131, 16, 16, 16, 16,
                        16, 16, 16, 16, 16, 16, 16, 16,
                        16, 16, 16, 16, 16
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
        let status = 0x0000;
        let mobile_temp_pubkey = [0x02; 65];
        let mobile_id = [0x20; 16];
        let iccoa = create_iccoa_standard_auth_pubkey_exchange_response(transaction_id, status, &mobile_temp_pubkey, &mobile_id).unwrap();
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
                    status: 0x0000,
                    tag: 0x01,
                    value: vec![
                        132, 67, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 2, 2, 2, 2, 2,
                        2, 2, 2, 137, 16, 32, 32, 32,
                        32, 32, 32, 32, 32, 32, 32, 32,
                        32, 32, 32, 32, 32
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
        let iccoa = create_iccoa_standard_auth_request(transaction_id, &vehicle_signature).unwrap();
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
                        134, 64, 3, 3, 3, 3, 3, 3,
                        3, 3, 3, 3, 3, 3, 3, 3,
                        3, 3, 3, 3, 3, 3, 3, 3,
                        3, 3, 3, 3, 3, 3, 3, 3,
                        3, 3, 3, 3, 3, 3, 3, 3,
                        3, 3, 3, 3, 3, 3, 3, 3,
                        3, 3, 3, 3, 3, 3, 3, 3,
                        3, 3, 3, 3, 3, 3, 3, 3,
                        3, 3
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
        let status = 0x0000;
        let mobile_signature = [0x30; 64];
        let iccoa = create_iccoa_standard_auth_response(transaction_id, status, &mobile_signature).unwrap();
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
                    status: 0x0000,
                    tag: 0x02,
                    value: vec![
                        135, 64, 48, 48, 48, 48, 48, 48,
                        48, 48, 48, 48, 48, 48, 48, 48,
                        48, 48, 48, 48, 48, 48, 48, 48,
                        48, 48, 48, 48, 48, 48, 48, 48,
                        48, 48, 48, 48, 48, 48, 48, 48,
                        48, 48, 48, 48, 48, 48, 48, 48,
                        48, 48, 48, 48, 48, 48, 48, 48,
                        48, 48, 48, 48, 48, 48, 48, 48,
                        48, 48
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
        let iccoa = create_iccoa_standard_auth_friend_request(transaction_id, &friend_key_data).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0003,
                pdu_length: 12+1+3+friend_key_data.len() as u16+8,
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
                        113, 64, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4, 4, 4, 4, 4, 4, 4,
                        4, 4
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
        let status = 0x0000;
        let friend_key_shared_info = [0x40; 64];
        let iccoa = create_iccoa_standard_auth_friend_response(transaction_id, status, &friend_key_shared_info).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0003,
                pdu_length: 12+1+2+3+friend_key_shared_info.len() as u16+8,
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
                    status: 0x0000,
                    tag: 0x03,
                    value: vec![
                        113, 64, 64, 64, 64, 64, 64, 64,
                        64, 64, 64, 64, 64, 64, 64, 64,
                        64, 64, 64, 64, 64, 64, 64, 64,
                        64, 64, 64, 64, 64, 64, 64, 64,
                        64, 64, 64, 64, 64, 64, 64, 64,
                        64, 64, 64, 64, 64, 64, 64, 64,
                        64, 64, 64, 64, 64, 64, 64, 64,
                        64, 64, 64, 64, 64, 64, 64, 64,
                        64, 64
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_write_request() {
        let transaction_id = 0x0004;
        let tag = 0x01;
        let write_data = [0x05; 32];
        let iccoa = create_iccoa_standard_auth_write_request(transaction_id, tag, &write_data).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+3+write_data.len() as u16+8,
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
                        1, 32, 5, 5, 5, 5, 5, 5,
                        5, 5, 5, 5, 5, 5, 5, 5,
                        5, 5, 5, 5, 5, 5, 5, 5,
                        5, 5, 5, 5, 5, 5, 5, 5,
                        5, 5
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
        let status = 0x0000;
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
                    status: 0x0000,
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
        let tag = 0x01;
        let read_list = vec![0x01, 0x02, 0x03];
        let iccoa = create_iccoa_standard_auth_read_request(transaction_id, tag, &read_list).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+read_list.len() as u16+8,
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
                        1, 3, 1, 2, 3
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
        let status = 0x0000;
        let tag = 0x01;
        let read_data = [0x50; 32];
        let iccoa = create_iccoa_standard_auth_read_response(transaction_id, status, tag, &read_data).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0005,
                pdu_length: 12+1+2+3+read_data.len() as u16+8,
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
                    status: 0x0000,
                    tag: 0x05,
                    value: vec![
                        1, 32, 80, 80, 80, 80, 80, 80,
                        80, 80, 80, 80, 80, 80, 80, 80,
                        80, 80, 80, 80, 80, 80, 80, 80,
                        80, 80, 80, 80, 80, 80, 80, 80,
                        80, 80
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
        let iccoa = create_iccoa_fast_auth_pubkey_exchange_request(transaction_id, &vehicle_temp_pubkey, &vehicle_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0006,
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
                    tag: 0xC1,
                    value: vec![
                        129, 65, 6, 6, 6, 6, 6, 6,
                        6, 6, 6, 6, 6, 6, 6, 6,
                        6, 6, 6, 6, 6, 6, 6, 6,
                        6, 6, 6, 6, 6, 6, 6, 6,
                        6, 6, 6, 6, 6, 6, 6, 6,
                        6, 6, 6, 6, 6, 6, 6, 6,
                        6, 6, 6, 6, 6, 6, 6, 6,
                        6, 6, 6, 6, 6, 6, 6, 6, 
                        6, 6, 6, 131, 16, 96, 96, 96,
                        96, 96, 96, 96, 96, 96, 96, 96,
                        96, 96, 96, 96, 96
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
        let status = 0x0000;
        let mobile_temp_pubkey = [0x07; 65];
        let mobile_id = [0x70; 16];
        let iccoa = create_iccoa_fast_auth_pubkey_exchange_response(transaction_id, status, &mobile_temp_pubkey, &mobile_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0006,
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
                    status: 0x0000,
                    tag: 0xC1,
                    value: vec![
                        132, 67, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 7, 7, 7, 7, 7,
                        7, 7, 7, 137, 16, 112, 112, 112,
                        112, 112, 112, 112, 112, 112, 112, 112,
                        112, 112, 112, 112, 112
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
        let iccoa = create_iccoa_fast_auth_request(transaction_id, &vehicle_fast_auth_data).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0007,
                pdu_length: 12+1+19+8,
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
                        136, 16, 8, 8, 8, 8, 8, 8,
                        8, 8, 8, 8, 8, 8, 8, 8,
                        8, 8
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
        let status = 0x0000;
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
                    status: 0x0000,
                    tag: 0xC2,
                    value: vec![],
                },
            },
            mac: [0x00; 8],
        });
    }
}