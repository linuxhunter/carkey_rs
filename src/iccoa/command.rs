use super::{errors::*, objects::{ICCOA, create_iccoa_header, Mark, create_iccoa_body_message_data, MessageType, create_iccoa_body, create_iccoa}, status::{StatusBuilder, Status}};

lazy_static! {
    static ref RKE_COMMAND_REQUEST_DATA_LENGTH: usize = 5;
    static ref RKE_COMMAND_RESPONSE_DATA_LENGTH_MINIUM: usize = 4;
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct RKECommandRequest {
    event_id: u16,
    function_id: u16,
    action_id: u8,
}

impl RKECommandRequest {
    pub fn new() -> Self {
        RKECommandRequest {
            ..Default::default()
        }
    }
    pub fn set_event_id(&mut self, event_id: u16) {
        self.event_id = event_id;
    }
    pub fn get_event_id(&self) -> u16 {
        self.event_id
    }
    pub fn set_function_id(&mut self, function_id: u16) {
        self.function_id = function_id;
    }
    pub fn get_function_id(&self) -> u16 {
        self.function_id
    }
    pub fn set_action_id(&mut self, action_id: u8) {
        self.action_id = action_id;
    }
    pub fn get_action_id(&self) -> u8 {
        self.action_id
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data = Vec::new();
        serialized_data.append(&mut self.event_id.to_be_bytes().to_vec());
        serialized_data.append(&mut self.function_id.to_be_bytes().to_vec());
        serialized_data.push(self.action_id);

        serialized_data
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() != *RKE_COMMAND_REQUEST_DATA_LENGTH {
            return Err(ErrorKind::ICCOACommandError("rke command request data length error".to_string()).into());
        }
        let mut request = RKECommandRequest::new();
        request.event_id = u16::from_be_bytes(buffer[0..2].try_into().map_err(|_| ErrorKind::ICCOACommandError("deserialize event id error".to_string()))?);
        request.function_id = u16::from_be_bytes(buffer[2..4].try_into().map_err(|_| ErrorKind::ICCOACommandError("deserialize function id error".to_string()))?);
        request.action_id = buffer[5];

        Ok(request)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
struct RKECommandResponse {
    event_id: u16,
    tag: u8,
    value: Vec<u8>,
}

impl RKECommandResponse {
    pub fn new() -> Self {
        RKECommandResponse {
            ..Default::default()
        }
    }
    pub fn set_event_id(&mut self, evnet_id: u16) {
        self.event_id = evnet_id;
    }
    pub fn get_event_id(&self) -> u16 {
        self.event_id
    }
    pub fn set_tag(&mut self, tag: u8) {
        self.tag = tag;
    }
    pub fn get_tag(&self) -> u8 {
        self.tag
    }
    pub fn set_value(&mut self, value: &[u8]) {
        self.value = value.to_vec();
    }
    pub fn get_value(&self) -> &[u8] {
        &self.value
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data = Vec::new();
        serialized_data.append(&mut self.event_id.to_be_bytes().to_vec());
        serialized_data.push(self.tag);
        serialized_data.push(self.value.len() as u8);
        serialized_data.append(&mut self.value.to_vec());

        serialized_data
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < *RKE_COMMAND_RESPONSE_DATA_LENGTH_MINIUM {
            return Err(ErrorKind::ICCOACommandError("deserialize rke response data length less than minium length".to_string()).into());
        }
        let mut response = RKECommandResponse::new();
        response.event_id = u16::from_be_bytes(buffer[0..2].try_into().map_err(|_| ErrorKind::ICCOACommandError("deserialize event id error".to_string()))?);
        response.tag = buffer[2];
        let length = buffer[3] as usize;
        response.value = buffer[4..4+length].to_vec();

        Ok(response)
    }
}

fn create_iccoa_rke_command_request(transaction_id: u16, request: RKECommandRequest) -> Result<ICCOA> {
    let serialized_request = request.serialize();
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+serialized_request.len() as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_AFTER_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000, 
        },
    );
    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        0x01,
        &serialized_request,
    );
    let body = create_iccoa_body(
        MessageType::COMMAND,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

fn create_iccoa_rke_command_response(transaction_id: u16, status: Status, response: RKECommandResponse) -> Result<ICCOA> {
    let serialized_response = response.serialize();
    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+serialized_response.len() as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_AFTER_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        },
    );
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x01,
        &serialized_response,
    );
    let body = create_iccoa_body(
        MessageType::COMMAND,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

fn create_iccoa_rke_request(transaction_id: u16, event_id: u16, function_id: u16, action_id: u8) -> Result<ICCOA> {
    let mut request = RKECommandRequest::new();
    request.set_event_id(event_id);
    request.set_function_id(function_id);
    request.set_action_id(action_id);
    create_iccoa_rke_command_request(transaction_id, request)
}

pub fn create_iccoa_rke_central_lock_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0001, 0x00)
}

pub fn create_iccoa_rke_central_unlock_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0001, 0x01)
}

pub fn create_iccoa_rke_electric_window_close_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0140, 0x00)
}

pub fn create_iccoa_rke_electric_window_open_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0140, 0x01)
}

pub fn create_iccoa_rke_electric_sunroof_close_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0141, 0x00)
}

pub fn create_iccoa_rke_electric_sunroof_open_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0141, 0x01)
}

pub fn create_iccoa_rke_trunk_close_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0111, 0x00)
}

pub fn create_iccoa_rke_trunk_open_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x0111, 0x01)
}

pub fn create_iccoa_rke_cancel_search_car_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x1000, 0x00)
}

pub fn create_iccoa_rke_konking_search_car_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x1000, 0x01)
}

pub fn create_iccoa_rke_flashing_search_car_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x1000, 0x02)
}

pub fn create_iccoa_rke_honking_and_flashing_search_car_request(transaction_id: u16, event_id: u16) -> Result<ICCOA> {
    create_iccoa_rke_request(transaction_id, event_id, 0x1000, 0x03)
}

pub fn create_iccoa_rke_response(transaction_id: u16, status: Status, event_id: u16, tag: u8, value: &[u8]) -> Result<ICCOA> {
    let mut response = RKECommandResponse::new();
    response.set_event_id(event_id);
    response.set_tag(tag);
    response.set_value(value);
    create_iccoa_rke_command_response(transaction_id, status, response)
}

pub fn create_iccoa_start_ranging_request(transaction_id: u16, ranging_type: u8) -> Result<ICCOA> {
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+3,
        Mark {
            encrypt_type: super::objects::EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );
    let mut ranging_data = Vec::new();
    ranging_data.push(0x01);
    ranging_data.push(0x01);
    ranging_data.push(ranging_type);
    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        0x02,
        &ranging_data,
    );
    let body = create_iccoa_body(
        MessageType::COMMAND,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_end_ranging_request(transaction_id: u16) -> Result<ICCOA> {
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+3,
        Mark {
            encrypt_type: super::objects::EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );
    let mut ranging_data = Vec::new();
    ranging_data.push(0x02);
    ranging_data.push(0x01);
    ranging_data.push(0x00);
    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        0x02,
        &ranging_data,
    );
    let body = create_iccoa_body(
        MessageType::COMMAND,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_ranging_response(transaction_id: u16, status: u16, ranging_value: u8) -> Result<ICCOA> {
    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+3,
        Mark {
            encrypt_type: super::objects::EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );
    let mut ranging_data = Vec::new();
    if ranging_value == 0x00 {
        ranging_data.push(0x00);
    } else {
        ranging_data.push(0x01);
    }
    ranging_data.push(0x01);
    ranging_data.push(ranging_value);
    let message_data = create_iccoa_body_message_data(
        true,
        StatusBuilder::new().success().build(),
        0x02,
        &ranging_data,
    );
    let body = create_iccoa_body(
        MessageType::COMMAND,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

#[cfg(test)]
mod tests {
    use crate::iccoa::objects::{Header, Body, PacketType, MessageData};

    use super::*;

    #[test]
    fn test_central_lock_request() {
        let transaction_id = 0x0001;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_central_lock_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0001,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x00, 0x01, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_central_unlock_requet() {
        let transaction_id = 0x0002;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_central_unlock_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0002,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x00, 0x01, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_electric_window_close_request() {
        let transaction_id = 0x0003;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_window_close_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0003,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x01, 0x40, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_electric_window_open_request() {
        let transaction_id = 0x0004;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_window_open_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x01, 0x40, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_electric_sunroof_close_request() {
        let transaction_id = 0x0005;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_sunroof_close_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x01, 0x41, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_electric_sunroof_open_request() {
        let transaction_id = 0x0006;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_sunroof_open_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0006,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x01, 0x41, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_trunk_close_request() {
        let transaction_id = 0x0007;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_trunk_close_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0007,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x01, 0x11, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_trunk_open_request() {
        let transaction_id = 0x0008;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_trunk_open_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0008,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x01, 0x11, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_cancel_search_car_request() {
        let transaction_id = 0x0009;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_cancel_search_car_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0009,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x10, 0x00, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_honking_search_car_request() {
        let transaction_id = 0x000A;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_konking_search_car_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x000A,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x10, 0x00, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_flashing_search_car_request() {
        let transaction_id = 0x000B;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_flashing_search_car_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x000B,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x10, 0x00, 0x02
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_honking_and_flashing_search_car_request() {
        let transaction_id = 0x000C;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_honking_and_flashing_search_car_request(transaction_id, event_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x000C,
                pdu_length: 12+1+3+5+8,
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
                    tag:0x01,
                    value: vec![
                        0xFF, 0xFF, 0x10, 0x00, 0x03
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_rke_command_response() {
        let transaction_id = 0x000D;
        let event_id = 0xFFFF;
        let status = StatusBuilder::new().success().build();
        let tag = 0x00;
        let value = vec![0x00];
        let iccoa = create_iccoa_rke_response(transaction_id, status, event_id, tag, &value).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x000D,
                pdu_length: 12+1+2+3+4+value.len() as u16+8,
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
    fn test_start_ranging_request() {
        let transaction_id = 0x000E;
        let ranging_type = 0x01;
        let iccoa = create_iccoa_start_ranging_request(transaction_id, ranging_type).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x000E,
                pdu_length: 12+1+3+3+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::COMMAND,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x01, 0x01, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_end_ranging_request() {
        let transaction_id = 0x000F;
        let iccoa = create_iccoa_end_ranging_request(transaction_id).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x000F,
                pdu_length: 12+1+3+3+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::COMMAND,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x02, 0x01, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_ranging_response() {
        let transaction_id = 0x0010;
        let status = 0x0000;
        let ranging_value = 0x00;
        let iccoa = create_iccoa_ranging_response(transaction_id, status, ranging_value).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0010,
                pdu_length: 12+1+2+3+3+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::COMMAND,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x02,
                    value: vec![
                        0x00, 0x01, 0x00
                    ],
                },
            },
            mac: [0x00; 8],
        });
    }
}
