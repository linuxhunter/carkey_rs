use log::info;
use crate::iccoa::{utils::{encrypt_aes_128_cbc, decrypt_aes_128_cbc, get_default_iv}, TLVPayload, TLVPayloadBuilder, auth};

use super::super::{errors::*, objects, objects::{ICCOA, create_iccoa_header, Mark, create_iccoa_body_message_data, MessageType, create_iccoa_body, create_iccoa}, status::{StatusBuilder, Status}};

lazy_static! {
    static ref RKE_COMMAND_REQUEST_DATA_LENGTH: usize = 5;
    static ref RKE_COMMAND_RESPONSE_DATA_LENGTH_MINIUM: usize = 4;
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct RKECommandRequest {
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

        let key = auth::get_auth_key_enc();
        let iv = get_default_iv();
        encrypt_aes_128_cbc(&key, &serialized_data, &iv).unwrap()
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let key = auth::get_auth_key_enc();
        let iv = get_default_iv();
        let plain_text = decrypt_aes_128_cbc(&key, buffer, &iv)?;
        if plain_text.len() != *RKE_COMMAND_REQUEST_DATA_LENGTH {
            return Err(ErrorKind::ICCOACommandError("rke command request data length error".to_string()).into());
        }
        let mut request = RKECommandRequest::new();
        request.event_id = u16::from_be_bytes(plain_text[0..2].try_into()
            .map_err(|e| ErrorKind::ICCOACommandError(format!("deserialize event id error: {:?}", e)))?);
        request.function_id = u16::from_be_bytes(plain_text[2..4].try_into()
            .map_err(|e| ErrorKind::ICCOACommandError(format!("deserialize function id error: {:?}", e)))?);
        request.action_id = plain_text[4];

        Ok(request)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RKECommandResponse {
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
        response.event_id = u16::from_be_bytes(buffer[0..2].try_into()
            .map_err(|e| ErrorKind::ICCOACommandError(format!("deserialize event id error: {:?}", e)))?);
        response.tag = buffer[2];
        let length = buffer[3] as usize;
        response.value = buffer[4..4+length].to_vec();

        Ok(response)
    }
}

fn create_iccoa_rke_command_request(transaction_id: u16, request: RKECommandRequest) -> Result<ICCOA> {
    let serialized_request = request.serialize();
    let mut mark = Mark::new();
    mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
    mark.set_more_fragment(false);
    mark.set_fragment_offset(0x0000);
    let header = create_iccoa_header(
        objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+serialized_request.len() as u16,
        mark
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
    let mut mark = Mark::new();
    mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
    mark.set_more_fragment(false);
    mark.set_fragment_offset(0x0000);
    let header = create_iccoa_header(
        objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+serialized_response.len() as u16,
        mark
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

pub fn handle_iccoa_rke_command(iccoa: &ICCOA) -> Result<TLVPayload> {
    //handle rke command from iccoa object
    let rke_command = RKECommandRequest::deserialize(iccoa.get_body().get_message_data().get_value())?;
    info!("[RKE Command]:");
    info!("\tevent_id: {:02X?}", rke_command.get_event_id());
    info!("\tfunction_id: {:02X?}", rke_command.get_function_id());
    info!("\taction_id: {:02X?}", rke_command.get_action_id());
    Ok(TLVPayloadBuilder::new().set_tag(0x00).set_value(&[0x00]).build())
}

pub fn handle_iccoa_rke_command_request_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    //handle rke command with request
    let rke_command_response = handle_iccoa_rke_command(iccoa)?;
    //create rke command response
    let transaction_id = 0x0000;
    let event_id = RKECommandRequest::deserialize(iccoa.get_body().get_message_data().get_value())?.get_event_id();
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

#[cfg(test)]
mod tests {
    use crate::iccoa::objects::{Header, Body, PacketType, MessageData};

    use super::*;

    #[test]
    fn test_central_lock_request() {
        let transaction_id = 0x0001;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_central_lock_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0001,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_central_unlock_requet() {
        let transaction_id = 0x0002;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_central_unlock_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0002,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_electric_window_close_request() {
        let transaction_id = 0x0003;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_window_close_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0003,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_electric_window_open_request() {
        let transaction_id = 0x0004;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_window_open_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0004,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value(),
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_electric_sunroof_close_request() {
        let transaction_id = 0x0005;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_sunroof_close_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0005,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_electric_sunroof_open_request() {
        let transaction_id = 0x0006;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_electric_sunroof_open_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0006,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_trunk_close_request() {
        let transaction_id = 0x0007;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_trunk_close_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0007,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_trunk_open_request() {
        let transaction_id = 0x0008;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_trunk_open_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0008,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_cancel_search_car_request() {
        let transaction_id = 0x0009;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_cancel_search_car_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0009,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_honking_search_car_request() {
        let transaction_id = 0x000A;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_konking_search_car_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x000A,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_flashing_search_car_request() {
        let transaction_id = 0x000B;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_flashing_search_car_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x000B,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_honking_and_flashing_search_car_request() {
        let transaction_id = 0x000C;
        let event_id = 0xFFFF;
        let iccoa = create_iccoa_rke_honking_and_flashing_search_car_request(transaction_id, event_id).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x000C,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_rke_command_response() {
        let transaction_id = 0x000D;
        let event_id = 0xFFFF;
        let status = StatusBuilder::new().success().build();
        let tag = 0x00;
        let value = vec![0x00];
        let iccoa = create_iccoa_rke_response(transaction_id, status, event_id, tag, &value).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_AFTER_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x000D,
            iccoa.get_header().get_pdu_length()-20,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0x01,
            iccoa.get_body().get_message_data().get_value()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
}
