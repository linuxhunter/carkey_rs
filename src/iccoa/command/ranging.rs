use log::debug;
use crate::iccoa::TLVPayloadBuilder;

use super::super::errors::*;
use super::super::objects::{create_iccoa_header, Mark, create_iccoa_body_message_data, create_iccoa_body, create_iccoa};
use super::super::status::{StatusBuilder, Status};
use super::super::{TLVPayload, objects, objects::ICCOA};


pub fn create_iccoa_ranging_request(transaction_id: u16, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += 2+p.value.len();
        payload_data.append(&mut p.serialize());
    });

    let mut mark = Mark::new();
    mark.set_encrypt_type(objects::EncryptType::NO_ENCRYPT);
    mark.set_more_fragment(false);
    mark.set_fragment_offset(0x0000);
    let header = create_iccoa_header(
        objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+payload_length as u16,
        mark
    );

    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        objects::MessageType::COMMAND,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

#[allow(dead_code)]
pub fn create_iccoa_ranging_response(transaction_id: u16, status: Status, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += 2+p.value.len();
        payload_data.append(&mut p.serialize());
    });

    let mut mark = Mark::new();
    mark.set_encrypt_type(objects::EncryptType::NO_ENCRYPT);
    mark.set_more_fragment(false);
    mark.set_fragment_offset(0x0000);
    let header = create_iccoa_header(
        objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+payload_length as u16,
        mark
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        objects::MessageType::COMMAND,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_ranging_request_package() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let ranging_type = 0x01;
    let ranging_type_payload = TLVPayloadBuilder::new().set_tag(0x01).set_value(&[ranging_type]).build();
    let iccoa = create_iccoa_ranging_request(transaction_id, 0x02, &[ranging_type_payload])?;
    Ok(iccoa)
}

pub fn handle_iccoa_ranging_command_response_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    let ranging_result= TLVPayload::deserialize(iccoa.get_body().get_message_data().get_value())?;
    if ranging_result.get_tag() == 0x00 {
        debug!("Ranging Success!");
    } else {
        debug!("Ranging Failure");
    }
    Err(ErrorKind::ICCOACommandError("Ranging Command completed".to_string()).into())
}

#[cfg(test)]
mod tests {
    use crate::iccoa::{TLVPayloadBuilder, objects::{Header, PacketType, Body, MessageType, MessageData}};

    use super::*;

    #[test]
    fn test_start_ranging_request() {
        let transaction_id = 0x000E;
        let ranging_type = 0x01;
        let ranging_type_payload = TLVPayloadBuilder::new().set_tag(0x01).set_value(&[ranging_type]).build();
        let iccoa = create_iccoa_ranging_request(transaction_id, 0x02, &[ranging_type_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::NO_ENCRYPT);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x000E,
            1+3+3,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x02,
           vec![
                0x01, 0x01, 0x01
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_end_ranging_request() {
        let transaction_id = 0x000F;
        let end_ranging_payload = TLVPayloadBuilder::new().set_tag(0x02).set_value(&[0x00]).build();
        let iccoa = create_iccoa_ranging_request(transaction_id, 0x02, &[end_ranging_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::NO_ENCRYPT);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x000F,
            1+3+3,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x02,
           vec![
                0x02, 0x01, 0x00
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_ranging_response() {
        let transaction_id = 0x0010;
        let status = StatusBuilder::new().success().build();
        let ranging_value = 0x00;
        let ranging_value_payload = TLVPayloadBuilder::new().set_tag(0x00).set_value(&[ranging_value]).build();
        let iccoa = create_iccoa_ranging_response(transaction_id, status, 0x02, &[ranging_value_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::NO_ENCRYPT);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0010,
            1+2+3+3,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0x02,
            vec![
                0x00, 0x01, 0x00
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::COMMAND,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
}