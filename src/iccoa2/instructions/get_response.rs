use std::fmt::{Display, Formatter};
use crate::iccoa2::errors::*;
use super::common;

#[allow(dead_code)]
const GET_RESPONSE_CLA: u8 = 0x00;
#[allow(dead_code)]
const GET_RESPONSE_INS: u8 = 0xC0;
#[allow(dead_code)]
const GET_RESPONSE_P1: u8 = 0x00;
#[allow(dead_code)]
const GET_RESPONSE_P2: u8 = 0x00;
#[allow(dead_code)]
const GET_RESPONSE_LE: u8 = 0x00;

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduGetResponse();

#[allow(dead_code)]
impl CommandApduGetResponse {
    pub fn new() -> Self {
        CommandApduGetResponse()
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            GET_RESPONSE_CLA,
            GET_RESPONSE_INS,
            GET_RESPONSE_P1,
            GET_RESPONSE_P2,
        );
        let trailer = common::CommandApduTrailer::new(
            None,
            Some(GET_RESPONSE_LE),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let apdu_request = common::CommandApdu::deserialize(data)?;
        let header = apdu_request.get_header();
        let trailer = apdu_request.get_trailer().ok_or(format!("deserialize trailer is NULL"))?;
        if header.get_cla() != GET_RESPONSE_CLA ||
            header.get_ins() != GET_RESPONSE_INS ||
            header.get_p1() != GET_RESPONSE_P1 ||
            header.get_p2() != GET_RESPONSE_P2 ||
            trailer.get_le().is_none() ||
            *trailer.get_le().unwrap() != GET_RESPONSE_LE {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize header and trailer error")).into());
        }
        Ok(CommandApduGetResponse::new())
    }
}

impl Display for CommandApduGetResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Get Response request")
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduGetResponse {
    data: Vec<u8>,
    status: common::ResponseApduTrailer,
}

#[allow(dead_code)]
impl ResponseApduGetResponse {
    pub fn new(data: &[u8], status: common::ResponseApduTrailer) -> Self {
        ResponseApduGetResponse {
            data: data.to_vec(),
            status,
        }
    }
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let response = common::ResponseApdu::new(
            Some(self.get_data().to_vec()),
            self.get_status().clone(),
        );
        response.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let apdu_response = common::ResponseApdu::deserialize(data)?;
        let body = apdu_response.get_body().ok_or(format!("deserialize body is NULL"))?;
        let trailer = apdu_response.get_trailer();
        Ok(ResponseApduGetResponse::new(body, *trailer))
    }
}

impl Display for ResponseApduGetResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "response data: {:02X?}", self.get_data())
    }
}

#[cfg(test)]
mod tests {
    use  super::*;

    #[test]
    fn test_get_response_request_serialize() {
        let request = CommandApduGetResponse::new();
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x00, 0xC0, 0x00, 0x00,
                0x00,
            ],
        );
    }
    #[test]
    fn test_get_response_request_deserialize() {
        let data = vec![
            0x00, 0xC0, 0x00, 0x00,
            0x00,
        ];
        let request = CommandApduGetResponse::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request, CommandApduGetResponse::new());
    }
    #[test]
    fn test_create_get_response_response() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduGetResponse::new(
            data.as_ref(),
            status,
        );
        assert_eq!(response.get_data(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_get_response_response() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut response = ResponseApduGetResponse::new(
            data.as_ref(),
            status,
        );
        let new_data = vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let new_status = common::ResponseApduTrailer::new(0x61, 0x10);
        response.set_data(new_data.as_ref());
        response.set_status(new_status);
        assert_eq!(response.get_data(), &vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x61, 0x10));
    }
    #[test]
    fn test_get_response_response_serialize() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduGetResponse::new(
            data.as_ref(),
            status,
        );
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(
            serialized_response,
            vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_get_response_response_deserialize() {
        let data = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x90, 0x00,
        ];
        let response = ResponseApduGetResponse::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_data(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
