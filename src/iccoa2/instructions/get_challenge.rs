use std::fmt::{Display, Formatter};
use crate::iccoa2::errors::*;
use super::common;

#[allow(dead_code)]
const GET_CHALLENGE_CLA: u8 = 0x00;
#[allow(dead_code)]
const GET_CHALLENGE_INS: u8 = 0x84;
#[allow(dead_code)]
const GET_CHALLENGE_P1: u8 = 0x00;
#[allow(dead_code)]
const GET_CHALLENGE_P2: u8 = 0x00;
#[allow(dead_code)]
const GET_CHALLENGE_LE: u8 = 0x08;

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduGetChallenge();

#[allow(dead_code)]
impl CommandApduGetChallenge {
    pub fn new() -> Self {
        CommandApduGetChallenge()
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            GET_CHALLENGE_CLA,
            GET_CHALLENGE_INS,
            GET_CHALLENGE_P1,
            GET_CHALLENGE_P2,
        );
        let trailer = common::CommandApduTrailer::new(
            None,
            Some(GET_CHALLENGE_LE),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let apdu_request = common::CommandApdu::deserialize(data)?;
        let header = apdu_request.get_header();
        let trailer = apdu_request.get_trailer()
            .ok_or(format!("deserialize trailer is NULL"))?;
        if header.get_cla() != GET_CHALLENGE_CLA ||
            header.get_ins() != GET_CHALLENGE_INS ||
            header.get_p1() != GET_CHALLENGE_P1 ||
            header.get_p2() != GET_CHALLENGE_P2 {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize header error")).into());
        }
        if trailer.get_data().is_some() ||
            trailer.get_le() != Some(&GET_CHALLENGE_LE) {
            return  Err(ErrorKind::ApduInstructionErr(format!("deserialize trailer error")).into());
        }
        Ok(CommandApduGetChallenge::new())
    }
}

impl Display for CommandApduGetChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Get Challenge Request")
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduGetChallenge {
    random: Vec<u8>,
    status: common::ResponseApduTrailer,
}

#[allow(dead_code)]
impl ResponseApduGetChallenge {
    pub fn new(random: &[u8], status: common::ResponseApduTrailer) -> Self {
        ResponseApduGetChallenge {
            random: random.to_vec(),
            status,
        }
    }
    pub fn get_random(&self) -> &[u8] {
        &self.random
    }
    pub fn set_random(&mut self, random: &[u8]) {
        self.random = random.to_vec();
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let response = common::ResponseApdu::new(
            Some(self.get_random().to_vec()),
            self.get_status().clone(),
        );
        response.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let response = common::ResponseApdu::deserialize(data)?;
        let body = response.get_body().ok_or(format!("deserialize body is NULL"))?;
        let trailer = response.get_trailer();
        Ok(ResponseApduGetChallenge::new(
            body,
            *trailer,
        ))
    }
}

impl Display for ResponseApduGetChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Random: {:02X?}", self.get_random())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_challenge_serialize() {
        let request = CommandApduGetChallenge::new();
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x00, 0x084, 0x00, 0x00,
                0x08,
            ],
        );
    }
    #[test]
    fn test_get_challenge_deserialize() {
        let data = vec![
            0x00, 0x084, 0x00, 0x00,
            0x08,
        ];
        let apdu_request = CommandApduGetChallenge::deserialize(data.as_ref());
        assert!(apdu_request.is_ok());
        let apdu_request = apdu_request.unwrap();
        assert_eq!(apdu_request, CommandApduGetChallenge::new());
    }
    #[test]
    fn test_create_get_challenge_response() {
        let random = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduGetChallenge::new(
            random.as_ref(),
            status,
        );
        assert_eq!(response.get_random(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_get_challenge_response() {
        let random = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut response = ResponseApduGetChallenge::new(
            random.as_ref(),
            status,
        );
        let new_random = vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let new_status = common::ResponseApduTrailer::new(0x61, 0x10);
        response.set_random(new_random.as_ref());
        response.set_status(new_status);
        assert_eq!(response.get_random(), &vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x61, 0x10));
    }
    #[test]
    fn test_get_challenge_response_serialize() {
        let random = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduGetChallenge::new(
            random.as_ref(),
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
    fn test_get_challenge_response_deserialize() {
        let data = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x90, 0x00,
        ];
        let response = ResponseApduGetChallenge::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_random(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
