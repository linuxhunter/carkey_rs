use std::fmt::{Display, Formatter};
use crate::iccoa2::errors::*;
use super::common;

const SELECT_CLA: u8 = 0x00;
const SELECT_INS: u8 = 0xA4;
const SELECT_P1: u8 = 0x04;
const SELECT_P2: u8 = 0x00;
const SELECT_LE: u8 = 0x00;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CommandApduSelect {
    aid: Vec<u8>,
}

impl CommandApduSelect {
    pub fn new(aid: &[u8]) -> Self {
        CommandApduSelect {
            aid: aid.to_vec(),
        }
    }
    pub fn get_aid(&self) -> &[u8] {
        &self.aid
    }
    pub fn set_aid(&mut self, aid: &[u8]) {
        self.aid = aid.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            SELECT_CLA,
            SELECT_INS,
            SELECT_P1,
            SELECT_P2,
        );
        let trailer = common::CommandApduTrailer::new(
            Some(self.aid.clone()),
            Some(SELECT_LE),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let command_apdu = common::CommandApdu::deserialize(data)?;
        let header = command_apdu.get_header();
        if header.get_cla() != SELECT_CLA {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu CLA error")).into());
        }
        if header.get_ins() != SELECT_INS {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu INS error")).into());
        }
        if header.get_p1() != SELECT_P1 {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu P1 error")).into());
        }
        if header.get_p2() != SELECT_P2 {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu P2 error")).into());
        }
        let trailer = command_apdu.get_trailer();
        if let Some(trailer) = trailer {
            if let Some(le) = trailer.get_le() {
                if *le != SELECT_LE {
                    Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu Le error")).into())
                } else {
                    if let Some(data) = trailer.get_data() {
                        Ok(CommandApduSelect::new(data))
                    } else {
                        Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu Data is NULL")).into())
                    }
                }
            } else {
                Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu Le is NULL")).into())
            }
        } else {
            Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT Apdu trailer is NULL")).into())
        }
    }
}

impl Display for CommandApduSelect {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct ResponseApduSelect {
    version: u16,
    status: common::ResponseApduTrailer,
}

impl ResponseApduSelect {
    pub fn new(version: u16, status: common::ResponseApduTrailer) -> Self {
        ResponseApduSelect {
            version,
            status,
        }
    }
    pub fn get_version(&self) -> u16 {
        self.version
    }
    pub fn set_version(&mut self, version: u16) {
        self.version = version;
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        common::ResponseApdu::new(Some(self.version.to_be_bytes().to_vec()), self.status).serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let response = common::ResponseApdu::deserialize(data)?;
        let status = response.get_trailer();
        if let Some(body) = response.get_body() {
            let version = u16::from_be_bytes(
                (&body[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize SELECT version error: {}", e)))?
            );
            Ok(ResponseApduSelect::new(version, *status))
        } else {
            Err(ErrorKind::ApduInstructionErr(format!("deserialize SELECT response version is NULL")).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::iccoa2::instructions::common::{ResponseApdu, ResponseApduTrailer};
    use super::*;

    #[test]
    fn test_create_select_request() {
        let aid = vec![0x10, 0x20, 0x30, 0x40];
        let request = CommandApduSelect::new(aid.as_ref());
        assert_eq!(request.get_aid(), &aid);
    }
    #[test]
    fn test_update_select_request() {
        let aid = vec![0x10, 0x20, 0x30, 0x40];
        let mut request = CommandApduSelect::new(aid.as_ref());
        let updated_aid = vec![0x11, 0x21, 0x31, 0x41];
        request.set_aid(updated_aid.as_ref());
        assert_eq!(request.get_aid(), &updated_aid);
    }
    #[test]
    fn test_select_request_serialize() {
        let aid = vec![0x10, 0x20, 0x30, 0x40];
        let request = CommandApduSelect::new(aid.as_ref());
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(serialized_request, vec![0x00, 0xA4, 0x04, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40, 0x00]);
    }
    #[test]
    fn test_select_request_deserialize() {
        let data = vec![0x00, 0xA4, 0x04, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40, 0x00];
        let request = CommandApduSelect::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.get_aid(), &vec![0x10, 0x20, 0x30, 0x40]);
    }
    #[test]
    fn test_create_select_response() {
        let version = 0x10;
        let sw1 = 0x90;
        let sw2 = 0x00;
        let status = ResponseApduTrailer::new(sw1, sw2);
        let response = ResponseApduSelect::new(version, status);
        assert_eq!(response.get_version(), version);
        assert_eq!(response.get_status(), &status);
        assert_eq!(response.get_status().is_success(), true);
    }
    #[test]
    fn test_update_select_response() {
        let version = 0x1010;
        let sw1 = 0x90;
        let sw2 = 0x00;
        let status = ResponseApduTrailer::new(sw1, sw2);
        let mut response = ResponseApduSelect::new(version, status);
        let new_version = 0x2020;
        let new_sw1 = 0x61;
        let new_sw2 = 0x10;
        let new_status = ResponseApduTrailer::new(new_sw1, new_sw2);
        response.set_version(new_version);
        response.set_status(new_status);
        assert_eq!(response.get_version(), new_version);
        assert_eq!(response.get_status(), &new_status);
        assert_eq!(response.get_status().is_success(), false);
        assert_eq!(response.get_status().has_remain(), true);
        assert_eq!(response.get_status().remain_bytes(), new_sw2);
    }
    #[test]
    fn test_select_response_serialize() {
        let version = 0x1010;
        let sw1 = 0x90;
        let sw2 = 0x00;
        let status = ResponseApduTrailer::new(sw1, sw2);
        let response = ResponseApduSelect::new(version, status);
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x10, 0x10, 0x90, 0x00]);
    }
    #[test]
    fn test_select_response_deserialize() {
        let data = vec![0x10, 0x10, 0x90, 0x00];
        let response = ResponseApduSelect::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_version(), 0x1010);
        assert_eq!(response.get_status(), &ResponseApduTrailer::new(0x90, 0x00));
        assert_eq!(response.get_status().is_success(), true);
    }
}
