use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::{create_tlv_with_primitive_value, get_tlv_primitive_value, Serde};
use crate::iccoa2::errors::*;
use super::{common, VERSION_TAG};

#[allow(dead_code)]
const SELECT_CLA: u8 = 0x00;
#[allow(dead_code)]
const SELECT_INS: u8 = 0xA4;
#[allow(dead_code)]
const SELECT_P1: u8 = 0x04;
#[allow(dead_code)]
const SELECT_P2: u8 = 0x00;
#[allow(dead_code)]
const SELECT_LE: u8 = 0x00;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CommandApduSelect {
    aid: Vec<u8>,
}

#[allow(dead_code)]
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
}

impl Serde for CommandApduSelect {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
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

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let command_apdu = common::CommandApdu::deserialize(data)?;
        let header = command_apdu.get_header();
        let trailer = command_apdu.get_trailer().ok_or("deserialize trailer is NULL".to_string())?;
        if header.get_cla() != SELECT_CLA ||
            header.get_ins() != SELECT_INS ||
            header.get_p1() != SELECT_P1 ||
            header.get_p2() != SELECT_P2 ||
            trailer.get_le().is_none() ||
            *trailer.get_le().unwrap() != SELECT_LE {
            return Err(ErrorKind::ApduInstructionErr("deserialize SELECT Apdu error".to_string()).into());
        }
        Ok(CommandApduSelect::new(trailer.get_data().unwrap()))
    }
}

impl Display for CommandApduSelect {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.get_aid())
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct ResponseApduSelect {
    version: u16,
    status: common::ResponseApduTrailer,
}

#[allow(dead_code)]
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
}

impl Serde for ResponseApduSelect {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let version_tlv = create_tlv_with_primitive_value(VERSION_TAG, self.get_version().to_be_bytes().as_ref())?;
        common::ResponseApdu::new(Some(version_tlv.to_vec()), self.status).serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let response = common::ResponseApdu::deserialize(data)?;
        let status = response.get_trailer();
        let body = response.get_body().ok_or("deserialize SELECT response version is NULL".to_string())?;
        let version_tlv = ber::Tlv::from_bytes(body)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize version error: {}", e)))?;
        let versions = get_tlv_primitive_value(&version_tlv, version_tlv.tag())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize version value error: {}", e)))?;
        let version = u16::from_be_bytes(
            (versions[0..2])
                .try_into()
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize SELECT version error: {}", e)))?
        );
        Ok(ResponseApduSelect::new(version, *status))
    }
}

impl Display for ResponseApduSelect {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "version: {}, status: {}", self.get_version(), self.get_status())
    }
}

#[cfg(test)]
mod tests {
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
        let status = common::ResponseApduTrailer::new(sw1, sw2);
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
        let status = common::ResponseApduTrailer::new(sw1, sw2);
        let mut response = ResponseApduSelect::new(version, status);
        let new_version = 0x2020;
        let new_sw1 = 0x61;
        let new_sw2 = 0x10;
        let new_status = common::ResponseApduTrailer::new(new_sw1, new_sw2);
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
        let status = common::ResponseApduTrailer::new(sw1, sw2);
        let response = ResponseApduSelect::new(version, status);
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(
            serialized_response,
            vec![
                0x5A, 0x02,
                0x10, 0x10,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_select_response_deserialize() {
        let data = vec![
            0x5A, 0x02,
            0x10, 0x10,
            0x90, 0x00,
        ];
        let response = ResponseApduSelect::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_version(), 0x1010);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
        assert_eq!(response.get_status().is_success(), true);
    }
}
