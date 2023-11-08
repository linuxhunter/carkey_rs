use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{create_tlv_with_primitive_value, get_tlv_primitive_value, identifier};
use super::{common, KEY_ID_TAG};

const DISABLE_DK_INS: u8 = 0x6E;
const DISABLE_DK_P1: u8 = 0x00;
const DISABLE_DK_P2: u8 = 0x00;
const DISABLE_DK_LE: u8 = 0x00;
const ENABLE_DK_INS: u8 = 0x6F;
const ENABLE_DK_P1: u8 = 0x00;
const ENABLE_DK_P2: u8 = 0x00;
const ENABLE_DK_LE: u8 = 0x00;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum StatusDk {
    DisableDk = 0x00,
    EnableDk = 0x01,
}

impl Default for StatusDk {
    fn default() -> Self {
        StatusDk::DisableDk
    }
}

impl TryFrom<u8> for StatusDk {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(StatusDk::DisableDk),
            0x01 => Ok(StatusDk::EnableDk),
            _ => Err(format!("Unsupported Disable/Enable Dk value: {}", value)),
        }
    }
}

impl From<StatusDk> for u8 {
    fn from(value: StatusDk) -> Self {
        match value {
            StatusDk::DisableDk => 0x00,
            StatusDk::EnableDk => 0x01,
        }
    }
}

impl Display for StatusDk {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduEnableDisable {
    cla: u8,
    status_dk: StatusDk,
    key_id: identifier::KeyId,
}

impl CommandApduEnableDisable {
    pub fn new(cla: u8, status_dk: StatusDk, key_id: identifier::KeyId) -> Self {
        CommandApduEnableDisable {
            cla,
            status_dk,
            key_id,
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_status_dk(&self) -> StatusDk {
        self.status_dk
    }
    pub fn set_status_dk(&mut self, status_dk: StatusDk) {
        self.status_dk = status_dk;
    }
    pub fn get_key_id(&self) -> &identifier::KeyId {
        &self.key_id
    }
    pub fn set_key_id(&mut self, key_id: identifier::KeyId) {
        self.key_id = key_id;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let (ins, p1, p2, le) = if self.get_status_dk() == StatusDk::DisableDk {
            (DISABLE_DK_INS, DISABLE_DK_P1, DISABLE_DK_P2, DISABLE_DK_LE)
        } else {
            (ENABLE_DK_INS, ENABLE_DK_P1, ENABLE_DK_P2, ENABLE_DK_LE)
        };
        let header = common::CommandApduHeader::new(
            self.get_cla(),
            ins,
            p1,
            p2,
        );
        let key_id_tlv = create_tlv_with_primitive_value(KEY_ID_TAG, &self.get_key_id().serialize()?);
        let trailer = common::CommandApduTrailer::new(
            Some(key_id_tlv.unwrap().to_vec()),
            Some(le),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let apdu_request = common::CommandApdu::deserialize(data.as_ref())?;
        let header = apdu_request.get_header();
        let trailer = apdu_request.get_trailer()
            .ok_or(format!("deserialize trailer is NULL"))?;
        let cla = header.get_cla();
        let ins = header.get_ins();
        let status_dk = if ins == DISABLE_DK_INS {
            StatusDk::DisableDk
        } else if ins == ENABLE_DK_INS {
            StatusDk::EnableDk
        } else {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize ins value error")).into());
        };
        let origin_key_id_data = trailer.get_data()
            .ok_or(format!("deserialize key id is NULL"))?;
        let key_id_tlv = ber::Tlv::from_bytes(origin_key_id_data)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id tlv error: {}", e)))?;
        let key_id_data = get_tlv_primitive_value(&key_id_tlv, key_id_tlv.tag())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id value error: {}", e)))?;
        let key_id = identifier::KeyId::deserialize(key_id_data)?;
        Ok(CommandApduEnableDisable::new(
            cla,
            status_dk,
            key_id,
        ))
    }
}

impl Display for CommandApduEnableDisable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduEnableDisable {
    status: common::ResponseApduTrailer,
}

impl ResponseApduEnableDisable {
    pub fn new(status: common::ResponseApduTrailer) -> Self {
        ResponseApduEnableDisable {
            status,
        }
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let response = common::ResponseApdu::new(
            None,
            self.get_status().clone(),
        );
        response.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let response = common::ResponseApdu::deserialize(data)?;
        let trailer = response.get_trailer();
        Ok(ResponseApduEnableDisable::new(*trailer))
    }
}

impl Display for ResponseApduEnableDisable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_enable_disable_request() {
        let cla = 0x00;
        let status_dk = StatusDk::DisableDk;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let request = CommandApduEnableDisable::new(
            cla,
            status_dk,
            key_id,
        );
        assert_eq!(request.get_cla(), 0x00);
        assert_eq!(request.get_status_dk(), StatusDk::DisableDk);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
    }
    #[test]
    fn test_update_enable_disable_request() {
        let cla = 0x00;
        let status_dk = StatusDk::DisableDk;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let mut request = CommandApduEnableDisable::new(
            cla,
            status_dk,
            key_id,
        );
        let new_cla = 0xFF;
        let new_status_dk = StatusDk::EnableDk;
        let new_device_oem_id = 0x1112;
        let new_vehicle_oem_id = 0x1314;
        let new_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_key_id = identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap();
        request.set_cla(new_cla);
        request.set_status_dk(new_status_dk);
        request.set_key_id(new_key_id);
        assert_eq!(request.get_cla(), 0xFF);
        assert_eq!(request.get_status_dk(), StatusDk::EnableDk);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap());
    }
    #[test]
    fn test_enable_disable_request_serialize() {
        let cla = 0x00;
        let status_dk = StatusDk::DisableDk;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let request = CommandApduEnableDisable::new(
            cla,
            status_dk,
            key_id,
        );
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x00, 0x6E, 0x00, 0x00,
                0x12,
                0x89, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x00,
            ],
        );
    }
    #[test]
    fn test_enable_disable_request_deserialize() {
        let data = vec![
            0x00, 0x6E, 0x00, 0x00,
            0x12,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x00,
        ];
        let request = CommandApduEnableDisable::deserialize(data.as_ref());
        println!("request = {:?}", request);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.get_cla(), 0x00);
        assert_eq!(request.get_status_dk(), StatusDk::DisableDk);
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
    }
    #[test]
    fn test_create_enable_disable_response() {
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduEnableDisable::new(status);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_enable_disable_response() {
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut response = ResponseApduEnableDisable::new(status);
        let new_status = common::ResponseApduTrailer::new(0x61, 0x10);
        response.set_status(new_status);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x61, 0x10));
    }
    #[test]
    fn test_enable_disable_response_serialize() {
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduEnableDisable::new(status);
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(
            serialized_response,
            vec![0x90, 0x00],
        );
    }
    #[test]
    fn test_enable_disable_response_deserialize() {
        let data = vec![0x90, 0x00];
        let response = ResponseApduEnableDisable::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
