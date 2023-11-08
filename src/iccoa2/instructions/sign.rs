use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{create_tlv_with_primitive_value, get_tlv_primitive_value, identifier};
use super::{common, KEY_ID_TAG, SIGNATURE_TAG};

const SIGN_INS: u8 = 0x67;
const SIGN_P1: u8 = 0x00;
const SIGN_P2: u8 = 0x00;
const SIGN_LE: u8 = 0x00;
const SIGN_DATA_TAG: u8 = 0x58;

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduSign {
    cla: u8,
    key_id: identifier::KeyId,
    data: Vec<u8>,
}

impl CommandApduSign {
    pub fn new(cla: u8, key_id: identifier::KeyId, data: &[u8]) -> Self {
        CommandApduSign {
            cla,
            key_id,
            data: data.to_vec(),
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_key_id(&self) -> &identifier::KeyId {
        &self.key_id
    }
    pub fn set_key_id(&mut self, key_id: identifier::KeyId) {
        self.key_id = key_id;
    }
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            self.cla,
            SIGN_INS,
            SIGN_P1,
            SIGN_P2,
        );
        let mut data = Vec::new();
        let key_id_tlv = create_tlv_with_primitive_value(KEY_ID_TAG, &self.get_key_id().serialize()?)?;
        let data_tlv = create_tlv_with_primitive_value(SIGN_DATA_TAG, self.get_data())?;
        data.append(&mut key_id_tlv.to_vec());
        data.append(&mut data_tlv.to_vec());
        let trailer = common::CommandApduTrailer::new(
            Some(data),
            Some(SIGN_LE),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let apdu_request = common::CommandApdu::deserialize(data)?;
        let header = apdu_request.get_header();
        let trailer = apdu_request.get_trailer().ok_or(format!("deserialize trailer is NULL"))?;
        if header.get_ins() != SIGN_INS ||
            header.get_p1() != SIGN_P1 ||
            header.get_p2() != SIGN_P2 ||
            trailer.get_le() != Some(&SIGN_LE) {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize sign request package error")).into());
        }
        let sign_data = trailer.get_data().ok_or(format!("deserialize sign data error"))?;
        let tlv_collections = ber::Tlv::parse_all(sign_data);
        let mut sign_request = CommandApduSign::default();
        sign_request.set_cla(header.get_cla());
        for tlv in tlv_collections {
            if tlv.tag().to_bytes() == KEY_ID_TAG.to_be_bytes() {
                let key_id = get_tlv_primitive_value(&tlv, &tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id error: {}", e)))?;
                sign_request.set_key_id(identifier::KeyId::deserialize(key_id)?);
            } else if tlv.tag().to_bytes() == SIGN_DATA_TAG.to_be_bytes() {
                let sign_data = get_tlv_primitive_value(&tlv, &tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize sign data error: {}", e)))?;
                sign_request.set_data(sign_data);
            }
        }
        Ok(sign_request)
    }
}

impl Display for CommandApduSign {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduSign {
    key_id: identifier::KeyId,
    signature: Vec<u8>,
    status: common::ResponseApduTrailer,
}

impl ResponseApduSign {
    pub fn new(key_id: identifier::KeyId, signature: &[u8], status: common::ResponseApduTrailer) -> Self {
        ResponseApduSign {
            key_id,
            signature: signature.to_vec(),
            status,
        }
    }
    pub fn get_key_id(&self) -> &identifier::KeyId {
        &self.key_id
    }
    pub fn set_key_id(&mut self, key_id: identifier::KeyId) {
        self.key_id = key_id;
    }
    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }
    pub fn set_signature(&mut self, signature: &[u8]) {
        self.signature = signature.to_vec();
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let key_id_tlv = create_tlv_with_primitive_value(KEY_ID_TAG, &self.get_key_id().serialize()?)?;
        let signature_tlv = create_tlv_with_primitive_value(SIGNATURE_TAG, self.get_signature())?;
        let mut body = Vec::new();
        body.append(&mut key_id_tlv.to_vec());
        body.append(&mut signature_tlv.to_vec());
        let response = common::ResponseApdu::new(
            Some(body),
            self.get_status().clone(),
        );
        response.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let apdu_response = common::ResponseApdu::deserialize(data)?;
        let body = apdu_response.get_body().ok_or(format!("deserialize response body is NULL"))?;
        let trailer = apdu_response.get_trailer();
        let tlv_collections = ber::Tlv::parse_all(body);
        let mut response = ResponseApduSign::default();
        response.set_status(*trailer);
        for tlv in tlv_collections {
            if tlv.tag().to_bytes() == KEY_ID_TAG.to_be_bytes() {
                let key_id = get_tlv_primitive_value(&tlv, &tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id error: {}",e )))?;
                response.set_key_id(identifier::KeyId::deserialize(key_id)?);
            } else if tlv.tag().to_bytes() == SIGNATURE_TAG.to_be_bytes() {
                let signature = get_tlv_primitive_value(&tlv, &tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize signature error: {}", e)))?;
                response.set_signature(signature);
            }
        }
        Ok(response)
    }
}

impl Display for ResponseApduSign {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sign_request() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let request = CommandApduSign::new(
            cla,
            key_id,
            &data,
        );
        assert_eq!(request.get_cla(), 0x00);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(request.get_data(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    #[test]
    fn test_update_sign_request() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut request = CommandApduSign::new(
            cla,
            key_id,
            &data,
        );
        let new_cla = 0xFF;
        let new_device_oem_id = 0x1112;
        let new_vehicle_oem_id = 0x1314;
        let new_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_key_id = identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap();
        let new_data = vec![0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        request.set_cla(new_cla);
        request.set_key_id(new_key_id);
        request.set_data(new_data.as_ref());
        assert_eq!(request.get_cla(), 0xFF);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap());
        assert_eq!(request.get_data(), &vec![0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    }
    #[test]
    fn test_sign_request_serialize() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let request = CommandApduSign::new(
            cla,
            key_id,
            &data,
        );
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x00, 0x067, 0x00, 0x00,
                0x1C,
                0x89, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x58, 0x08,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00,
            ],
        );
    }
    #[test]
    fn test_sign_request_deserialize() {
        let data = vec![
            0x00, 0x067, 0x00, 0x00,
            0x1C,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x58, 0x08,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00,
        ];
        let request = CommandApduSign::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.get_cla(), 0x00);
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(request.get_data(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    #[test]
    fn test_create_sign_response() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let signature = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduSign::new(
            key_id,
            signature.as_ref(),
            status,
        );
        assert_eq!(response.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(
            response.get_signature(),
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ],
        );
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_sign_response() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let signature = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut response = ResponseApduSign::new(
            key_id,
            signature.as_ref(),
            status,
        );
        let new_device_oem_id = 0x1112;
        let new_vehicle_oem_id = 0x1314;
        let new_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_key_id = identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap();
        let new_signature = vec![
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        ];
        let new_status = common::ResponseApduTrailer::new(0x61, 0x10);
        response.set_key_id(new_key_id);
        response.set_signature(new_signature.as_ref());
        response.set_status(new_status);
        assert_eq!(response.get_key_id(), &identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap());
        assert_eq!(
            response.get_signature(),
            vec![
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            ],
        );
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x61, 0x10));
    }
    #[test]
    fn test_sign_response_serailize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let signature = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduSign::new(
            key_id,
            signature.as_ref(),
            status,
        );
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(
            serialized_response,
            vec![
                0x89, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x8F, 0x40,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_sign_response_deserialize() {
        let data = vec![
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x8F, 0x40,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x90, 0x00,
        ];
        let response = ResponseApduSign::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(response.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(
            response.get_signature(),
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ],
        );
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
