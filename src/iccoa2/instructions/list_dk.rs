use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{get_tlv_primitive_value, identifier};
use super::common;

const LIST_DK_INS: u8 = 0x60;
const LIST_DK_ALL_P1: u8 = 0x00;
const LIST_DK_SPEC_P1: u8 = 0x01;
const LIST_DK_P2: u8 = 0x00;
const LIST_DK_LE: u8 = 0x00;
const LIST_DK_KEY_ID_TAG: u8 = 0x89;
const LIST_DK_KEY_ID_STATUS_TAG: u8 = 0x88;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CommandApduListDk {
    cla: u8,
    key_id: Option<identifier::KeyId>,
}

impl CommandApduListDk {
    pub fn new(cla: u8, key_id: Option<identifier::KeyId>) -> Self {
        CommandApduListDk {
            cla,
            key_id,
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_key_id(&self) -> Option<&identifier::KeyId> {
        if let Some(ref key_id) = self.key_id {
            Some(key_id)
        } else {
            None
        }
    }
    pub fn set_key_id(&mut self, key_id: Option<identifier::KeyId>) {
        self.key_id = key_id;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match self.key_id {
            Some(ref key_id) => {
                let header = common::CommandApduHeader::new(
                    self.cla,
                    LIST_DK_INS,
                    LIST_DK_SPEC_P1,
                    LIST_DK_P2
                );
                let key_id_tag = ber::Tag::try_from(LIST_DK_KEY_ID_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tag error")))?;
                let key_id_value = ber::Value::Primitive(key_id.serialize()?);
                let key_id_tlv = ber::Tlv::new(key_id_tag, key_id_value)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tlv error")))?;
                let trailer = common::CommandApduTrailer::new(
                    Some(key_id_tlv.to_vec()),
                    Some(LIST_DK_LE),
                );
                common::CommandApdu::new(header, Some(trailer)).serialize()
            },
            None => {
                let header = common::CommandApduHeader::new(
                    self.cla,
                    LIST_DK_INS,
                    LIST_DK_ALL_P1,
                    LIST_DK_P2
                );
                let trailer = common::CommandApduTrailer::new(
                    None,
                    Some(LIST_DK_LE),
                );
                common::CommandApdu::new(header, Some(trailer)).serialize()
            }
        }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let command_apdu = common::CommandApdu::deserialize(data)?;
        let header = command_apdu.get_header();
        let trailer = command_apdu
            .get_trailer()
            .ok_or(format!("deserialize trailer is NULL"))?;
        if trailer.get_le() != Some(&LIST_DK_LE) {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize LIST DK Le is invalid")).into());
        }
        let cla = header.get_cla();
        let key_id = if header.get_p1() == LIST_DK_SPEC_P1 {
            let data = trailer
                .get_data()
                .ok_or(format!("deserialize LIST DK key is NULL"))?;
            let key_id_tag = ber::Tag::try_from(LIST_DK_KEY_ID_TAG)
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tag error")))?;
            let tlv = ber::Tlv::from_bytes(data)
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize list dk apdu error: {}", e)))?;
            let serialized_key_id = get_tlv_primitive_value(&tlv, &key_id_tag)
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize list dk key id error: {}", e)))?;
            Some(identifier::KeyId::deserialize(serialized_key_id)?)
        } else {
            None
        };
        Ok(CommandApduListDk::new(cla, key_id))
    }
}

impl Display for CommandApduListDk {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum KeyIdStatus {
    UNDELIVERED = 0x01,
    DELIVERED = 0x02,
    ACTIVATED = 0x03,
    SUSPENDED = 0x04,
}

impl TryFrom<u8> for KeyIdStatus {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(KeyIdStatus::UNDELIVERED),
            0x02 => Ok(KeyIdStatus::DELIVERED),
            0x03 => Ok(KeyIdStatus::ACTIVATED),
            0x04 => Ok(KeyIdStatus::SUSPENDED),
            _ => Err(format!("Unsupported KeyIdStatus from u8: {}", value)),
        }
    }
}

impl From<KeyIdStatus> for u8 {
    fn from(value: KeyIdStatus) -> Self {
        match value {
            KeyIdStatus::UNDELIVERED => 0x01,
            KeyIdStatus::DELIVERED => 0x02,
            KeyIdStatus::ACTIVATED => 0x03,
            KeyIdStatus::SUSPENDED => 0x04,
        }
    }
}

impl Display for KeyIdStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct ResponseApduListDk {
    key_id: identifier::KeyId,
    key_id_status: KeyIdStatus,
    status: common::ResponseApduTrailer,
}

impl ResponseApduListDk {
    pub fn new(key_id: identifier::KeyId, key_id_status: KeyIdStatus, status: common::ResponseApduTrailer) -> Self {
        ResponseApduListDk {
            key_id,
            key_id_status,
            status,
        }
    }
    pub fn get_key_id(&self) -> &identifier::KeyId {
        &self.key_id
    }
    pub fn set_key_id(&mut self, key_id: identifier::KeyId) {
        self.key_id = key_id;
    }
    pub fn get_key_id_status(&self) -> &KeyIdStatus {
        &self.key_id_status
    }
    pub fn set_key_id_status(&mut self, key_id_status: KeyIdStatus) {
        self.key_id_status = key_id_status;
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let key_id_tag = ber::Tag::try_from(LIST_DK_KEY_ID_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tag error")))?;
        let key_id_value = ber::Value::Primitive(self.get_key_id().serialize()?);
        let key_id_tlv = ber::Tlv::new(key_id_tag, key_id_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tlv error")))?;
        let key_id_status_tag = ber::Tag::try_from(LIST_DK_KEY_ID_STATUS_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id status tag error")))?;
        let key_id_status_value = ber::Value::Primitive(vec![u8::from(self.get_key_id_status().clone())]);
        let key_id_status_tlv = ber::Tlv::new(key_id_status_tag, key_id_status_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id status tlv error")))?;
        let mut body = Vec::new();
        body.append(&mut key_id_tlv.to_vec());
        body.append(&mut key_id_status_tlv.to_vec());
        let response = common::ResponseApdu::new(
            Some(body),
            self.status,
        );
        response.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let response_apdu = common::ResponseApdu::deserialize(data)?;
        let status = response_apdu.get_trailer();
        if let Some(body) = response_apdu.get_body() {
            let tlv_collections = ber::Tlv::parse_all(body);
            let mut serialized_key_id: Vec<u8> = Vec::new();
            let mut key_id_status = KeyIdStatus::UNDELIVERED;
            for tlv in tlv_collections {
                if tlv.tag().to_bytes() == LIST_DK_KEY_ID_TAG.to_be_bytes() {
                    let key_id_tag = ber::Tag::try_from(LIST_DK_KEY_ID_TAG)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tag error")))?;
                    serialized_key_id = get_tlv_primitive_value(&tlv, &key_id_tag)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize list dk key id error: {}", e)))?.to_vec();
                } else if tlv.tag().to_bytes() == LIST_DK_KEY_ID_STATUS_TAG.to_be_bytes() {
                    let key_id_status_tag = ber::Tag::try_from(LIST_DK_KEY_ID_STATUS_TAG)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id status tag error")))?;
                    let key_id_status_value = get_tlv_primitive_value(&tlv, &key_id_status_tag)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize list dk key id status error: {}", e)))?;
                    key_id_status = KeyIdStatus::try_from(key_id_status_value[0])?;
                }
            }
            let key_id = identifier::KeyId::deserialize(serialized_key_id.as_ref())?;
            Ok(ResponseApduListDk::new(
                key_id,
                key_id_status,
                *status,
            ))
        } else {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize list dk response key id is NULL")).into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_list_dk_request_all() {
        let cla = 0x00;
        let list_dk_request = CommandApduListDk::new(cla, None);
        assert_eq!(list_dk_request.get_cla(), 0x00);
        assert_eq!(list_dk_request.get_key_id(), None);
    }
    #[test]
    fn test_create_list_dk_request() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let list_dk_request = CommandApduListDk::new(cla, Some(key_id));
        assert_eq!(list_dk_request.get_cla(), 0x00);
        assert_eq!(list_dk_request.get_key_id(), Some(&identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap()));
    }
    #[test]
    fn test_update_list_dk_request() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let mut list_dk_request = CommandApduListDk::new(cla, Some(key_id));
        let new_cla = 0x01;
        let updated_device_oem_id = 0x1112;
        let updated_vehicle_oem_id = 0x1314;
        let updated_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let updated_key_id = identifier::KeyId::new(updated_device_oem_id, updated_vehicle_oem_id, &updated_key_serial_id);
        assert!(updated_key_id.is_ok());
        let updated_key_id = updated_key_id.unwrap();
        list_dk_request.set_cla(new_cla);
        list_dk_request.set_key_id(Some(updated_key_id));
        assert_eq!(list_dk_request.get_cla(), 0x01);
        assert_eq!(list_dk_request.get_key_id(), Some(&identifier::KeyId::new(updated_device_oem_id, updated_vehicle_oem_id, &updated_key_serial_id).unwrap()));
    }
    #[test]
    fn test_list_dk_request_all_serialize() {
        let cla = 0x00;
        let list_dk_request = CommandApduListDk::new(cla, None);
        let serialized_list_dk_request = list_dk_request.serialize();
        assert!(serialized_list_dk_request.is_ok());
        let serialized_list_dk_request = serialized_list_dk_request.unwrap();
        assert_eq!(serialized_list_dk_request, vec![0x00, 0x60, 0x00, 0x00, 0x00]);
    }
    #[test]
    fn test_list_dk_request_serialize() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let list_dk_request = CommandApduListDk::new(cla, Some(key_id));
        let serialized_list_dk_request = list_dk_request.serialize();
        assert!(serialized_list_dk_request.is_ok());
        let serialized_list_dk_request = serialized_list_dk_request.unwrap();
        assert_eq!(serialized_list_dk_request, vec![
            0x00, 0x60, 0x01, 0x00,
            0x12,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x00,
        ]);
    }
    #[test]
    fn test_list_dk_request_all_deserialize() {
        let data = vec![0x00, 0x60, 0x00, 0x00, 0x00];
        let list_dk_request = CommandApduListDk::deserialize(data.as_ref());
        assert!(list_dk_request.is_ok());
        let list_dk_request = list_dk_request.unwrap();
        assert_eq!(list_dk_request.get_cla(), 0x00);
        assert_eq!(list_dk_request.get_key_id(), None);
    }
    #[test]
    fn test_list_dk_request_deserialize() {
        let data = vec![
            0x00, 0x60, 0x01, 0x00,
            0x12,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x00,
        ];
        let list_dk_request = CommandApduListDk::deserialize(data.as_ref());
        assert!(list_dk_request.is_ok());
        let list_dk_request = list_dk_request.unwrap();
        assert_eq!(list_dk_request.get_cla(), 0x00);
        assert!(list_dk_request.get_key_id().is_some());
        let key_id = list_dk_request.get_key_id().unwrap();
        assert_eq!(key_id.get_device_oem_id(), 0x0102);
        assert_eq!(key_id.get_vehicle_oem_id(), 0x0304);
        assert_eq!(key_id.get_key_serial_id(), vec![0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    }
    #[test]
    fn test_create_list_dk_response() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let key_id_status = KeyIdStatus::UNDELIVERED;
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduListDk::new(
            key_id,
            key_id_status,
            status,
        );
        assert_eq!(response.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(*response.get_key_id_status(), KeyIdStatus::UNDELIVERED);
        assert_eq!(response.status, common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_list_dk_response() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let key_id_status = KeyIdStatus::UNDELIVERED;
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut response = ResponseApduListDk::new(
            key_id,
            key_id_status,
            status,
        );
        let updated_device_oem_id = 0x1112;
        let updated_vehicle_oem_id = 0x1314;
        let updated_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let updated_key_id = identifier::KeyId::new(updated_device_oem_id, updated_vehicle_oem_id, &updated_key_serial_id);
        assert!(updated_key_id.is_ok());
        let updated_key_id = updated_key_id.unwrap();
        let updated_key_id_status = KeyIdStatus::DELIVERED;
        let status = common::ResponseApduTrailer::new(0x61, 0x10);
        response.set_key_id(updated_key_id);
        response.set_key_id_status(updated_key_id_status);
        response.set_status(status);
        assert_eq!(response.get_key_id(), &identifier::KeyId::new(updated_device_oem_id, updated_vehicle_oem_id, &updated_key_serial_id).unwrap());
        assert_eq!(*response.get_key_id_status(), KeyIdStatus::DELIVERED);
        assert_eq!(response.status, common::ResponseApduTrailer::new(0x61, 0x10));
    }
    #[test]
    fn test_list_dk_response_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let key_id_status = KeyIdStatus::UNDELIVERED;
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduListDk::new(
            key_id,
            key_id_status,
            status,
        );
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x88, 0x01,
            0x01,
            0x90, 0x00,
        ]);
    }
    #[test]
    fn test_list_dk_response_deserialize() {
        let data = vec![
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x88, 0x01,
            0x01,
            0x90, 0x00,
        ];
        let response = ResponseApduListDk::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        assert_eq!(response.get_key_id(), &key_id);
        assert_eq!(*response.get_key_id_status(), KeyIdStatus::UNDELIVERED);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
