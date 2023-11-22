use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{create_tlv_with_primitive_value, get_tlv_primitive_value, ble::identifier, Serde};
use super::{common, KEY_ID_STATUS_TAG, KEY_ID_TAG};

#[allow(dead_code)]
const LIST_DK_INS: u8 = 0x60;
#[allow(dead_code)]
const LIST_DK_ALL_P1: u8 = 0x00;
#[allow(dead_code)]
const LIST_DK_SPEC_P1: u8 = 0x01;
#[allow(dead_code)]
const LIST_DK_P2: u8 = 0x00;
#[allow(dead_code)]
const LIST_DK_LE: u8 = 0x00;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CommandApduListDk {
    cla: u8,
    key_id: Option<identifier::KeyId>,
}

#[allow(dead_code)]
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
}

impl Serde for CommandApduListDk {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        match self.key_id {
            Some(ref key_id) => {
                let header = common::CommandApduHeader::new(
                    self.cla,
                    LIST_DK_INS,
                    LIST_DK_SPEC_P1,
                    LIST_DK_P2
                );
                let key_id_tlv = create_tlv_with_primitive_value(KEY_ID_TAG, &key_id.serialize()?)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tlv error: {}", e)))?;
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

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let command_apdu = common::CommandApdu::deserialize(data)?;
        let header = command_apdu.get_header();
        let trailer = command_apdu
            .get_trailer()
            .ok_or("deserialize trailer is NULL".to_string())?;
        if trailer.get_le() != Some(&LIST_DK_LE) {
            return Err(ErrorKind::ApduInstructionErr("deserialize LIST DK Le is invalid".to_string()).into());
        }
        let cla = header.get_cla();
        let key_id = if header.get_p1() == LIST_DK_SPEC_P1 {
            let data = trailer
                .get_data()
                .ok_or("deserialize LIST DK key is NULL".to_string())?;
            let tlv = ber::Tlv::from_bytes(data)
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize list dk apdu error: {}", e)))?;
            let serialized_key_id = get_tlv_primitive_value(&tlv, tlv.tag())
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
        match self.get_key_id() {
            Some(key_id) => {
                write!(f, "{}", key_id)
            },
            None => {
                write!(f, "All")
            }
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum KeyIdStatus {
    #[default]
    Undelivered = 0x01,
    Delivered = 0x02,
    Activated = 0x03,
    Suspended = 0x04,
}

impl TryFrom<u8> for KeyIdStatus {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(KeyIdStatus::Undelivered),
            0x02 => Ok(KeyIdStatus::Delivered),
            0x03 => Ok(KeyIdStatus::Activated),
            0x04 => Ok(KeyIdStatus::Suspended),
            _ => Err(format!("Unsupported KeyIdStatus from u8: {}", value)),
        }
    }
}

impl From<KeyIdStatus> for u8 {
    fn from(value: KeyIdStatus) -> Self {
        match value {
            KeyIdStatus::Undelivered => 0x01,
            KeyIdStatus::Delivered => 0x02,
            KeyIdStatus::Activated => 0x03,
            KeyIdStatus::Suspended => 0x04,
        }
    }
}

impl Display for KeyIdStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyIdStatus::Undelivered => write!(f, "undelivered"),
            KeyIdStatus::Delivered => write!(f, "delivered"),
            KeyIdStatus::Activated => write!(f, "activated"),
            KeyIdStatus::Suspended => write!(f, "suspended"),
        }
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduListDk {
    key_id: identifier::KeyId,
    key_id_status: KeyIdStatus,
    status: common::ResponseApduTrailer,
}

#[allow(dead_code)]
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
}

impl Serde for ResponseApduListDk {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let key_id_tlv = create_tlv_with_primitive_value(KEY_ID_TAG, &self.get_key_id().serialize()?)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id tlv error: {}", e)))?;
        let key_id_status_tlv = create_tlv_with_primitive_value(KEY_ID_STATUS_TAG, &[u8::from(*self.get_key_id_status())])
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create list dk key id status tlv error: {}", e)))?;
        let mut body = Vec::new();
        body.append(&mut key_id_tlv.to_vec());
        body.append(&mut key_id_status_tlv.to_vec());
        let response = common::ResponseApdu::new(
            Some(body),
            self.status,
        );
        response.serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let response_apdu = common::ResponseApdu::deserialize(data)?;
        let status = response_apdu.get_trailer();
        let body = response_apdu.get_body().ok_or("deserialize list dk response is NULL".to_string())?;
        let tlv_collections = ber::Tlv::parse_all(body);
        let mut response = ResponseApduListDk::default();
        response.set_status(*status);
        for tlv in tlv_collections {
            if tlv.tag().to_bytes() == KEY_ID_TAG.to_be_bytes() {
                let key_id = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id error: {}", e)))?;
                response.set_key_id(identifier::KeyId::deserialize(key_id)?);
            } else if tlv.tag().to_bytes() == KEY_ID_STATUS_TAG.to_be_bytes() {
                let key_id_status = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id status error: {}", e)))?;
                response.set_key_id_status(KeyIdStatus::try_from(key_id_status[0])?);
            }
        }
        Ok(response)
    }
}

impl Display for ResponseApduListDk {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "key id: {}, key id status: {}", self.get_key_id(), self.get_key_id_status())
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
        let key_id_status = KeyIdStatus::Undelivered;
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduListDk::new(
            key_id,
            key_id_status,
            status,
        );
        assert_eq!(response.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(*response.get_key_id_status(), KeyIdStatus::Undelivered);
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
        let key_id_status = KeyIdStatus::Undelivered;
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
        let updated_key_id_status = KeyIdStatus::Delivered;
        let status = common::ResponseApduTrailer::new(0x61, 0x10);
        response.set_key_id(updated_key_id);
        response.set_key_id_status(updated_key_id_status);
        response.set_status(status);
        assert_eq!(response.get_key_id(), &identifier::KeyId::new(updated_device_oem_id, updated_vehicle_oem_id, &updated_key_serial_id).unwrap());
        assert_eq!(*response.get_key_id_status(), KeyIdStatus::Delivered);
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
        let key_id_status = KeyIdStatus::Undelivered;
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
        assert_eq!(*response.get_key_id_status(), KeyIdStatus::Undelivered);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
