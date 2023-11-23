use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{create_tlv_with_primitive_value, get_tlv_primitive_value, identifier, Serde};
use super::{common, KEY_ID_TAG, RANDOM_TAG, RKE_CMD_TAG, SIGNATURE_TAG};

#[allow(dead_code)]
const RKE_INS: u8 = 0x66;
#[allow(dead_code)]
const RKE_P1: u8 = 0x00;
#[allow(dead_code)]
const RKE_P2: u8 = 0x00;
#[allow(dead_code)]
const RKE_LE: u8 = 0x00;

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduRke {
    cla: u8,
    key_id: identifier::KeyId,
    random: Vec<u8>,
    command: Vec<u8>,
}

#[allow(dead_code)]
impl CommandApduRke {
    pub fn new(cla: u8, key_id: identifier::KeyId, random: &[u8], command: &[u8]) -> Self {
        CommandApduRke {
            cla,
            key_id,
            random: random.to_vec(),
            command: command.to_vec(),
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
    pub fn get_random(&self) -> &[u8] {
        &self.random
    }
    pub fn set_random(&mut self, random: &[u8]) {
        self.random = random.to_vec();
    }
    pub fn get_command(&self) -> &[u8] {
        &self.command
    }
    pub fn set_command(&mut self, command: &[u8]) {
        self.command = command.to_vec();
    }
}

impl Serde for CommandApduRke {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            self.cla,
            RKE_INS,
            RKE_P1,
            RKE_P2,
        );
        let key_id_tlv = create_tlv_with_primitive_value(KEY_ID_TAG, &self.get_key_id().serialize()?)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("crate key id tlv error: {}", e)))?;
        let random_tlv = create_tlv_with_primitive_value(RANDOM_TAG, self.get_random())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle random tlv error: {}", e)))?;
        let rke_cmd_tlv = create_tlv_with_primitive_value(RKE_CMD_TAG, self.get_command())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create rke command tlv error: {}", e)))?;
        let mut data = Vec::new();
        data.append(&mut key_id_tlv.to_vec());
        data.append(&mut random_tlv.to_vec());
        data.append(&mut rke_cmd_tlv.to_vec());
        let trailer = common::CommandApduTrailer::new(
            Some(data),
            Some(RKE_LE),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let request = common::CommandApdu::deserialize(data)?;
        let header = request.get_header();
        let trailer = request.get_trailer().ok_or("deserialize trailer is NULL".to_string())?;
        let data = trailer.get_data().ok_or("deserialize trailer data is NULL".to_string())?;
        let tlv_collections = ber::Tlv::parse_all(data);
        let mut rke = CommandApduRke::default();
        rke.set_cla(header.get_cla());
        for tlv in tlv_collections {
            if tlv.tag().to_bytes() == KEY_ID_TAG.to_be_bytes() {
                let key_id = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id error: {}", e)))?;
                rke.set_key_id(identifier::KeyId::deserialize(key_id)?);
            } else if tlv.tag().to_bytes() == RANDOM_TAG.to_be_bytes() {
                let vehicle_random = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize vehicle random number error: {}", e)))?;
                rke.set_random(vehicle_random);
            } else if tlv.tag().to_bytes() == RKE_CMD_TAG.to_be_bytes() {
                let rke_cmd = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize rke command error: {}", e)))?;
                rke.set_command(rke_cmd);
            }
        }
        Ok(rke)
    }
}

impl Display for CommandApduRke {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "key id: {}, random: {:02X?}, rke command: {:02X?}", self.get_key_id(), self.get_random(), self.get_command())
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduRke {
    key_id: identifier::KeyId,
    signature: Vec<u8>,
    status: common::ResponseApduTrailer,
}

#[allow(dead_code)]
impl ResponseApduRke {
    pub fn new(key_id: identifier::KeyId, signature: &[u8], status: common::ResponseApduTrailer) -> Self {
        ResponseApduRke {
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
}

impl Serde for ResponseApduRke {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let key_id_tlv = create_tlv_with_primitive_value(KEY_ID_TAG, &self.get_key_id().serialize()?)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create key id tlv error: {}", e)))?;
        let signature_tlv = create_tlv_with_primitive_value(SIGNATURE_TAG, self.get_signature())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create rke signature tlv error: {}", e)))?;
        let mut body = Vec::new();
        body.append(&mut key_id_tlv.to_vec());
        body.append(&mut signature_tlv.to_vec());
        let response = common::ResponseApdu::new(
            Some(body),
            *self.get_status(),
        );
        response.serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let response = common::ResponseApdu::deserialize(data)?;
        let body = response.get_body().ok_or("deserialize response body is NULL".to_string())?;
        let status = response.get_trailer();
        let mut rke_response = ResponseApduRke::default();
        rke_response.set_status(*status);
        let tlv_collections = ber::Tlv::parse_all(body);
        for tlv in tlv_collections {
            if tlv.tag().to_bytes() == KEY_ID_TAG.to_be_bytes() {
                let key_id = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize response key id error: {}", e)))?;
                rke_response.set_key_id(identifier::KeyId::deserialize(key_id)?);
            } else if tlv.tag().to_bytes() == SIGNATURE_TAG.to_be_bytes() {
                let signature = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize response signature error: {}", e)))?;
                rke_response.set_signature(signature);
            }
        }
        Ok(rke_response)
    }
}

impl Display for ResponseApduRke {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "key id: {}, signature: {:02X?}", self.get_key_id(), self.get_signature())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rke_request() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let random = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let rke_command = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let request = CommandApduRke::new(
            cla,
            key_id,
            random.as_ref(),
            rke_command.as_ref(),
        );
        assert_eq!(request.get_cla(), 0x00);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(
            request.get_random(),
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            ],
        );
        assert_eq!(request.get_command(), vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    #[test]
    fn test_update_rke_request() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let random = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let rke_command = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut request = CommandApduRke::new(
            cla,
            key_id,
            random.as_ref(),
            rke_command.as_ref(),
        );

        let new_cla = 0xFF;
        let new_device_oem_id = 0x1112;
        let new_vehicle_oem_id = 0x1314;
        let new_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_key_id = identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap();
        let new_random = vec![
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let new_rke_command = vec![0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA];
        request.set_cla(new_cla);
        request.set_key_id(new_key_id);
        request.set_command(new_rke_command.as_ref());
        request.set_random(new_random.as_ref());
        assert_eq!(request.get_cla(), 0xFF);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap());
        assert_eq!(
            request.get_random(),
            vec![
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ],
        );
        assert_eq!(request.get_command(), vec![0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
    }
    #[test]
    fn test_rke_request_serialize() {
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let random = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let rke_command = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let request = CommandApduRke::new(
            cla,
            key_id,
            random.as_ref(),
            rke_command.as_ref(),
        );
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x00, 0x66, 0x00, 0x00,
                0x2C,
                0x89, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x55, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x57, 0x06,
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                0x00,
            ],
        );
    }
    #[test]
    fn test_rke_request_deserialize() {
        let data = vec![
            0x00, 0x66, 0x00, 0x00,
            0x2C,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x55, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x57, 0x06,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00,
        ];
        let request = CommandApduRke::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.get_cla(), 0x00);
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(
            request.get_random(),
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            ],
        );
        assert_eq!(request.get_command(), vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    #[test]
    fn test_create_rke_response() {
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
        let response = ResponseApduRke::new(
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
    fn test_update_rke_response() {
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
        let mut response = ResponseApduRke::new(
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
    fn test_rke_response_serialize() {
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
        let response = ResponseApduRke::new(
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
    fn test_rke_response_deserialize() {
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
        let response = ResponseApduRke::deserialize(data.as_ref());
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
