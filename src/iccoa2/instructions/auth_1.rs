use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{create_tlv_with_primitive_value, get_tlv_primitive_value, identifier, Serde};
use super::{common, DEVICE_TEMP_PUB_KEY_TAG, RANDOM_TAG, SIGNATURE_TAG, VEHICLE_ID_TAG, VEHICLE_TEMP_PUB_KEY_TAG};

#[allow(dead_code)]
const AUTH_1_INS: u8 = 0x63;
#[allow(dead_code)]
const AUTH_1_P1: u8 = 0x00;
#[allow(dead_code)]
const AUTH_1_P2: u8 = 0x00;
#[allow(dead_code)]
const AUTH_1_LE: u8 = 0x00;
#[allow(dead_code)]
const AUTH_1_SIGNATURE_LENGTH: usize = 0x40;

pub fn vehicle_signature(_data: &[u8]) -> [u8; AUTH_1_SIGNATURE_LENGTH] {
    [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    ]
}

pub fn vehicle_verify(_data: &[u8]) -> bool {
    true
}

pub fn device_signature(_data: &[u8]) -> [u8; AUTH_1_SIGNATURE_LENGTH] {
    [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    ]
}

pub fn device_verify(_data: &[u8]) -> bool {
    true
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct Auth1Data {
    vehicle_id: identifier::VehicleId,
    device_temp_pub_key_x: Vec<u8>,
    vehicle_temp_pub_key_x: Vec<u8>,
    random: Vec<u8>,
}

#[allow(dead_code)]
impl Auth1Data {
    pub fn new(vehicle_id: identifier::VehicleId, device_temp_pub_key_x: &[u8], vehicle_temp_pub_key_x: &[u8], random: &[u8]) -> Self {
        Auth1Data {
            vehicle_id,
            device_temp_pub_key_x: device_temp_pub_key_x.to_vec(),
            vehicle_temp_pub_key_x: vehicle_temp_pub_key_x.to_vec(),
            random: random.to_vec(),
        }
    }
    pub fn get_vehicle_id(&self) -> &identifier::VehicleId {
        &self.vehicle_id
    }
    pub fn set_vehicle_id(&mut self, vehicle_id: identifier::VehicleId) {
        self.vehicle_id = vehicle_id;
    }
    pub fn get_device_temp_pub_key_x(&self) -> &[u8] {
        &self.device_temp_pub_key_x
    }
    pub fn set_device_temp_pub_key_x(&mut self, device_temp_pub_key_x: &[u8]) {
        self.device_temp_pub_key_x = device_temp_pub_key_x.to_vec();
    }
    pub fn get_vehicle_temp_pub_key_x(&self) -> &[u8] {
        &self.vehicle_temp_pub_key_x
    }
    pub fn set_vehicle_temp_pub_key_x(&mut self, vehicle_temp_pub_key_x: &[u8]) {
        self.vehicle_temp_pub_key_x = vehicle_temp_pub_key_x.to_vec();
    }
    pub fn get_random(&self) -> &[u8] {
        &self.random
    }
    pub fn set_random(&mut self, random: &[u8]) {
        self.random = random.to_vec();
    }
}

impl Serde for Auth1Data {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let vehicle_id_tlv = create_tlv_with_primitive_value(VEHICLE_ID_TAG, &self.get_vehicle_id().serialize()?)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle id tlv error: {}", e)))?;
        let device_temp_pub_key_x_tlv = create_tlv_with_primitive_value(DEVICE_TEMP_PUB_KEY_TAG, self.get_device_temp_pub_key_x())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create device temp public key x tlv error: {}", e)))?;
        let vehicle_temp_pub_key_x_tlv = create_tlv_with_primitive_value(VEHICLE_TEMP_PUB_KEY_TAG, self.get_vehicle_temp_pub_key_x())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle temp public key x tlv error: {}", e)))?;
        let random_tlv = create_tlv_with_primitive_value(RANDOM_TAG, self.get_random())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create random tlv error: {}", e)))?;

        let mut buffer = Vec::new();
        buffer.append(&mut vehicle_id_tlv.to_vec());
        buffer.append(&mut device_temp_pub_key_x_tlv.to_vec());
        buffer.append(&mut vehicle_temp_pub_key_x_tlv.to_vec());
        buffer.append(&mut random_tlv.to_vec());
        Ok(buffer)
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let mut auth_data = Auth1Data::default();
        let tlv_collections = ber::Tlv::parse_all(data);
        for tlv in tlv_collections {
            if tlv.tag().to_bytes() == VEHICLE_ID_TAG.to_be_bytes() {
                let vehicle_id = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize vehicle id error: {}", e)))?;
                auth_data.set_vehicle_id(identifier::VehicleId::deserialize(vehicle_id)?);
            } else if tlv.tag().to_bytes() == DEVICE_TEMP_PUB_KEY_TAG.to_be_bytes() {
                let device_temp_pub_key_x = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize device temp public key x error: {}", e)))?;
                auth_data.set_device_temp_pub_key_x(device_temp_pub_key_x);
            } else if tlv.tag().to_bytes() == VEHICLE_TEMP_PUB_KEY_TAG.to_be_bytes() {
                let vehicle_temp_pub_key_x = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize vehicle temp public key x error: {}", e)))?;
                auth_data.set_vehicle_temp_pub_key_x(vehicle_temp_pub_key_x);
            } else if tlv.tag().to_bytes() == RANDOM_TAG.to_be_bytes() {
                let random_value = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize random error: {}", e)))?;
                auth_data.set_random(random_value);
            }
        }
        Ok(auth_data)
    }
}

impl Display for Auth1Data {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "vehicle id: {}, device_ePK.x: {:02X?}, vehicle_ePK.x: {:02X?}, random: {:02X?}",
            self.get_vehicle_id(),
            self.get_device_temp_pub_key_x(),
            self.get_vehicle_temp_pub_key_x(),
            self.get_random(),
        )
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduAuth1 {
    cla: u8,
    auth_data: Auth1Data,
}

#[allow(dead_code)]
impl CommandApduAuth1 {
    pub fn new(cla: u8, auth_data: Auth1Data) -> Self {
        CommandApduAuth1 {
            cla,
            auth_data,
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_auth_data(&self) -> &Auth1Data {
        &self.auth_data
    }
    pub fn set_auth_data(&mut self, auth_data: Auth1Data) {
        self.auth_data = auth_data;
    }
    pub fn signature(&self) -> Result<[u8; AUTH_1_SIGNATURE_LENGTH]> {
        Ok(vehicle_signature(self.auth_data.serialize()?.as_ref()))
    }
    pub fn verify(data: &[u8]) -> Result<bool> {
        Ok(vehicle_verify(&CommandApduAuth1::deserialize(data)?))
    }

}

impl Serde for CommandApduAuth1 {
    type Output = Vec<u8>;

    fn serialize(&self) -> Result<Vec<u8>> {
        let signature_tlv = create_tlv_with_primitive_value(SIGNATURE_TAG, &self.signature()?)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("crate auth1 signature tlv error: {}", e)))?;

        let header = common::CommandApduHeader::new(
            self.cla,
            AUTH_1_INS,
            AUTH_1_P1,
            AUTH_1_P2,
        );
        let trailer = common::CommandApduTrailer::new(
            Some(signature_tlv.to_vec()),
            Some(AUTH_1_LE),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let command_apdu = common::CommandApdu::deserialize(data)?;
        let _header = command_apdu.get_header();
        let trailer = command_apdu
            .get_trailer()
            .ok_or("deserialize trailer error".to_string())?;
        let origin_data = trailer
            .get_data()
            .ok_or("deserialize trailer data error".to_string())?;

        let tlv = ber::Tlv::from_bytes(origin_data)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize origin data error: {}", e)))?;
        if tlv.tag().to_bytes() != SIGNATURE_TAG.to_be_bytes() {
            return Err(ErrorKind::ApduInstructionErr("deserialize tag is invalid".to_string()).into());
        }
        let signature_value = get_tlv_primitive_value(&tlv, tlv.tag())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize signature value error: {}", e)))?;
        Ok(signature_value.to_owned())
    }
}

impl Display for CommandApduAuth1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.signature())
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduAuth1 {
    auth_data: Auth1Data,
    status: common::ResponseApduTrailer,
}

#[allow(dead_code)]
impl ResponseApduAuth1 {
    pub fn new(auth_data: Auth1Data, status: common::ResponseApduTrailer) -> Self {
        ResponseApduAuth1 {
            auth_data,
            status,
        }
    }
    pub fn get_auth_data(&self) -> &Auth1Data {
        &self.auth_data
    }
    pub fn set_auth_data(&mut self, auth_data: Auth1Data) {
        self.auth_data = auth_data;
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn signature(&self) -> Result<[u8; AUTH_1_SIGNATURE_LENGTH]> {
        Ok(device_signature(self.auth_data.serialize()?.as_ref()))
    }
    pub fn verify(data: &[u8]) -> Result<bool> {
        Ok(device_verify(&ResponseApduAuth1::deserialize(data)?))
    }
}

impl Serde for ResponseApduAuth1 {
    type Output = Vec<u8>;

    fn serialize(&self) -> Result<Vec<u8>> {
        let response = common::ResponseApdu::new(
            Some(self.signature()?.to_vec()),
            self.status,
        );
        response.serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let response_apdu = common::ResponseApdu::deserialize(data)?;
        let body = response_apdu.get_body().ok_or("deserialize auth1 response body is NULL".to_string())?;
        Ok(body.to_vec())
    }
}

impl Display for ResponseApduAuth1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.signature())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_vehicle_id(vehicle_oem_id: u16, vehicle_serial_id: &[u8]) -> identifier::VehicleId {
        let vehicle_id = identifier::VehicleId::new(vehicle_oem_id, &vehicle_serial_id);
        assert!(vehicle_id.is_ok());
        vehicle_id.unwrap()
    }
    fn create_vehicle_temp_public_key() -> Vec<u8> {
        vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ]
    }
    fn create_device_temp_public_key() -> Vec<u8> {
        vec![
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ]
    }
    fn create_random_number() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    #[test]
    fn test_create_auth1_data() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        assert_eq!(auth1_data.get_vehicle_id(), &create_vehicle_id(vehicle_oem_id, &vehicle_serial_id));
        assert_eq!(auth1_data.get_device_temp_pub_key_x(), &create_device_temp_public_key());
        assert_eq!(auth1_data.get_vehicle_temp_pub_key_x(), &create_vehicle_temp_public_key());
        assert_eq!(auth1_data.get_random(), &create_random_number());
    }
    #[test]
    fn test_update_auth1_data() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let mut auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );

        let new_vehicle_oem_id = 0x0201;
        let new_vehicle_serial_id = [0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_vehicle_id = create_vehicle_id(new_vehicle_oem_id, &new_vehicle_serial_id);
        let new_device_temp_pub_key_x = create_vehicle_temp_public_key();
        let new_vehicle_temp_pub_key_x = create_device_temp_public_key();
        let new_random = create_random_number();
        auth1_data.set_vehicle_id(new_vehicle_id);
        auth1_data.set_device_temp_pub_key_x(&new_device_temp_pub_key_x);
        auth1_data.set_vehicle_temp_pub_key_x(&new_vehicle_temp_pub_key_x);
        auth1_data.set_random(&new_random);
        assert_eq!(auth1_data.get_vehicle_id(), &create_vehicle_id(new_vehicle_oem_id, &new_vehicle_serial_id));
        assert_eq!(auth1_data.get_device_temp_pub_key_x(), &new_device_temp_pub_key_x);
        assert_eq!(auth1_data.get_vehicle_temp_pub_key_x(), &new_vehicle_temp_pub_key_x);
        assert_eq!(auth1_data.get_random(), &new_random);
    }
    #[test]
    fn test_auth1_data_serialize() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        let serialized_auth1_data = auth1_data.serialize();
        assert!(serialized_auth1_data.is_ok());
        let serialized_auth1_data = serialized_auth1_data.unwrap();
        assert_eq!(
            serialized_auth1_data,
            vec![
                0x83, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x84, 0x20,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x81, 0x20,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x55, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ],
        );
    }
    #[test]
    fn test_auth1_data_deserialize() {
        let data = vec![
            0x83, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x84, 0x20,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x81, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x55, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let auth1_data = Auth1Data::deserialize(data.as_ref());
        assert!(auth1_data.is_ok());
        let auth1_data = auth1_data.unwrap();

        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(auth1_data.get_vehicle_id(), &create_vehicle_id(vehicle_oem_id, &vehicle_serial_id));
        assert_eq!(auth1_data.get_device_temp_pub_key_x(), &create_device_temp_public_key());
        assert_eq!(auth1_data.get_vehicle_temp_pub_key_x(), &create_vehicle_temp_public_key());
        assert_eq!(auth1_data.get_random(), &create_random_number());
    }
    #[test]
    fn test_create_auth1_request() {
        let cla = 0x00;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        let auth1_request = CommandApduAuth1::new(cla, auth1_data);
        assert_eq!(auth1_request.get_cla(), 0x00);
        assert_eq!(
            auth1_request.get_auth_data(),
            &Auth1Data::new(
                create_vehicle_id(vehicle_oem_id, &vehicle_serial_id),
                device_temp_pub_key_x.as_ref(),
                vehicle_temp_pub_key_x.as_ref(),
                random.as_ref(),
            ),
        );
    }
    #[test]
    fn test_auth1_request_serialize() {
        let cla = 0x00;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        let auth1_request = CommandApduAuth1::new(cla, auth1_data);
        let auth1_request_signature = auth1_request.serialize();
        assert!(auth1_request_signature.is_ok());
        let auth1_request_signature = auth1_request_signature.unwrap();
        assert_eq!(
            auth1_request_signature,
            vec![
                0x00, 0x63, 0x00, 0x00,
                0x42,
                0x8F, 0x40,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
                0x00,
            ],
        );
    }
    #[test]
    fn test_auth1_request_deserialize() {
        let data = vec![
            0x00, 0x63, 0x00, 0x00,
            0x42,
            0x8F, 0x40,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x00,
        ];
        let auth1_request_signature = CommandApduAuth1::deserialize(data.as_ref());
        assert!(auth1_request_signature.is_ok());
        let auth1_request_signature = auth1_request_signature.unwrap();
        assert_eq!(
            auth1_request_signature,
            vec![
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            ],
        );
    }
    #[test]
    fn test_auth1_request_signature() {
        let cla = 0x00;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        let auth1_request = CommandApduAuth1::new(cla, auth1_data);
        let auth1_request_signature = auth1_request.signature();
        assert!(auth1_request_signature.is_ok());
        let auth1_request_signature = auth1_request_signature.unwrap();
        assert_eq!(
            auth1_request_signature,
            [
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            ],
        )
    }
    #[test]
    fn test_auth1_request_verify() {
        let data = vec![
            0x00, 0x63, 0x00, 0x00,
            0x42,
            0x8F, 0x40,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x00,
        ];
        let result = CommandApduAuth1::verify(data.as_ref());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, true);
    }
    #[test]
    fn test_create_auth1_response() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let auth1_response = ResponseApduAuth1::new(auth1_data, status);
        assert_eq!(
            auth1_response.get_auth_data(),
            &Auth1Data::new(
                create_vehicle_id(vehicle_oem_id, &vehicle_serial_id),
                device_temp_pub_key_x.as_ref(),
                vehicle_temp_pub_key_x.as_ref(),
                random.as_ref(),
            )
        );
    }
    #[test]
    fn test_auth1_response_serialize() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let auth1_response = ResponseApduAuth1::new(auth1_data, status);
        let serialized_auth1_response = auth1_response.serialize();
        assert!(serialized_auth1_response.is_ok());
        let serialized_auth1_response = serialized_auth1_response.unwrap();
        assert_eq!(
            serialized_auth1_response,
            vec![
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_auth1_response_deserialize() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x90, 0x00,
        ];
        let signature = ResponseApduAuth1::deserialize(data.as_ref());
        assert!(signature.is_ok());
        let signature = signature.unwrap();
        assert_eq!(
            signature,
            vec![
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            ],
        );
    }
    #[test]
    fn test_auth1_response_signature() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let device_temp_pub_key_x = create_device_temp_public_key();
        let vehicle_temp_pub_key_x = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth1_data = Auth1Data::new(
            vehicle_id,
            device_temp_pub_key_x.as_ref(),
            vehicle_temp_pub_key_x.as_ref(),
            random.as_ref(),
        );
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let auth1_response = ResponseApduAuth1::new(auth1_data, status);
        let signature = auth1_response.signature();
        assert!(signature.is_ok());
        let signature = signature.unwrap();
        assert_eq!(
            signature,
            [
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            ],
        );
    }
    #[test]
    fn test_auth1_response_verify() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x90, 0x00,
        ];
        let result = ResponseApduAuth1::verify(data.as_ref());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, true);
    }
}
