use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{get_tlv_primitive_value, identifier};
use super::common;

const AUTH_0_INS: u8 = 0x67;
const AUTH_0_P2: u8 = 0x00;
const AUTH_0_LE: u8 = 0x00;
const TEMP_PUB_KEY_LENGTH: usize = 0x41;
const RANDOM_NUMBER_LENGTH: usize = 0x08;
const CRYPTOGRAM_LENGTH: usize = 0x10;
const VERSION_TAG: u8 = 0x5A;
const VEHICLE_ID_TAG: u8 = 0x83;
const VEHICLE_TEMP_PUB_KEY_TAG: u8 = 0x81;
const RANDOM_TAG: u8 = 0x55;
const DEVICE_TEMP_PUB_KEY_TAG: u8 = 0x84;
const CRYPTO_GRAM_TAG: u8 = 0x85;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum Auth0P1 {
    Standard = 0x00,
    Fast = 0x01,
}

impl Default for Auth0P1 {
    fn default() -> Self {
        Auth0P1::Standard
    }
}

impl TryFrom<u8> for Auth0P1 {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Auth0P1::Standard),
            0x01 => Ok(Auth0P1::Fast),
            _ => Err(format!("Invalid u8 value {} for Auth0 P1", value)),
        }
    }
}

impl From<Auth0P1> for u8 {
    fn from(value: Auth0P1) -> Self {
        match value {
            Auth0P1::Standard => 0x00,
            Auth0P1::Fast => 0x01,
        }
    }
}

impl Display for Auth0P1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth0P1::Standard => write!(f, "Standard"),
            Auth0P1::Fast => write!(f, "Fast"),
        }
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduAuth0 {
    cla: u8,
    p1: Auth0P1,
    version: u16,
    vehicle_id: identifier::VehicleId,
    vehicle_temp_pub_key: Vec<u8>,
    random: Vec<u8>,
}

impl CommandApduAuth0 {
    pub fn new(cla: u8, p1: Auth0P1, version: u16, vehicle_id: identifier::VehicleId, vehicle_temp_pub_key: &[u8], random: &[u8]) -> Self {
        CommandApduAuth0 {
            cla,
            p1,
            version,
            vehicle_id,
            vehicle_temp_pub_key: vehicle_temp_pub_key.to_vec(),
            random: random.to_vec(),
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_p1(&self) -> Auth0P1 {
        self.p1
    }
    pub fn set_p1(&mut self, p1: Auth0P1) {
        self.p1 = p1;
    }
    pub fn get_version(&self) -> u16 {
        self.version
    }
    pub fn set_version(&mut self, version: u16) {
        self.version = version;
    }
    pub fn get_vehicle_id(&self) -> &identifier::VehicleId {
        &self.vehicle_id
    }
    pub fn set_vehicle_id(&mut self, vehicle_id: identifier::VehicleId) {
        self.vehicle_id = vehicle_id;
    }
    pub fn get_vehicle_temp_pub_key(&self) -> &[u8] {
        &self.vehicle_temp_pub_key
    }
    pub fn set_vehicle_temp_pub_key(&mut self, vehicle_temp_pub_key: &[u8]) {
        self.vehicle_temp_pub_key = vehicle_temp_pub_key.to_vec();
    }
    pub fn get_random(&self) -> &[u8] {
        &self.random
    }
    pub fn set_random(&mut self, random: &[u8]) {
        self.random = random.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            self.cla,
            AUTH_0_INS,
            u8::from(self.p1),
            AUTH_0_P2,
        );
        let version_tag = ber::Tag::try_from(VERSION_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create version tag error: {}", e)))?;
        let version_value = ber::Value::Primitive(self.version.to_be_bytes().to_vec());
        let version_tlv = ber::Tlv::new(version_tag, version_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create version tlv error: {}", e)))?;
        let vehicle_id_tag = ber::Tag::try_from(VEHICLE_ID_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle id tag error: {}", e)))?;
        let vehicle_id_value = ber::Value::Primitive(self.vehicle_id.serialize()?);
        let vehicle_id_tlv = ber::Tlv::new(vehicle_id_tag, vehicle_id_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle id tlv error: {}", e)))?;
        let vehicle_temp_pub_key_tag = ber::Tag::try_from(VEHICLE_TEMP_PUB_KEY_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle temp pub key tag error: {}", e)))?;
        let vehicle_temp_pub_key_value = ber::Value::Primitive(self.vehicle_temp_pub_key.clone());
        let vehicle_temp_pub_key_tlv = ber::Tlv::new(vehicle_temp_pub_key_tag, vehicle_temp_pub_key_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle temp pub key tlv error: {}", e)))?;
        let random_tag = ber::Tag::try_from(RANDOM_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create random tag error: {}", e)))?;
        let random_value = ber::Value::Primitive(self.random.clone());
        let random_tlv = ber::Tlv::new(random_tag, random_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create random tlv error: {}", e)))?;
        let mut data = Vec::new();
        data.append(&mut version_tlv.to_vec());
        data.append(&mut vehicle_id_tlv.to_vec());
        data.append(&mut vehicle_temp_pub_key_tlv.to_vec());
        data.append(&mut random_tlv.to_vec());
        let trailer = common::CommandApduTrailer::new(
            Some(data),
            Some(AUTH_0_LE),
        );
        common::CommandApdu::new(header, Some(trailer)).serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let mut auth_0 = CommandApduAuth0::default();
        let command_apdu = common::CommandApdu::deserialize(data)?;
        let header = command_apdu.get_header();
        auth_0.set_cla(header.get_cla());
        auth_0.set_p1(Auth0P1::try_from(header.get_p1())?);

        let trailer = command_apdu
            .get_trailer()
            .ok_or(format!("deserialize trailer is NULL"))?;
        let data = trailer
            .get_data()
            .ok_or(format!("deserialize data is NULL"))?;
        let tlv_collections = ber::Tlv::parse_all(data);
        for tlv in tlv_collections {
            let tag = tlv.tag().to_bytes();
            if tag == VERSION_TAG.to_be_bytes() {
                let version_tag = ber::Tag::try_from(VERSION_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create version tag error: {}", e)))?;
                let version = get_tlv_primitive_value(&tlv, &version_tag)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize version error: {}", e)))?;
                auth_0.set_version(
                    u16::from_be_bytes(
                        (&version[0..2])
                            .try_into()
                            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize version error: {}", e)))?
                    )
                );
            } else if tag == VEHICLE_ID_TAG.to_be_bytes() {
                let vehicle_id_tag = ber::Tag::try_from(VEHICLE_ID_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle id tag error: {}", e)))?;
                let vehicle_id_value = get_tlv_primitive_value(&tlv, &vehicle_id_tag)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize vehicle id value error: {}", e)))?;
                auth_0.set_vehicle_id(identifier::VehicleId::deserialize(vehicle_id_value)?);
            } else if tag == VEHICLE_TEMP_PUB_KEY_TAG.to_be_bytes() {
                let vehicle_temp_pub_key_tag = ber::Tag::try_from(VEHICLE_TEMP_PUB_KEY_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle temp pub key tag error: {}", e)))?;
                let vehicle_temp_pub_key_value = get_tlv_primitive_value(&tlv, &vehicle_temp_pub_key_tag)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize vehicle temp public key error: {}", e)))?;
                auth_0.set_vehicle_temp_pub_key(vehicle_temp_pub_key_value);
            } else if tag == RANDOM_TAG.to_be_bytes() {
                let random_tag = ber::Tag::try_from(RANDOM_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create random tag error: {}", e)))?;
                let random_value = get_tlv_primitive_value(&tlv, &random_tag)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize random number error: {}", e)))?;
                auth_0.set_random(random_value);
            }
        }
        Ok(auth_0)
    }
}

impl Display for CommandApduAuth0 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduAuth0 {
    device_temp_pub_key: Vec<u8>,
    cryptogram: Option<Vec<u8>>,
    status: common::ResponseApduTrailer,
}

impl ResponseApduAuth0 {
    pub fn new(device_temp_pub_key: &[u8], cryptogram: Option<Vec<u8>>, status: common::ResponseApduTrailer) -> Self {
        ResponseApduAuth0 {
            device_temp_pub_key: device_temp_pub_key.to_vec(),
            cryptogram,
            status,
        }
    }
    pub fn get_device_temp_pub_key(&self) -> &[u8] {
        &self.device_temp_pub_key
    }
    pub fn set_device_temp_pub_key(&mut self, device_temp_pub_key: &[u8]) {
        self.device_temp_pub_key = device_temp_pub_key.to_vec();
    }
    pub fn get_cryptogram(&self) -> Option<&[u8]> {
        if let Some(ref cryptogram) = self.cryptogram {
            Some(cryptogram)
        } else {
            None
        }
    }
    pub fn set_cryptogram(&mut self, cryptogram: Option<Vec<u8>>) {
        self.cryptogram = cryptogram;
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let device_temp_pub_key_tag = ber::Tag::try_from(DEVICE_TEMP_PUB_KEY_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create device temp pub key tag error: {}", e)))?;
        let device_tmp_pub_key_value = ber::Value::Primitive(self.device_temp_pub_key.clone());
        let device_temp_pub_key_tlv = ber::Tlv::new(device_temp_pub_key_tag, device_tmp_pub_key_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create device temp pub key tlv error: {}", e)))?;
        data.append(&mut device_temp_pub_key_tlv.to_vec());
        if let Some(cryptogram) = self.get_cryptogram() {
            let crypto_gram_tag = ber::Tag::try_from(CRYPTO_GRAM_TAG)
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("create cryptogram tag error: {}", e)))?;
            let crypto_gram_value = ber::Value::Primitive(cryptogram.to_vec());
            let crypto_gram_tlv = ber::Tlv::new(crypto_gram_tag, crypto_gram_value)
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("create cryptogram tlv error: {}", e)))?;
            data.append(&mut crypto_gram_tlv.to_vec());
        }
        let response_apdu = common::ResponseApdu::new(
            Some(data),
            self.status,
        );
        response_apdu.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let mut auth_0_response = ResponseApduAuth0::default();
        let response_apdu = common::ResponseApdu::deserialize(data)?;
        if let Some(body) = response_apdu.get_body() {
            let tlv_collections = ber::Tlv::parse_all(body);
            for tlv in tlv_collections {
                let tag = tlv.tag().to_bytes();
                if tag == DEVICE_TEMP_PUB_KEY_TAG.to_be_bytes() {
                    let device_temp_pub_key_tag = ber::Tag::try_from(DEVICE_TEMP_PUB_KEY_TAG)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create device temp pub key tag error: {}", e)))?;
                    let device_temp_pub_key_value = get_tlv_primitive_value(&tlv, &device_temp_pub_key_tag)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize temp pub key value error: {}", e)))?;
                    auth_0_response.set_device_temp_pub_key(device_temp_pub_key_value);
                } else if tag == CRYPTO_GRAM_TAG.to_be_bytes() {
                    let crypto_gram_tag = ber::Tag::try_from(CRYPTO_GRAM_TAG)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create cryptogram tag error: {}", e)))?;
                    let crypto_gram_value = get_tlv_primitive_value(&tlv, &crypto_gram_tag)
                        .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize cryptogram value error: {}", e)))?;
                    auth_0_response.set_cryptogram(Some(crypto_gram_value.to_owned()));
                }
            }
        } else {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize response auth 0 body is NULL")).into());
        }
        auth_0_response.set_status(response_apdu.get_trailer().clone());
        Ok(auth_0_response)
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
            0x04,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ]
    }
    fn create_device_temp_public_key() -> Vec<u8> {
        vec![
            0x04,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ]
    }
    fn create_random_number() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }
    fn create_crypto_gram() -> Vec<u8> {
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ]
    }
    #[test]
    fn test_create_auth0_standard_request() {
        let cla = 0x00;
        let version = 0x0001;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth0_standard_request = CommandApduAuth0::new(
            cla,
            Auth0P1::Standard,
            version,
            vehicle_id,
            vehicle_temp_pub_key.as_ref(),
            random.as_ref(),
        );
        assert_eq!(auth0_standard_request.get_cla(), 0x00);
        assert_eq!(auth0_standard_request.get_p1(), Auth0P1::Standard);
        assert_eq!(auth0_standard_request.get_version(), 0x0001);
        assert_eq!(auth0_standard_request.get_vehicle_id(), &create_vehicle_id(vehicle_oem_id, &vehicle_serial_id));
        assert_eq!(auth0_standard_request.get_vehicle_temp_pub_key(), &create_vehicle_temp_public_key());
        assert_eq!(auth0_standard_request.get_random(), &create_random_number());
    }
    #[test]
    fn test_update_auth0_standard_request() {
        let cla = 0x00;
        let version = 0x0001;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let random = create_random_number();
        let mut auth0_standard_request = CommandApduAuth0::new(
            cla,
            Auth0P1::Standard,
            version,
            vehicle_id,
            vehicle_temp_pub_key.as_ref(),
            random.as_ref(),
        );
        let new_cla = 0xFF;
        let new_version = 0x00002;
        let new_vehicle_oem_id = 0x0201;
        let new_vehicle_serial_id = [0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_vehicle_id = create_vehicle_id(new_vehicle_oem_id, &new_vehicle_serial_id);
        let new_vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let new_random = create_random_number();
        auth0_standard_request.set_cla(new_cla);
        auth0_standard_request.set_p1(Auth0P1::Fast);
        auth0_standard_request.set_version(new_version);
        auth0_standard_request.set_vehicle_id(new_vehicle_id);
        auth0_standard_request.set_vehicle_temp_pub_key(&new_vehicle_temp_pub_key);
        auth0_standard_request.set_random(&new_random);
        assert_eq!(auth0_standard_request.get_cla(), 0xFF);
        assert_eq!(auth0_standard_request.get_p1(), Auth0P1::Fast);
        assert_eq!(auth0_standard_request.get_version(), 0x0002);
        assert_eq!(auth0_standard_request.get_vehicle_id(), &create_vehicle_id(new_vehicle_oem_id, &new_vehicle_serial_id));
        assert_eq!(auth0_standard_request.get_vehicle_temp_pub_key(), &create_vehicle_temp_public_key());
        assert_eq!(auth0_standard_request.get_random(), &create_random_number());
    }
    #[test]
    fn test_auth0_standard_serialize() {
        let cla = 0x00;
        let version = 0x0001;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth0_standard_request = CommandApduAuth0::new(
            cla,
            Auth0P1::Standard,
            version,
            vehicle_id,
            vehicle_temp_pub_key.as_ref(),
            random.as_ref(),
        );
        let serialized_auth0_standard_request = auth0_standard_request.serialize();
        assert!(serialized_auth0_standard_request.is_ok());
        let serialized_auth0_standard_request = serialized_auth0_standard_request.unwrap();
        assert_eq!(
            serialized_auth0_standard_request,
            vec![
                0x00, 0x67, 0x00, 0x00,
                0x63,
                0x5A, 0x02,
                0x00, 0x01,
                0x83, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x81, 0x41,
                0x04,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x55, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x00,
            ],
        );
    }
    #[test]
    fn test_auth0_standard_deserialize() {
        let data =  vec![
            0x00, 0x67, 0x00, 0x00,
            0x63,
            0x5A, 0x02,
            0x00, 0x01,
            0x83, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x81, 0x41,
            0x04,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x55, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00,
        ];
        let auth0_request = CommandApduAuth0::deserialize(data.as_ref());
        assert!(auth0_request.is_ok());
        let auth0_standard_request = auth0_request.unwrap();
        assert_eq!(auth0_standard_request.get_cla(), 0x00);
        assert_eq!(auth0_standard_request.get_p1(), Auth0P1::Standard);
        assert_eq!(auth0_standard_request.get_version(), 0x0001);
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(auth0_standard_request.get_vehicle_id(), &create_vehicle_id(vehicle_oem_id, &vehicle_serial_id));
        assert_eq!(auth0_standard_request.get_vehicle_temp_pub_key(), &create_vehicle_temp_public_key());
        assert_eq!(auth0_standard_request.get_random(), &create_random_number());
    }
    #[test]
    fn test_create_auth0_fast_request() {
        let cla = 0x00;
        let version = 0x0001;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth0_standard_request = CommandApduAuth0::new(
            cla,
            Auth0P1::Fast,
            version,
            vehicle_id,
            vehicle_temp_pub_key.as_ref(),
            random.as_ref(),
        );
        assert_eq!(auth0_standard_request.get_cla(), 0x00);
        assert_eq!(auth0_standard_request.get_p1(), Auth0P1::Fast);
        assert_eq!(auth0_standard_request.get_version(), 0x0001);
        assert_eq!(auth0_standard_request.get_vehicle_id(), &create_vehicle_id(vehicle_oem_id, &vehicle_serial_id));
        assert_eq!(auth0_standard_request.get_vehicle_temp_pub_key(), &create_vehicle_temp_public_key());
        assert_eq!(auth0_standard_request.get_random(), &create_random_number());
    }
    #[test]
    fn test_update_auth0_fast_request() {
        let cla = 0x00;
        let version = 0x0001;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let random = create_random_number();
        let mut auth0_standard_request = CommandApduAuth0::new(
            cla,
            Auth0P1::Fast,
            version,
            vehicle_id,
            vehicle_temp_pub_key.as_ref(),
            random.as_ref(),
        );
        let new_cla = 0xFF;
        let new_version = 0x00002;
        let new_vehicle_oem_id = 0x0201;
        let new_vehicle_serial_id = [0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_vehicle_id = create_vehicle_id(new_vehicle_oem_id, &new_vehicle_serial_id);
        let new_vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let new_random = create_random_number();
        auth0_standard_request.set_cla(new_cla);
        auth0_standard_request.set_p1(Auth0P1::Standard);
        auth0_standard_request.set_version(new_version);
        auth0_standard_request.set_vehicle_id(new_vehicle_id);
        auth0_standard_request.set_vehicle_temp_pub_key(&new_vehicle_temp_pub_key);
        auth0_standard_request.set_random(&new_random);
        assert_eq!(auth0_standard_request.get_cla(), 0xFF);
        assert_eq!(auth0_standard_request.get_p1(), Auth0P1::Standard);
        assert_eq!(auth0_standard_request.get_version(), 0x0002);
        assert_eq!(auth0_standard_request.get_vehicle_id(), &create_vehicle_id(new_vehicle_oem_id, &new_vehicle_serial_id));
        assert_eq!(auth0_standard_request.get_vehicle_temp_pub_key(), &create_vehicle_temp_public_key());
        assert_eq!(auth0_standard_request.get_random(), &create_random_number());
    }
    #[test]
    fn test_auth0_fast_serialize() {
        let cla = 0x00;
        let version = 0x0001;
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = create_vehicle_id(vehicle_oem_id, &vehicle_serial_id);
        let vehicle_temp_pub_key = create_vehicle_temp_public_key();
        let random = create_random_number();
        let auth0_standard_request = CommandApduAuth0::new(
            cla,
            Auth0P1::Fast,
            version,
            vehicle_id,
            vehicle_temp_pub_key.as_ref(),
            random.as_ref(),
        );
        let serialized_auth0_standard_request = auth0_standard_request.serialize();
        assert!(serialized_auth0_standard_request.is_ok());
        let serialized_auth0_standard_request = serialized_auth0_standard_request.unwrap();
        assert_eq!(
            serialized_auth0_standard_request,
            vec![
                0x00, 0x67, 0x01, 0x00,
                0x63,
                0x5A, 0x02,
                0x00, 0x01,
                0x83, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x81, 0x41,
                0x04,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x55, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x00,
            ],
        );
    }
    #[test]
    fn test_auth0_fast_deserialize() {
        let data =  vec![
            0x00, 0x67, 0x01, 0x00,
            0x63,
            0x5A, 0x02,
            0x00, 0x01,
            0x83, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x81, 0x41,
            0x04,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x55, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00,
        ];
        let auth0_request = CommandApduAuth0::deserialize(data.as_ref());
        assert!(auth0_request.is_ok());
        let auth0_standard_request = auth0_request.unwrap();
        assert_eq!(auth0_standard_request.get_cla(), 0x00);
        assert_eq!(auth0_standard_request.get_p1(), Auth0P1::Fast);
        assert_eq!(auth0_standard_request.get_version(), 0x0001);
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(auth0_standard_request.get_vehicle_id(), &create_vehicle_id(vehicle_oem_id, &vehicle_serial_id));
        assert_eq!(auth0_standard_request.get_vehicle_temp_pub_key(), &create_vehicle_temp_public_key());
        assert_eq!(auth0_standard_request.get_random(), &create_random_number());
    }
    #[test]
    fn test_create_auth0_response() {
        let device_temp_pub_key = create_device_temp_public_key();
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let auth0_response = ResponseApduAuth0::new(
            &device_temp_pub_key,
            None,
            status,
        );
        assert_eq!(auth0_response.get_device_temp_pub_key(), &create_device_temp_public_key());
        assert_eq!(auth0_response.get_cryptogram(), None);
        assert_eq!(auth0_response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));

        let cryptogram = create_crypto_gram();
        let auth0_response = ResponseApduAuth0::new(
            &device_temp_pub_key,
            Some(cryptogram),
            status,
        );
        assert_eq!(auth0_response.get_device_temp_pub_key(), &create_device_temp_public_key());
        assert_eq!(
            auth0_response.get_cryptogram(),
            Some(create_crypto_gram().as_ref()),
        );
        assert_eq!(auth0_response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_auth0_response() {
        let device_temp_pub_key = create_device_temp_public_key();
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut auth0_response = ResponseApduAuth0::new(
            &device_temp_pub_key,
            None,
            status,
        );
        let new_device_temp_pub_key = create_device_temp_public_key();
        let new_cryptogram = create_crypto_gram();
        let new_status = common::ResponseApduTrailer::new(0x61, 0x10);
        auth0_response.set_device_temp_pub_key(&new_device_temp_pub_key);
        auth0_response.set_cryptogram(Some(new_cryptogram));
        auth0_response.set_status(new_status);
        assert_eq!(auth0_response.get_device_temp_pub_key(), &create_device_temp_public_key());
        assert_eq!(
            auth0_response.get_cryptogram(),
            Some(create_crypto_gram().as_ref()),
        );
        assert_eq!(auth0_response.get_status(), &common::ResponseApduTrailer::new(0x61, 0x10));
    }
    #[test]
    fn test_auth0_response_serialize() {
        let device_temp_pub_key = create_device_temp_public_key();
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let auth0_response = ResponseApduAuth0::new(
            &device_temp_pub_key,
            None,
            status,
        );
        let serialized_auth0_response = auth0_response.serialize();
        assert!(serialized_auth0_response.is_ok());
        let serialized_auth0_response = serialized_auth0_response.unwrap();
        assert_eq!(
            serialized_auth0_response,
            vec![
                0x84, 0x41,
                0x04,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x90, 0x00,
            ],
        );
        let cryptogram = create_crypto_gram();
        let auth0_response = ResponseApduAuth0::new(
            &device_temp_pub_key,
            Some(cryptogram),
            status,
        );
        let serialized_auth0_response = auth0_response.serialize();
        assert!(serialized_auth0_response.is_ok());
        let serialized_auth0_response = serialized_auth0_response.unwrap();
        assert_eq!(
            serialized_auth0_response,
            vec![
                0x84, 0x41,
                0x04,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x85, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_auth0_response_deserialize() {
        let data = vec![
            0x84, 0x41,
            0x04,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x90, 0x00,
        ];
        let auth0_response = ResponseApduAuth0::deserialize(data.as_ref());
        assert!(auth0_response.is_ok());
        let auth0_response = auth0_response.unwrap();
        assert_eq!(auth0_response.get_device_temp_pub_key(), &create_device_temp_public_key());
        assert_eq!(auth0_response.get_cryptogram(), None);
        assert_eq!(auth0_response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));

        let data = vec![
            0x84, 0x41,
            0x04,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x85, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x90, 0x00,
        ];
        let auth0_response = ResponseApduAuth0::deserialize(data.as_ref());
        assert!(auth0_response.is_ok());
        let auth0_response = auth0_response.unwrap();
        assert_eq!(auth0_response.get_device_temp_pub_key(), &create_device_temp_public_key());
        assert_eq!(
            auth0_response.get_cryptogram(),
            Some(create_crypto_gram().as_ref()),
        );
        assert_eq!(auth0_response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
