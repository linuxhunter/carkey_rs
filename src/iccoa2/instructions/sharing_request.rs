use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::{get_tlv_primitive_value, identifier};
use super::common;

const KEY_ID_TAG: u8 = 0x89;
const INNER_CSR_TAG: u8 = 0x02;
const INNER_CERT_TAG: u8 = 0x03;
const TEMP_CSR_TAG: u16 = 0x7F22;
const TEMP_CERT_TAG: u16 = 0x7F48;
const SHARING_REQUEST_INS: u8 = 0x65;
const SHARING_REQUEST_P2: u8 = 0x00;
const SHARING_REQUEST_LE: u8 = 0x00;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum SharingRequestP1 {
    FromDevice = 0x00,
    FromVehicle = 0x01,
}

impl Default for SharingRequestP1 {
    fn default() -> Self {
        SharingRequestP1::FromDevice
    }
}

impl TryFrom<u8> for SharingRequestP1 {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SharingRequestP1::FromDevice),
            0x01 => Ok(SharingRequestP1::FromVehicle),
            _ => Err(format!("Unsupported Sharing Request P1 value: {}", value)),
        }
    }
}

impl From<SharingRequestP1> for u8 {
    fn from(value: SharingRequestP1) -> Self {
        match value {
            SharingRequestP1::FromDevice => 0x00,
            SharingRequestP1::FromVehicle => 0x01,
        }
    }
}

impl Display for SharingRequestP1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduSharingRequest {
    cla: u8,
    p1: SharingRequestP1,
    key_id: identifier::KeyId,
    temp_csr: Vec<u8>,
}

impl CommandApduSharingRequest {
    pub fn new(cla: u8, p1: SharingRequestP1, key_id: identifier::KeyId, temp_csr: &[u8]) -> Self {
        CommandApduSharingRequest {
            cla,
            p1,
            key_id,
            temp_csr: temp_csr.to_vec(),
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_p1(&self) -> SharingRequestP1 {
        self.p1
    }
    pub fn set_p1(&mut self, p1: SharingRequestP1) {
        self.p1 = p1;
    }
    pub fn get_key_id(&self) -> &identifier::KeyId {
        &self.key_id
    }
    pub fn set_key_id(&mut self, key_id: identifier::KeyId) {
        self.key_id = key_id;
    }
    pub fn get_temp_csr(&self) -> &[u8] {
        &self.temp_csr
    }
    pub fn set_temp_csr(&mut self, temp_csr: &[u8]) {
        self.temp_csr = temp_csr.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            self.get_cla(),
            SHARING_REQUEST_INS,
            u8::from(self.get_p1()),
            SHARING_REQUEST_P2,
        );
        let mut buffer = Vec::new();
        let key_id_tag = ber::Tag::try_from(KEY_ID_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create key id tag error")))?;
        let key_id_value = ber::Value::Primitive(self.get_key_id().serialize()?);
        let key_id_tlv = ber::Tlv::new(key_id_tag, key_id_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create key id tlv error")))?;
        let inner_temp_csr_tag = ber::Tag::try_from(INNER_CSR_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner temp csr tag error: {}", e)))?;
        let inner_temp_csr_value = ber::Value::Primitive(self.get_temp_csr().to_vec());
        let inner_temp_csr_tlv = ber::Tlv::new(inner_temp_csr_tag, inner_temp_csr_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner temp csr tlv error: {}", e)))?;
        let temp_csr_tag = ber::Tag::try_from(TEMP_CSR_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("crate temp csr tag error: {}", e)))?;
        let temp_csr_value = ber::Value::Constructed(vec![inner_temp_csr_tlv]);
        let temp_csr_tlv = ber::Tlv::new(temp_csr_tag, temp_csr_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create temp csr tlv error: {}", e)))?;
        buffer.append(&mut key_id_tlv.to_vec());
        buffer.append(&mut temp_csr_tlv.to_vec());
        let trailer = common::CommandApduTrailer::new(
            Some(buffer),
            Some(SHARING_REQUEST_LE),
        );
        let request = common::CommandApdu::new(header, Some(trailer));
        request.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let request = common::CommandApdu::deserialize(data)?;
        let header = request.get_header();
        let trailer = request.get_trailer().ok_or(format!("deserialize trailer is NULL"))?;
        let cla = header.get_cla();
        let p1 = SharingRequestP1::try_from(header.get_p1())
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize P1 error: {}", e)))?;
        let data = trailer.get_data().ok_or(format!("deserialize trailer data is NULL"))?;
        let tlv_collections = ber::Tlv::parse_all(data);
        let mut request = CommandApduSharingRequest::default();
        request.set_cla(cla);
        request.set_p1(p1);
        for tlv in tlv_collections {
            if tlv.tag().to_bytes() == KEY_ID_TAG.to_be_bytes() {
                let key_id_data = get_tlv_primitive_value(&tlv, tlv.tag())
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize key id error: {}", e)))?;
                request.set_key_id(identifier::KeyId::deserialize(key_id_data)?);
            } else if tlv.tag().to_bytes() == TEMP_CSR_TAG.to_be_bytes() {
                let inner_csr_tag = ber::Tag::try_from(INNER_CSR_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner csr tag error: {}", e)))?;
                let inner_csr_value = get_tlv_primitive_value(&tlv, &inner_csr_tag)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize inner csr value error: {}", e)))?;
                request.set_temp_csr(inner_csr_value);
            }
        }
        Ok(request)
    }
}

impl Display for CommandApduSharingRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduSharingRequest {
    temp_cert: Vec<u8>,
    status: common::ResponseApduTrailer,
}

impl ResponseApduSharingRequest {
    pub fn new(temp_cert: &[u8], status: common::ResponseApduTrailer) -> Self {
        ResponseApduSharingRequest {
            temp_cert: temp_cert.to_vec(),
            status,
        }
    }
    pub fn get_temp_cert(&self) -> &[u8] {
        &self.temp_cert
    }
    pub fn set_temp_cert(&mut self, temp_cert: &[u8]) {
        self.temp_cert = temp_cert.to_vec();
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let inner_cert_tag = ber::Tag::try_from(INNER_CERT_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner cert tag error: {}", e)))?;
        let inner_cert_value = ber::Value::Primitive(self.get_temp_cert().to_vec());
        let inner_cert_tlv = ber::Tlv::new(inner_cert_tag, inner_cert_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner cert tlv error: {}", e)))?;
        let cert_tag = ber::Tag::try_from(TEMP_CERT_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create temp cert tag error: {}", e)))?;
        let cert_value = ber::Value::Constructed(vec![inner_cert_tlv]);
        let cert_tlv = ber::Tlv::new(cert_tag, cert_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create temp cert tlv error: {}", e)))?;
        let response = common::ResponseApdu::new(
            Some(cert_tlv.to_vec()),
            self.get_status().clone(),
        );
        response.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let response = common::ResponseApdu::deserialize(data)?;
        let body = response
            .get_body()
            .ok_or(format!("deserialize response body is NULL"))?;
        let trailer = response.get_trailer();
        let cert_tlv = ber::Tlv::from_bytes(body)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize temp cert tlv error: {}", e)))?;
        if cert_tlv.tag().to_bytes() != TEMP_CERT_TAG.to_be_bytes() {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize temp cert tag is invalid")).into());
        }
        let inner_cert_tag = ber::Tag::try_from(INNER_CERT_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner cert tag error: {}", e)))?;
        let inner_cert_value = get_tlv_primitive_value(&cert_tlv, &inner_cert_tag)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserailize inner cert value error: {}", e)))?;
        Ok(ResponseApduSharingRequest::new(
            inner_cert_value,
            *trailer,
        ))
    }
}

impl Display for ResponseApduSharingRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sharing_request() {
        let cla = 0x00;
        let p1 = SharingRequestP1::FromDevice;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let temp_csr = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let request = CommandApduSharingRequest::new(
            cla,
            p1,
            key_id,
            temp_csr.as_ref(),
        );
        assert_eq!(request.get_cla(), cla);
        assert_eq!(request.get_p1(), SharingRequestP1::FromDevice);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(request.get_temp_csr(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    #[test]
    fn test_update_sharing_request() {
        let cla = 0x00;
        let p1 = SharingRequestP1::FromDevice;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let temp_csr = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut request = CommandApduSharingRequest::new(
            cla,
            p1,
            key_id,
            temp_csr.as_ref(),
        );
        let new_cla = 0xFF;
        let new_p1 = SharingRequestP1::FromVehicle;
        let new_device_oem_id = 0x1112;
        let new_vehicle_oem_id = 0x1314;
        let new_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let new_key_id = identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap();
        let new_tmp_csr = vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        request.set_cla(new_cla);
        request.set_p1(new_p1);
        request.set_key_id(new_key_id);
        request.set_temp_csr(&new_tmp_csr);
        assert_eq!(request.get_cla(), 0xFF);
        assert_eq!(request.get_p1(), SharingRequestP1::FromVehicle);
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(new_device_oem_id, new_vehicle_oem_id, &new_key_serial_id).unwrap());
        assert_eq!(request.get_temp_csr(), &vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]);
    }
    #[test]
    fn test_sharing_request_serialize() {
        let cla = 0x00;
        let p1 = SharingRequestP1::FromDevice;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let temp_csr = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let request = CommandApduSharingRequest::new(
            cla,
            p1,
            key_id,
            temp_csr.as_ref(),
        );
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x00, 0x65, 0x00, 0x00,
                0x1F,
                0x89, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x7F, 0x22, 0x0A,
                0x02, 0x08,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00,
            ],
        );
    }
    #[test]
    fn test_sharing_request_deserialize() {
        let data = vec![
            0x00, 0x65, 0x00, 0x00,
            0x1F,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x7F, 0x22, 0x0A,
            0x02, 0x08,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00,
        ];
        let request = CommandApduSharingRequest::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();

        assert_eq!(request.get_cla(), 0x00);
        assert_eq!(request.get_p1(), SharingRequestP1::FromDevice);
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        assert_eq!(request.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
        assert_eq!(request.get_temp_csr(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    #[test]
    fn test_create_sharing_response() {
        let temp_cert = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduSharingRequest::new(
            temp_cert.as_ref(),
            status,
        );
        assert_eq!(response.get_temp_cert(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_sharing_response() {
        let temp_cert = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut response = ResponseApduSharingRequest::new(
            temp_cert.as_ref(),
            status,
        );
        let new_temp_cert = vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let new_status = common::ResponseApduTrailer::new(0x61, 0x10);
        response.set_temp_cert(new_temp_cert.as_ref());
        response.set_status(new_status);
        assert_eq!(response.get_temp_cert(), &vec![0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x61, 0x10));
    }
    #[test]
    fn test_sharing_response_serialize() {
        let temp_cert = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduSharingRequest::new(
            temp_cert.as_ref(),
            status,
        );
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(
            serialized_response,
            vec![
                0x7F, 0x48, 0x0A,
                0x03, 0x08,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_sharing_response_deserialize() {
        let data = vec![
            0x7F, 0x48, 0x0A,
            0x03, 0x08,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x90, 0x00,
        ];
        let response = ResponseApduSharingRequest::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_temp_cert(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}
