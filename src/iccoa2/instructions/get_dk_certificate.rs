use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::errors::*;
use crate::iccoa2::get_tlv_primitive_value;
use super::common;

const VEHICLE_CA_CERT_TAG: u16 = 0x7F40;
const VEHICLE_MASTER_KEY_CERT_TAG: u16 = 0x7F42;
const TEMP_SHARED_CERT_TAG: u16 = 0x7F44;
const FRIEND_KEY_CERT_TAG: u16 = 0x7F46;
const CERT_TAG: u8 = 0x01;

const GET_DK_CERT_INS: u8 = 0x64;
const GET_DK_CERT_P1: u8 = 0x00;
const GET_DK_CERT_P2: u8 = 0x00;
const GET_DK_CERT_LE: u8 = 0x00;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum DkCertType {
    VehicleCACert = 0x01,
    VehicleMasterKeyCert = 0x02,
    TempSharedCert = 0x03,
    FriendKeyCert = 0x04,
}

impl Default for DkCertType {
    fn default() -> Self {
        DkCertType::VehicleCACert
    }
}

impl TryFrom<u8> for DkCertType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(DkCertType::VehicleCACert),
            0x02 => Ok(DkCertType::VehicleMasterKeyCert),
            0x03 => Ok(DkCertType::TempSharedCert),
            0x04 => Ok(DkCertType::FriendKeyCert),
            _ => Err(format!("Unsupported Dk Certificate Type: {}", value)),
        }
    }
}

impl From<DkCertType> for u8 {
    fn from(value: DkCertType) -> Self {
        match value {
            DkCertType::VehicleCACert => 0x01,
            DkCertType::VehicleMasterKeyCert => 0x02,
            DkCertType::TempSharedCert => 0x03,
            DkCertType::FriendKeyCert => 0x04,
        }
    }
}

impl Display for DkCertType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduGetDkCert {
    cla: u8,
    dk_cert_type: DkCertType,
}

impl CommandApduGetDkCert {
    pub fn new(cla: u8, dk_cert_type: DkCertType) -> Self {
        CommandApduGetDkCert {
            cla,
            dk_cert_type,
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_dk_cert_type(&self) -> DkCertType {
        self.dk_cert_type
    }
    pub fn set_dk_cert_type(&mut self, dk_cert_type: DkCertType) {
        self.dk_cert_type = dk_cert_type;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            self.cla,
            GET_DK_CERT_INS,
            GET_DK_CERT_P1,
            GET_DK_CERT_P2,
        );
        let trailer = common::CommandApduTrailer::new(
            Some(vec![u8::from(self.get_dk_cert_type())]),
            Some(GET_DK_CERT_LE),
        );
        let apdu_request = common::CommandApdu::new(
            header,
            Some(trailer),
        );
        apdu_request.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let apdu_request = common::CommandApdu::deserialize(data)?;
        let header = apdu_request.get_header();
        let trailer = apdu_request
            .get_trailer()
            .ok_or(format!("deserialize trailer is NULL"))?;
        if header.get_ins() != GET_DK_CERT_INS ||
            header.get_p1() != GET_DK_CERT_P1 ||
            header.get_p2() != GET_DK_CERT_P2 ||
            trailer.get_le().is_none() ||
            trailer.get_le().unwrap() != &GET_DK_CERT_LE {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize Apdu error")).into());
        }
        let dk_cert_type_data = trailer
            .get_data()
            .ok_or(format!("deserialize trailer data is NULL"))?;
        let dk_cert_type = DkCertType::try_from(dk_cert_type_data[0])
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize DK Certificate Type error: {}", e)))?;
        Ok(CommandApduGetDkCert::new(
            header.get_cla(),
            dk_cert_type,
        ))
    }
}

impl Display for CommandApduGetDkCert {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct ResponseApduGetDkCert {
    dk_cert_type: DkCertType,
    dk_cert: Vec<u8>,
    status: common::ResponseApduTrailer,
}

impl ResponseApduGetDkCert {
    pub fn new(dk_cert_type: DkCertType, dk_cert: &[u8], status: common::ResponseApduTrailer) -> Self {
        ResponseApduGetDkCert {
            dk_cert_type,
            dk_cert: dk_cert.to_vec(),
            status,
        }
    }
    pub fn get_dk_cert_type(&self) -> DkCertType {
        self.dk_cert_type
    }
    pub fn set_dk_cert_type(&mut self, dk_cert_type: DkCertType) {
        self.dk_cert_type = dk_cert_type;
    }
    pub fn get_dk_cert(&self) -> &[u8] {
        &self.dk_cert
    }
    pub fn set_dk_cert(&mut self, dk_cert: &[u8]) {
        self.dk_cert = dk_cert.to_vec();
    }
    pub fn get_status(&self) -> &common::ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: common::ResponseApduTrailer) {
        self.status = status;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let response_tag = match self.dk_cert_type {
            DkCertType::VehicleCACert => {
                ber::Tag::try_from(VEHICLE_CA_CERT_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle ca cert tag error: {}", e)))?
            },
            DkCertType::VehicleMasterKeyCert => {
                ber::Tag::try_from(VEHICLE_MASTER_KEY_CERT_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create vehicle master key cert tag error: {}", e)))?
            },
            DkCertType::TempSharedCert => {
                ber::Tag::try_from(TEMP_SHARED_CERT_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create temp shared cert tag error: {}", e)))?
            },
            DkCertType::FriendKeyCert => {
                ber::Tag::try_from(FRIEND_KEY_CERT_TAG)
                    .map_err(|e| ErrorKind::ApduInstructionErr(format!("create friend key cert tag error: {}", e)))?
            }
        };
        let cert_tag = ber::Tag::try_from(CERT_TAG)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner cert tag error: {}", e)))?;
        let cert_value = ber::Value::Primitive(self.get_dk_cert().to_vec());
        let cert_tlv = ber::Tlv::new(cert_tag, cert_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create inner cert tlv error: {}", e)))?;
        let response_value = ber::Value::Constructed(vec![cert_tlv]);
        let response_tlv = ber::Tlv::new(response_tag, response_value)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("create get dk certificate response tlv error: {}", e)))?;

        let response_apdu = common::ResponseApdu::new(
            Some(response_tlv.to_vec()),
            self.get_status().clone(),
        );
        response_apdu.serialize()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let response_apdu = common::ResponseApdu::deserialize(data)?;
        let body = response_apdu
            .get_body()
            .ok_or(format!("deserialize get dk certificate eror"))?;

        let response_tlv = ber::Tlv::from_bytes(body)
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize origin bytes error: {}", e)))?;
        let response_tag_bytes = response_tlv.tag().to_bytes();
        let cert_type = DkCertType::try_from(response_tag_bytes[0])
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize get dk certificate tag error: {}", e)))?;
        let cert = get_tlv_primitive_value(&response_tlv, response_tlv.tag())?;
        Ok(ResponseApduGetDkCert::new(
            cert_type,
            cert,
            response_apdu.get_trailer().clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_get_dk_cert_request() {
        let cla = 0x00;
        let dk_cert_type = DkCertType::VehicleCACert;
        let request = CommandApduGetDkCert::new(cla, dk_cert_type);
        assert_eq!(request.get_cla(), cla);
        assert_eq!(request.get_dk_cert_type(), DkCertType::VehicleCACert);

        let dk_cert_type = DkCertType::VehicleMasterKeyCert;
        let request = CommandApduGetDkCert::new(cla, dk_cert_type);
        assert_eq!(request.get_cla(), cla);
        assert_eq!(request.get_dk_cert_type(), DkCertType::VehicleMasterKeyCert);


        let dk_cert_type = DkCertType::TempSharedCert;
        let request = CommandApduGetDkCert::new(cla, dk_cert_type);
        assert_eq!(request.get_cla(), cla);
        assert_eq!(request.get_dk_cert_type(), DkCertType::TempSharedCert);


        let dk_cert_type = DkCertType::FriendKeyCert;
        let request = CommandApduGetDkCert::new(cla, dk_cert_type);
        assert_eq!(request.get_cla(), cla);
        assert_eq!(request.get_dk_cert_type(), DkCertType::FriendKeyCert);
    }
    #[test]
    fn test_update_get_dk_cert_request() {
        let cla = 0x00;
        let dk_cert_type = DkCertType::VehicleCACert;
        let mut request = CommandApduGetDkCert::new(cla, dk_cert_type);
        assert_eq!(request.get_cla(), cla);
        assert_eq!(request.get_dk_cert_type(), DkCertType::VehicleCACert);

        let new_cla = 0x0FF;
        let mut new_dk_cert_type = DkCertType::VehicleMasterKeyCert;
        request.set_cla(new_cla);
        request.set_dk_cert_type(new_dk_cert_type);
        assert_eq!(request.get_cla(), new_cla);
        assert_eq!(request.get_dk_cert_type(), DkCertType::VehicleMasterKeyCert);

        new_dk_cert_type = DkCertType::TempSharedCert;
        request.set_dk_cert_type(new_dk_cert_type);
        assert_eq!(request.get_dk_cert_type(), DkCertType::TempSharedCert);

        new_dk_cert_type = DkCertType::FriendKeyCert;
        request.set_dk_cert_type(new_dk_cert_type);
        assert_eq!(request.get_dk_cert_type(), DkCertType::FriendKeyCert);
    }
    #[test]
    fn test_get_dk_cert_request_serialize() {
        let cla = 0x00;
        let dk_cert_type = DkCertType::VehicleCACert;
        let request = CommandApduGetDkCert::new(cla, dk_cert_type);
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x00, 0x64, 0x00, 0x00,
                0x01,
                0x01,
                0x00,
            ],
        );
    }
    #[test]
    fn test_get_dk_cert_request_deserailize() {
        let data = vec![
            0x00, 0x64, 0x00, 0x00,
            0x01,
            0x01,
            0x00,
        ];
        let request = CommandApduGetDkCert::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.get_cla(), 0x00);
        assert_eq!(request.get_dk_cert_type(), DkCertType::VehicleCACert);
    }
    #[test]
    fn test_create_get_dk_cert_response() {
        let dk_cert_type = DkCertType::VehicleCACert;
        let vehicle_ca_cert = vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduGetDkCert::new(
            dk_cert_type,
            vehicle_ca_cert.as_ref(),
            status,
        );
        assert_eq!(response.get_dk_cert_type(), dk_cert_type);
        assert_eq!(response.get_dk_cert(), &vehicle_ca_cert);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_update_get_dk_cert_response() {
        let dk_cert_type = DkCertType::VehicleCACert;
        let vehicle_ca_cert = vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let mut response = ResponseApduGetDkCert::new(
            dk_cert_type,
            vehicle_ca_cert.as_ref(),
            status,
        );

        let new_status = common::ResponseApduTrailer::new(0x61, 0x10);
        let new_dk_cert_type = DkCertType::VehicleMasterKeyCert;
        let vehicle_master_key_cert = vec![
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        response.set_dk_cert_type(new_dk_cert_type);
        response.set_dk_cert(&vehicle_master_key_cert);
        response.set_status(new_status);
        assert_eq!(response.get_dk_cert_type(), new_dk_cert_type);
        assert_eq!(response.get_dk_cert(), &vehicle_master_key_cert);
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x61, 0x10));

        let new_dk_cert_type = DkCertType::TempSharedCert;
        let temp_shared_cert = vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ];
        response.set_dk_cert_type(new_dk_cert_type);
        response.set_dk_cert(&temp_shared_cert);
        assert_eq!(response.get_dk_cert_type(), new_dk_cert_type);
        assert_eq!(response.get_dk_cert(), &temp_shared_cert);

        let new_dk_cert_type = DkCertType::FriendKeyCert;
        let friend_key_cert = vec![
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        response.set_dk_cert_type(new_dk_cert_type);
        response.set_dk_cert(&friend_key_cert);
        assert_eq!(response.get_dk_cert_type(), new_dk_cert_type);
        assert_eq!(response.get_dk_cert(), &friend_key_cert);
    }
    #[test]
    fn test_get_dk_cert_response_serialize() {
        let dk_cert_type = DkCertType::VehicleCACert;
        let vehicle_ca_cert = vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ];
        let status = common::ResponseApduTrailer::new(0x90, 0x00);
        let response = ResponseApduGetDkCert::new(
            dk_cert_type,
            vehicle_ca_cert.as_ref(),
            status,
        );
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(
            serialized_response,
            vec![
                0x7F, 0x40, 0x42,
                0x01, 0x40,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_get_dk_cert_response_deserialize() {
        let data = vec![
            0x7F, 0x40, 0x42,
            0x01, 0x40,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x90, 0x00,
        ];
        let response_apdu = common::ResponseApdu::deserialize(data.as_ref());
        assert!(response_apdu.is_ok());
        let response_apdu = response_apdu.unwrap();
        let body = response_apdu.get_body();
        assert!(body.is_some());
        let body = body.unwrap();
        let status = response_apdu.get_trailer();
        let cert_tlv = ber::Tlv::from_bytes(body);
        assert!(cert_tlv.is_ok());
        let cert_tlv = cert_tlv.unwrap();
        let cert_tag = cert_tlv.tag().to_bytes();
        let cert_type = if cert_tag == &VEHICLE_CA_CERT_TAG.to_be_bytes() {
            Some(DkCertType::VehicleCACert)
        } else if cert_tag == &VEHICLE_MASTER_KEY_CERT_TAG.to_be_bytes() {
            Some(DkCertType::VehicleMasterKeyCert)
        } else if cert_tag == &TEMP_SHARED_CERT_TAG.to_be_bytes() {
            Some(DkCertType::TempSharedCert)
        } else if cert_tag == &FRIEND_KEY_CERT_TAG.to_be_bytes() {
            Some(DkCertType::FriendKeyCert)
        } else {
            None
        };
        assert!(cert_type.is_some());
        let cert_type = cert_type.unwrap();
        let tag = ber::Tag::try_from(CERT_TAG);
        assert!(tag.is_ok());
        let tag = tag.unwrap();
        let cert = get_tlv_primitive_value(&cert_tlv, &tag);
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        let response = ResponseApduGetDkCert::new(
            cert_type,
            cert,
            *status,
        );
        assert_eq!(response.get_dk_cert_type(), DkCertType::VehicleCACert);
        assert_eq!(
            response.get_dk_cert(),
            vec![
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            ],
        );
        assert_eq!(response.get_status(), &common::ResponseApduTrailer::new(0x90, 0x00));
    }
}