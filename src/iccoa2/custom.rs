use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::get_tlv_primitive_value;
use super::errors::*;

const VEHICLE_APP_CUSTOM_REQUEST_TAG: u8 = 0x80;
const VEHICLE_APP_CUSTOM_RESPONSE_TAG: u8 = 0x81;
const VEHICLE_SERVER_CUSTOM_REQUEST_TAG: u8 = 0x82;
const VEHICLE_SERVER_CUSTOM_RESPONSE_TAG: u8 = 0x83;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleAppCustomRequest {
    inner: Vec<u8>,
}

impl VehicleAppCustomRequest {
    pub fn new(custom_data: &[u8]) -> Self {
        VehicleAppCustomRequest {
            inner: custom_data.to_vec(),
        }
    }
    pub fn get_custom_data(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_custom_data(&mut self, custom_data: &[u8]) {
        self.inner = custom_data.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tag = ber::Tag::try_from(VEHICLE_APP_CUSTOM_REQUEST_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle app custom request tag error: {}", e)))?;
        let value = ber::Value::Primitive(self.inner.clone());
        let tlv = ber::Tlv::new(tag, value)
            .map_err(|e| ErrorKind::CustomError(format!("crate vehicle app custom request tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize from bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != VEHICLE_APP_CUSTOM_REQUEST_TAG.to_be_bytes() {
            return Err(ErrorKind::CustomError(format!("deserialize tag value is invalid")).into());
        }
        let tag = ber::Tag::try_from(VEHICLE_APP_CUSTOM_REQUEST_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle app custom request tag error: {}", e)))?;
        let custom_data = get_tlv_primitive_value(&tlv, &tag)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize custom data error: {}", e)))?;
        Ok(VehicleAppCustomRequest::new(custom_data))
    }
}

impl Display for VehicleAppCustomRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.inner)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleAppCustomResponse {
    inner: Vec<u8>,
}

impl VehicleAppCustomResponse {
    pub fn new(custom_data: &[u8]) -> Self {
        VehicleAppCustomResponse {
            inner: custom_data.to_vec(),
        }
    }
    pub fn get_custom_data(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_custom_data(&mut self, custom_data: &[u8]) {
        self.inner = custom_data.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tag = ber::Tag::try_from(VEHICLE_APP_CUSTOM_RESPONSE_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle app custom response tag error: {}", e)))?;
        let value = ber::Value::Primitive(self.inner.clone());
        let tlv = ber::Tlv::new(tag, value)
            .map_err(|e| ErrorKind::CustomError(format!("crate vehicle app custom response tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize from bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != VEHICLE_APP_CUSTOM_RESPONSE_TAG.to_be_bytes() {
            return Err(ErrorKind::CustomError(format!("deserialize tag value is invalid")).into());
        }
        let tag = ber::Tag::try_from(VEHICLE_APP_CUSTOM_RESPONSE_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle app custom response tag error: {}", e)))?;
        let custom_data = get_tlv_primitive_value(&tlv, &tag)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize custom data error: {}", e)))?;
        Ok(VehicleAppCustomResponse::new(custom_data))
    }
}

impl Display for VehicleAppCustomResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.inner)
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct VehicleServerCustomRequest {
    offset: u16,
    length: u8,
}

impl VehicleServerCustomRequest {
    pub fn new(offset: u16, length: u8) -> Self {
        VehicleServerCustomRequest {
            offset,
            length,
        }
    }
    pub fn get_offset(&self) -> u16 {
        self.offset
    }
    pub fn set_offset(&mut self, offset: u16) {
        self.offset = offset;
    }
    pub fn get_length(&self) -> u8 {
        self.length
    }
    pub fn set_length(&mut self, length: u8) {
        self.length = length;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tag = ber::Tag::try_from(VEHICLE_SERVER_CUSTOM_REQUEST_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle server request tag error: {}", e)))?;
        let mut data_buffer = Vec::with_capacity(3);
        data_buffer.append(&mut self.offset.to_be_bytes().to_vec());
        data_buffer.push(self.length);
        let value = ber::Value::Primitive(data_buffer);
        let tlv = ber::Tlv::new(tag, value)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle server request tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize from bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != VEHICLE_SERVER_CUSTOM_REQUEST_TAG.to_be_bytes() {
            return Err(ErrorKind::CustomError(format!("deserialize tag value is invalid")).into());
        }
        let tag = ber::Tag::try_from(VEHICLE_SERVER_CUSTOM_REQUEST_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle server custom request tag error: {}", e)))?;
        let custom_data = get_tlv_primitive_value(&tlv, &tag)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize custom data error: {}", e)))?;
        if custom_data.len() < 3 {
            return Err(ErrorKind::CustomError(format!("deserialize custom data length less than 3")).into());
        }
        let offset = u16::from_be_bytes(
            (&custom_data[0..2])
                .try_into()
                .map_err(|e| ErrorKind::CustomError(format!("deserialize offset value error: {}", e)))?
        );
        let length = custom_data[2];
        Ok(VehicleServerCustomRequest::new(offset, length))
    }
}

impl Display for VehicleServerCustomRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "offset: {}, length: {}", self.offset, self.length)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleServerCustomResponse {
    inner: Vec<u8>,
}

impl VehicleServerCustomResponse {
    pub fn new(custom_data: &[u8]) -> Self {
        VehicleServerCustomResponse {
            inner: custom_data.to_vec(),
        }
    }
    pub fn get_custom_data(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_custom_data(&mut self, custom_data: &[u8]) {
        self.inner = custom_data.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tag = ber::Tag::try_from(VEHICLE_SERVER_CUSTOM_RESPONSE_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle server custom response tag error: {}", e)))?;
        let value = ber::Value::Primitive(self.inner.clone());
        let tlv = ber::Tlv::new(tag, value)
            .map_err(|e| ErrorKind::CustomError(format!("crate vehicle server custom response tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize from bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != VEHICLE_SERVER_CUSTOM_RESPONSE_TAG.to_be_bytes() {
            return Err(ErrorKind::CustomError(format!("deserialize tag value is invalid")).into());
        }
        let tag = ber::Tag::try_from(VEHICLE_SERVER_CUSTOM_RESPONSE_TAG)
            .map_err(|e| ErrorKind::CustomError(format!("create vehicle server custom response tag error: {}", e)))?;
        let custom_data = get_tlv_primitive_value(&tlv, &tag)
            .map_err(|e| ErrorKind::CustomError(format!("deserialize custom data error: {}", e)))?;
        Ok(VehicleServerCustomResponse::new(custom_data))
    }
}

impl Display for VehicleServerCustomResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.inner)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum CustomMessage {
    VehicleAppCustomRequest(VehicleAppCustomRequest),
    VehicleAppCustomResponse(VehicleAppCustomResponse),
    VehicleServerCustomRequest(VehicleServerCustomRequest),
    VehicleServerCustomResponse(VehicleServerCustomResponse),
}

impl CustomMessage {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match self {
            CustomMessage::VehicleAppCustomRequest(request) => request.serialize(),
            CustomMessage::VehicleAppCustomResponse(response) => response.serialize(),
            CustomMessage::VehicleServerCustomRequest(request) => request.serialize(),
            CustomMessage::VehicleServerCustomResponse(response) => response.serialize(),
        }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        match data[0] {
            0x80 => Ok(CustomMessage::VehicleAppCustomRequest(VehicleAppCustomRequest::deserialize(data)?)),
            0x81 => Ok(CustomMessage::VehicleAppCustomResponse(VehicleAppCustomResponse::deserialize(data)?)),
            0x82 => Ok(CustomMessage::VehicleServerCustomRequest(VehicleServerCustomRequest::deserialize(data)?)),
            0x83 => Ok(CustomMessage::VehicleServerCustomResponse(VehicleServerCustomResponse::deserialize(data)?)),
            _ => Err(ErrorKind::CustomError(format!("unsupported custom data tag")).into()),
        }
    }
}

impl Display for CustomMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomMessage::VehicleAppCustomRequest(request) => write!(f, "Vehicle App Request: {}", request),
            CustomMessage::VehicleAppCustomResponse(response) => write!(f, "Vehicle App Response: {}", response),
            CustomMessage::VehicleServerCustomRequest(request) => write!(f, "Vehicle Server Request: {}", request),
            CustomMessage::VehicleServerCustomResponse(response) => write!(f, "Vehicle Server Response: {}", response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_vehicle_app_request() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let request = VehicleAppCustomRequest::new(custom_data.as_ref());
        assert_eq!(request.get_custom_data(), &custom_data);
    }
    #[test]
    fn test_update_vehicle_app_request() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let mut request = VehicleAppCustomRequest::new(custom_data.as_ref());
        let updated_custom_data = vec![0x03, 0x02, 0x01, 0x00];
        request.set_custom_data(updated_custom_data.as_ref());
        assert_eq!(request.get_custom_data(), &updated_custom_data);
    }
    #[test]
    fn test_create_vehicle_app_request_serialize() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let request = VehicleAppCustomRequest::new(custom_data.as_ref());
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(serialized_request, vec![0x80, 0x04, 0x00, 0x01, 0x02, 0x03]);
    }
    #[test]
    fn test_create_vehicle_app_request_deserialize() {
        let data = vec![0x80, 0x04, 0x00, 0x01, 0x02, 0x03];
        let request = VehicleAppCustomRequest::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request, VehicleAppCustomRequest::new(vec![0x00, 0x01, 0x02, 0x03].as_ref()));
    }
    #[test]
    fn test_create_vehicle_app_response() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let response = VehicleAppCustomResponse::new(custom_data.as_ref());
        assert_eq!(response.get_custom_data(), &vec![0x00, 0x01, 0x02, 0x03]);
    }
    #[test]
    fn test_update_vehicle_app_response() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let mut response = VehicleAppCustomResponse::new(custom_data.as_ref());
        let updated_custom_data = vec![0x03, 0x02, 0x01, 0x00];
        response.set_custom_data(updated_custom_data.as_ref());
        assert_eq!(response.get_custom_data(), &updated_custom_data);
    }
    #[test]
    fn test_create_vehicle_app_response_serialize() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let response = VehicleAppCustomResponse::new(custom_data.as_ref());
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x81, 0x04, 0x00, 0x01, 0x02, 0x03]);
    }
    #[test]
    fn test_create_vehicle_app_response_deserialize() {
        let data = vec![0x81, 0x04, 0x00, 0x01, 0x02, 0x03];
        let response = VehicleAppCustomResponse::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response, VehicleAppCustomResponse::new(vec![0x00, 0x01, 0x02, 0x03].as_ref()));
    }
    #[test]
    fn test_create_vehicle_server_request() {
        let offset = 0x0102;
        let length = 0x03;
        let request = VehicleServerCustomRequest::new(offset, length);
        assert_eq!(request.get_offset(), offset);
        assert_eq!(request.get_length(), length);
    }
    #[test]
    fn test_update_vehicle_server_request() {
        let offset = 0x0102;
        let length = 0x03;
        let mut request = VehicleServerCustomRequest::new(offset, length);
        let updated_offset = 0x0405;
        let updated_length = 0x06;
        request.set_offset(updated_offset);
        request.set_length(updated_length);
        assert_eq!(request.get_offset(), updated_offset);
        assert_eq!(request.get_length(), updated_length);
    }
    #[test]
    fn test_create_vehicle_server_request_serialize() {
        let offset = 0x0102;
        let length = 0x03;
        let request = VehicleServerCustomRequest::new(offset, length);
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(serialized_request, vec![0x82, 0x03, 0x01, 0x02, 0x03]);
    }
    #[test]
    fn test_create_vehicle_server_request_deserialize() {
        let data = vec![0x82, 0x03, 0x01, 0x02, 0x03];
        let request = VehicleServerCustomRequest::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request, VehicleServerCustomRequest::new(0x0102, 0x03));
    }
    #[test]
    fn test_create_vehicle_server_response() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let response = VehicleServerCustomResponse::new(custom_data.as_ref());
        assert_eq!(response.get_custom_data(), &custom_data);
    }
    #[test]
    fn test_update_vehicle_server_response() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let mut response = VehicleServerCustomResponse::new(custom_data.as_ref());
        let updated_custom_data = vec![0x03, 0x02, 0x01, 0x00];
        response.set_custom_data(updated_custom_data.as_ref());
        assert_eq!(response.get_custom_data(), &updated_custom_data);
    }
    #[test]
    fn test_create_vehicle_server_response_serialize() {
        let custom_data = vec![0x00, 0x01, 0x02, 0x03];
        let response = VehicleServerCustomResponse::new(custom_data.as_ref());
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x83, 0x04, 0x00, 0x01, 0x02, 0x03]);
    }
    #[test]
    fn test_create_vehicle_server_response_deserialize() {
        let data = vec![0x83, 0x04, 0x00, 0x01, 0x02, 0x03];
        let response = VehicleServerCustomResponse::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response, VehicleServerCustomResponse::new(vec![0x00, 0x01, 0x02, 0x03].as_ref()));
    }
}
