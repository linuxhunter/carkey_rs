use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::{create_tlv_with_constructed_value, create_tlv_with_primitive_value, get_tlv_primitive_value, Serde, identifier};
use crate::iccoa2::ble::{rke, vehicle_status};
use crate::iccoa2::errors::*;

#[allow(dead_code)]
const AUTH_REQUEST_RANDOM_TAG: u8 = 0x8B;
#[allow(dead_code)]
const AUTH_REQUEST_TAG: u8 = 0x8A;
#[allow(dead_code)]
const AUTH_RESPONSE_TAG: u16 = 0x7F2D;
#[allow(dead_code)]
const AUTH_RESPONSE_KEY_ID_TAG: u8 = 0x5D;
#[allow(dead_code)]
const AUTH_RESPONSE_SIGNATURE_TAG: u8 = 0x9E;
#[allow(dead_code)]
const AUTH_RANDOM_NUMBER_LENGTH: usize = 0x10;
#[allow(dead_code)]
const AUTH_SIGNATURE_LENGTH: usize = 0x40;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct AuthRequestRandom();

#[allow(dead_code)]
impl AuthRequestRandom {
    pub fn new() -> Self {
        AuthRequestRandom()
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tlv = create_tlv_with_primitive_value(AUTH_REQUEST_RANDOM_TAG, &[])
            .map_err(|e| ErrorKind::AuthError(format!("create auth request random tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }
    pub fn deserialize(_data: &[u8]) -> Result<Self> {
        Ok(AuthRequestRandom::new())
    }
}

impl Display for AuthRequestRandom {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.serialize().unwrap())
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct AuthRequest {
    random: [u8; AUTH_RANDOM_NUMBER_LENGTH],
}

#[allow(dead_code)]
impl AuthRequest {
    pub fn new(random: &[u8]) -> Result<Self> {
        if random.len() != AUTH_RANDOM_NUMBER_LENGTH {
            return Err(ErrorKind::AuthError("random number length is invalid".to_string()).into());
        }
        Ok(AuthRequest {
            random: random
                .try_into()
                .map_err(|e| ErrorKind::AuthError(format!("create auth request error: {}", e)))?
        })
    }
    pub fn get_random(&self) -> &[u8] {
        &self.random
    }
    pub fn set_random(&mut self, random: &[u8]) -> Result<()> {
        if random.len() != AUTH_RANDOM_NUMBER_LENGTH {
            return Err(ErrorKind::AuthError("random number length is invalid".to_string()).into());
        }
        self.random = random
            .try_into()
            .map_err(|e| ErrorKind::AuthError(format!("set auth request random number error: {}", e)))?;
        Ok(())
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tlv = create_tlv_with_primitive_value(AUTH_REQUEST_TAG, self.get_random())
            .map_err(|e| ErrorKind::AuthError(format!("create auth request tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::AuthError(format!("deserialize origin data bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != AUTH_REQUEST_TAG.to_be_bytes() {
            return Err(ErrorKind::AuthError("deserialize tag content error".to_string()).into());
        }
        let random = get_tlv_primitive_value(&tlv, tlv.tag())
            .map_err(|e| ErrorKind::AuthError(format!("deserialize random content error: {}", e)))?;
        AuthRequest::new(random)
    }
}

impl Display for AuthRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.random)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct AuthEntries {
    rke: Option<rke::RkeRequest>,
    subscribe: Option<vehicle_status::VehicleStatusRequest>,
    query: Option<vehicle_status::VehicleStatusRequest>,
    unsubscribe: Option<vehicle_status::VehicleStatusRequest>,
}

#[allow(dead_code)]
impl AuthEntries {
    pub fn new(
        rke: Option<rke::RkeRequest>,
        subscribe: Option<vehicle_status::VehicleStatusRequest>,
        query: Option<vehicle_status::VehicleStatusRequest>,
        unsubscribe: Option<vehicle_status::VehicleStatusRequest>) -> Self {
        AuthEntries {
            rke,
            subscribe,
            query,
            unsubscribe,
        }
    }
    pub fn get_rke(&self) -> Option<&rke::RkeRequest> {
        if self.rke.is_some() {
            self.rke.as_ref()
        } else {
            None
        }
    }
    pub fn set_rke(&mut self, rke: Option<rke::RkeRequest>) {
        self.rke = rke;
    }
    pub fn get_subscribe(&self) -> Option<&vehicle_status::VehicleStatusRequest> {
        if self.subscribe.is_some() {
            self.subscribe.as_ref()
        } else {
            None
        }
    }
    pub fn set_subscribe(&mut self, subscribe: Option<vehicle_status::VehicleStatusRequest>) {
        self.subscribe = subscribe;
    }
    pub fn get_query(&self) -> Option<&vehicle_status::VehicleStatusRequest> {
        if self.query.is_some() {
            self.query.as_ref()
        } else {
            None
        }
    }
    pub fn set_query(&mut self, query: Option<vehicle_status::VehicleStatusRequest>) {
        self.query = query;
    }
    pub fn get_unsubscribe(&self) -> Option<&vehicle_status::VehicleStatusRequest> {
        if self.unsubscribe.is_some() {
            self.unsubscribe.as_ref()
        } else {
            None
        }
    }
    pub fn set_unsubscribe(&mut self, unsubscribe: Option<vehicle_status::VehicleStatusRequest>) {
        self.unsubscribe = unsubscribe;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        if let Some(rke) = self.rke {
            buffer.append(&mut rke.serialize()?);
        }
        if let Some(subscribe) = self.subscribe {
            buffer.append(&mut subscribe.serialize()?);
        }
        if let Some(query) = self.query {
            buffer.append(&mut query.serialize()?);
        }
        if let Some(unsubscribe) = self.unsubscribe {
            buffer.append(&mut unsubscribe.serialize()?);
        }
        Ok(buffer)
    }
    pub fn get_tlv(&self) -> Option<Vec<ber::Tlv>> {
        let mut tlv_buffer = Vec::new();
        if let Some(rke) = self.rke {
            if let Ok(serialized_rke) = rke.serialize() {
                if let Ok(rke_tlv) = ber::Tlv::from_bytes(&serialized_rke) {
                    tlv_buffer.push(rke_tlv);
                }
            }
        }
        if let Some(subscribe) = self.subscribe {
            if let Ok(serialized_subscribe) = subscribe.serialize() {
                if let Ok(subscribe_tlv) = ber::Tlv::from_bytes(&serialized_subscribe) {
                    tlv_buffer.push(subscribe_tlv);
                }
            }
        }
        if let Some(query) = self.query {
            if let Ok(serialized_query) = query.serialize() {
                if let Ok(query_tlv) = ber::Tlv::from_bytes(&serialized_query) {
                    tlv_buffer.push(query_tlv);
                }
            }
        }
        if let Some(unsubscribe) = self.unsubscribe {
            if let Ok(serialized_unsubscribe) = unsubscribe.serialize() {
                if let Ok(unsubscribe_tlv) = ber::Tlv::from_bytes(&serialized_unsubscribe) {
                    tlv_buffer.push(unsubscribe_tlv);
                }
            }
        }
        if !tlv_buffer.is_empty() {
            Some(tlv_buffer)
        } else {
            None
        }
    }
}

impl Display for AuthEntries {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.rke.is_some() {
            write!(f, "rke: {}", self.rke.unwrap())?;
        } else {
            write!(f, "rke: None")?;
        }
        if self.subscribe.is_some() {
            write!(f, "{}", self.subscribe.unwrap())?;
        } else {
            write!(f, "subscribe: None")?;
        }
        if self.query.is_some() {
            write!(f, "{}", self.query.unwrap())?;
        } else {
            write!(f, "query: None")?;
        }
        if self.unsubscribe.is_some() {
            write!(f, "{}", self.unsubscribe.unwrap())
        } else {
            write!(f, "unsbscribe: None")
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct AuthResponse {
    key_id: identifier::KeyId,
    auth_entries: Option<AuthEntries>,
    signature: [u8; AUTH_SIGNATURE_LENGTH],
}

#[allow(dead_code)]
impl AuthResponse {
    pub fn new(key_id: identifier::KeyId, auth_entries: Option<AuthEntries>, signature: &[u8]) -> Result<Self> {
        Ok(AuthResponse {
            key_id,
            auth_entries,
            signature: signature
                .try_into()
                .map_err(|e| ErrorKind::AuthError(format!("create auth response signature error: {}", e)))?
        })
    }
    pub fn get_key_id(&self) -> &identifier::KeyId {
        &self.key_id
    }
    pub fn set_key_id(&mut self, key_id: identifier::KeyId) {
        self.key_id = key_id;
    }
    pub fn get_auth_entries(&self) -> Option<&AuthEntries> {
        if self.auth_entries.is_some() {
            self.auth_entries.as_ref()
        } else {
            None
        }
    }
    pub fn set_auth_entries(&mut self, auth_entries: Option<AuthEntries>) {
        self.auth_entries = auth_entries;
    }
    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }
    pub fn set_signature(&mut self, signature: &[u8]) -> Result<()> {
        self.signature = signature
            .try_into()
            .map_err(|e| ErrorKind::AuthError(format!("set signature error: {}", e)))?;
        Ok(())
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let key_id_tlv = create_tlv_with_primitive_value(AUTH_RESPONSE_KEY_ID_TAG, &self.get_key_id().serialize()?)
            .map_err(|e| ErrorKind::AuthError(format!("create key id tlv error: {}", e)))?;
        let signature_tlv = create_tlv_with_primitive_value(AUTH_RESPONSE_SIGNATURE_TAG, self.get_signature())
            .map_err(|e| ErrorKind::AuthError(format!("create signature tlv error: {}", e)))?;
        let auth_entries_tlv = match &self.auth_entries {
            Some(auth_entries) => {
                auth_entries.get_tlv()
            },
            None => None
        };
        let mut auth_response_values = Vec::new();
        auth_response_values.push(key_id_tlv);
        if let Some(mut auth_entries_tlv) = auth_entries_tlv {
            auth_response_values.append(&mut auth_entries_tlv);
        }
        auth_response_values.push(signature_tlv);

        let auth_response_tlv = create_tlv_with_constructed_value(AUTH_RESPONSE_TAG, &auth_response_values)
            .map_err(|e| ErrorKind::AuthError(format!("create auth reponse tlv error: {}", e)))?;
        Ok(auth_response_tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::AuthError(format!("deserialize origin bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != AUTH_RESPONSE_TAG.to_be_bytes() {
            return Err(ErrorKind::AuthError(format!("deserialize tag content is not {:02X?}", AUTH_RESPONSE_TAG)).into());
        }

        let key_id_tag = ber::Tag::try_from(AUTH_RESPONSE_KEY_ID_TAG)
            .map_err(|e| ErrorKind::AuthError(format!("create key id tag error: {}", e)))?;
        let key_id_value = get_tlv_primitive_value(&tlv, &key_id_tag)
            .map_err(|e| ErrorKind::AuthError(format!("deserialize key id value error: {}", e)))?;
        let key_id = identifier::KeyId::deserialize(key_id_value)
            .map_err(|e| ErrorKind::AuthError(format!("deserialize struct KeyId error: {}", e)))?;

        let signature_tag = ber::Tag::try_from(AUTH_RESPONSE_SIGNATURE_TAG)
            .map_err(|e| ErrorKind::AuthError(format!("create signature tag error: {}", e)))?;
        let signature_value = get_tlv_primitive_value(&tlv, &signature_tag)
            .map_err(|e| ErrorKind::AuthError(format!("deserialize signature value error: {}", e)))?;
        let signature = signature_value;

        let mut auth_entries = AuthEntries::new(None, None, None, None);
        let values = tlv.value();
        if let ber::Value::Constructed(tlv_collection) = values {
            for tlv in tlv_collection {
                let tag = tlv.tag().to_bytes();
                if tag == rke::RKE_REQUEST_TAG.to_be_bytes() {
                    if let Ok(rke) = rke::RkeRequest::deserialize(tlv.to_vec().as_ref()) {
                        auth_entries.set_rke(Some(rke));
                    }
                } else if tag == vehicle_status::SUBSCRIBE_REQUEST_TAG.to_be_bytes() {
                    if let Ok(subscribe) = vehicle_status::VehicleStatusRequest::deserialize(tlv.to_vec().as_ref()) {
                        auth_entries.set_subscribe(Some(subscribe));
                    }
                } else if tag == vehicle_status::QUERY_REQUEST_TAG.to_be_bytes() {
                    if let Ok(query) = vehicle_status::VehicleStatusRequest::deserialize(tlv.to_vec().as_ref()) {
                        auth_entries.set_query(Some(query));
                    }
                } else if tag == vehicle_status::UNSUBSCRIBE_REQUEST_TAG.to_be_bytes() {
                    if let Ok(unsubscribe) = vehicle_status::VehicleStatusRequest::deserialize(tlv.to_vec().as_ref()) {
                        auth_entries.set_unsubscribe(Some(unsubscribe));
                    }
                }
            }
        }
        let auth_entries = if auth_entries.get_rke().is_some() ||
            auth_entries.get_subscribe().is_some() ||
            auth_entries.get_query().is_some() ||
            auth_entries.get_unsubscribe().is_some() {
            Some(auth_entries)
        } else {
            None
        };
        AuthResponse::new(
            key_id,
            auth_entries,
            signature
        )
    }
}

impl Display for AuthResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "key id: {}, signature: {:02X?}", self.get_key_id(), self.get_signature())
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum Auth {
    RequestRandom(AuthRequestRandom),
    Request(AuthRequest),
    Response(AuthResponse),
}

#[allow(dead_code)]
impl Auth {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match self {
            Auth::RequestRandom(request) => request.serialize(),
            Auth::Request(request) => request.serialize(),
            Auth::Response(response) => response.serialize(),
        }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data[0] == AUTH_REQUEST_RANDOM_TAG {
            Ok(Auth::RequestRandom(AuthRequestRandom::deserialize(data)?))
        } else if data[0] ==AUTH_REQUEST_TAG {
            Ok(Auth::Request(AuthRequest::deserialize(data)?))
        } else {
            let tag = u16::from_be_bytes((&data[0..2])
                .try_into()
                .map_err(|e| ErrorKind::AuthError(format!("deserialize response tag error: {}", e)))?);
            if tag != AUTH_RESPONSE_TAG {
                return Err(ErrorKind::AuthError("deserialize response tag content is invalid".to_string()).into());
            }
            return Ok(Auth::Response(AuthResponse::deserialize(data)?));
        }
    }
}

impl Display for Auth {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Request(request) => write!(f, "{}", request),
            Auth::Response(response) => write!(f, "{}", response),
            Auth::RequestRandom(request) => write!(f, "{}", request),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_auth_request_random() {
        let auth_request_random = AuthRequestRandom::new().serialize();
        assert!(auth_request_random.is_ok());
        let auth_request_random = auth_request_random.unwrap();
        assert_eq!(auth_request_random, vec![0x8B, 0x00]);
    }
    #[test]
    fn test_create_auth_request() {
        let random = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let auth_request = AuthRequest::new(random.as_ref());
        assert!(auth_request.is_ok());
        let auth_request = auth_request.unwrap();
        assert_eq!(auth_request.get_random(), vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ]);
    }
    #[test]
    fn test_update_auth_request() {
        let random = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let auth_request = AuthRequest::new(random.as_ref());
        assert!(auth_request.is_ok());
        let mut auth_request = auth_request.unwrap();
        let updated_random = vec![
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        assert!(auth_request.set_random(updated_random.as_ref()).is_ok());
        assert_eq!(auth_request.get_random(), vec![
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ]);
    }
    #[test]
    fn test_create_auth_request_serialize() {
        let random = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let auth_request = AuthRequest::new(random.as_ref());
        assert!(auth_request.is_ok());
        let auth_request = auth_request.unwrap();
        let serialized_auth_request = auth_request.serialize();
        assert!(serialized_auth_request.is_ok());
        let serialized_auth_request = serialized_auth_request.unwrap();
        assert_eq!(serialized_auth_request, vec![
            0x8A, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ]);
    }
    #[test]
    fn test_create_auth_request_deserialize() {
        let data = vec![
            0x8A, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let auth_request = AuthRequest::deserialize(data.as_ref());
        assert!(auth_request.is_ok());
        let auth_request = auth_request.unwrap();
        assert_eq!(auth_request.get_random(), vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ]);
    }
    #[test]
    fn test_create_auth_response() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::new(
            key_id,
            None,
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        assert_eq!(
            auth_response.get_key_id(),
            &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap(),
        );
        assert_eq!(auth_response.get_auth_entries(), None);
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_create_auth_response_with_rke() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let rke = rke::RkeRequest::new(
            rke::RkeFunctions::DoorLock,
            rke::RkeActions::DoorLockAction(rke::DoorLockAction::Lock)
            ).unwrap();
        let subscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Subscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock
        );
        let query = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Query,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let unsubscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Unsubscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let auth_entries = AuthEntries::new(
            Some(rke),
            Some(subscribe),
            Some(query),
            Some(unsubscribe),
        );

        let auth_response = AuthResponse::new(
            key_id,
            Some(auth_entries),
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        assert_eq!(
            auth_response.get_key_id(),
            &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap(),
        );
        assert_eq!(
            auth_response.get_auth_entries(),
            Some(&AuthEntries::new(
                Some(rke),
                Some(subscribe),
                Some(query),
                Some(unsubscribe),
            ))
        );
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_update_auth_response() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::new(
            key_id,
            None,
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let mut auth_response = auth_response.unwrap();

        let updated_device_oem_id = 0x1112;
        let updated_vehicle_oem_id = 0x1314;
        let updated_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        let updated_key_id = identifier::KeyId::new(updated_device_oem_id, updated_vehicle_oem_id, &updated_key_serial_id);
        assert!(updated_key_id.is_ok());
        let updated_key_id = updated_key_id.unwrap();
        auth_response.set_key_id(updated_key_id);
        let rke = rke::RkeRequest::new(
            rke::RkeFunctions::DoorLock,
            rke::RkeActions::DoorLockAction(rke::DoorLockAction::Lock)
        ).unwrap();
        let subscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Subscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock
        );
        let query = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Query,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let unsubscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Unsubscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let auth_entries = AuthEntries::new(
            Some(rke),
            Some(subscribe),
            Some(query),
            Some(unsubscribe),
        );
        auth_response.set_auth_entries(Some(auth_entries));
        let updated_signature = vec![
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        ];
        assert!(auth_response.set_signature(updated_signature.as_ref()).is_ok());
        assert_eq!(
            auth_response.get_key_id(),
            &identifier::KeyId::new(updated_device_oem_id, updated_vehicle_oem_id, &updated_key_serial_id).unwrap(),
        );
        assert_eq!(
            auth_response.get_auth_entries(),
            Some(&AuthEntries::new(
               Some(rke::RkeRequest::new(rke::RkeFunctions::DoorLock, rke::RkeActions::DoorLockAction(rke::DoorLockAction::Lock)).unwrap()),
                Some(vehicle_status::VehicleStatusRequest::new(vehicle_status::VehicleStatusOperations::Subscribe, vehicle_status::VehicleStatusEntityId::DoorLock)),
                Some(vehicle_status::VehicleStatusRequest::new(vehicle_status::VehicleStatusOperations::Query, vehicle_status::VehicleStatusEntityId::DoorLock)),
                Some(vehicle_status::VehicleStatusRequest::new(vehicle_status::VehicleStatusOperations::Unsubscribe, vehicle_status::VehicleStatusEntityId::DoorLock)),
            ))
        );
        assert_eq!(auth_response.get_signature(), &updated_signature);
    }
    #[test]
    fn test_create_auth_response_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::new(
            key_id,
            None,
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let serialized_auth_response = auth_response.serialize();
        assert!(serialized_auth_response.is_ok());
        let serialized_auth_response = serialized_auth_response.unwrap();
        assert_eq!(serialized_auth_response, vec![
            0x7F, 0x2D, 0x54,
            0x5D, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x9E, 0x40,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ]);
    }
    #[test]
    fn test_create_auth_response_with_rke_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let rke = rke::RkeRequest::new(
            rke::RkeFunctions::DoorLock,
            rke::RkeActions::DoorLockAction(rke::DoorLockAction::Lock)
        ).unwrap();
        let auth_entries = AuthEntries::new(
            Some(rke),
            None,
            None,
            None,
        );

        let auth_response = AuthResponse::new(
            key_id,
            Some(auth_entries),
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let serialized_auth_response = auth_response.serialize();
        assert!(serialized_auth_response.is_ok());
        let serialized_auth_response = serialized_auth_response.unwrap();
        assert_eq!(
            serialized_auth_response,
            vec![
                0x7F, 0x2D, 0x5E,
                0x5D, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x7F, 0x70, 0x07,
                0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02,
                0x9E, 0x40,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ]
        );
    }
    #[test]
    fn test_create_auth_response_with_subscribe_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let subscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Subscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock
        );
        let auth_entries = AuthEntries::new(
            None,
            Some(subscribe),
            None,
            None,
        );

        let auth_response = AuthResponse::new(
            key_id,
            Some(auth_entries),
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let serialized_auth_response = auth_response.serialize();
        assert!(serialized_auth_response.is_ok());
        let serialized_auth_response = serialized_auth_response.unwrap();
        assert_eq!(
            serialized_auth_response,
            vec![
                0x7F, 0x2D, 0x5D,
                0x5D, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x7F, 0x73, 0x06,
                0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
                0x9E, 0x40,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ]
        );
    }
    #[test]
    fn test_create_auth_response_with_query_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let query = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Query,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let auth_entries = AuthEntries::new(
            None,
            None,
            Some(query),
            None,
        );

        let auth_response = AuthResponse::new(
            key_id,
            Some(auth_entries),
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let serialized_auth_response = auth_response.serialize();
        assert!(serialized_auth_response.is_ok());
        let serialized_auth_response = serialized_auth_response.unwrap();
        assert_eq!(
            serialized_auth_response,
            vec![
                0x7F, 0x2D, 0x5D,
                0x5D, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x7F, 0x74, 0x06,
                0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
                0x9E, 0x40,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ]
        );
    }
    #[test]
    fn test_create_auth_response_with_unsubscribe_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let unsubscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Unsubscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let auth_entries = AuthEntries::new(
            None,
            None,
            None,
            Some(unsubscribe),
        );

        let auth_response = AuthResponse::new(
            key_id,
            Some(auth_entries),
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let serialized_auth_response = auth_response.serialize();
        assert!(serialized_auth_response.is_ok());
        let serialized_auth_response = serialized_auth_response.unwrap();
        assert_eq!(
            serialized_auth_response,
            vec![
                0x7F, 0x2D, 0x5D,
                0x5D, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x7F, 0x75, 0x06,
                0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
                0x9E, 0x40,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ]
        );
    }
    #[test]
    fn test_create_auth_response_with_all_auth_entries_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let rke = rke::RkeRequest::new(
            rke::RkeFunctions::DoorLock,
            rke::RkeActions::DoorLockAction(rke::DoorLockAction::Lock)
        ).unwrap();
        let subscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Subscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock
        );
        let query = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Query,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let unsubscribe = vehicle_status::VehicleStatusRequest::new(
            vehicle_status::VehicleStatusOperations::Unsubscribe,
            vehicle_status::VehicleStatusEntityId::DoorLock,
        );
        let auth_entries = AuthEntries::new(
            Some(rke),
            Some(subscribe),
            Some(query),
            Some(unsubscribe),
        );

        let auth_response = AuthResponse::new(
            key_id,
            Some(auth_entries),
            signature.as_ref()
        );
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let serialized_auth_response = auth_response.serialize();
        assert!(serialized_auth_response.is_ok());
        let serialized_auth_response = serialized_auth_response.unwrap();
        assert_eq!(
            serialized_auth_response,
            vec![
                0x7F, 0x2D, 0x79,
                0x5D, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x7F, 0x70, 0x07,
                0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02,
                0x7F, 0x73, 0x06,
                0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
                0x7F, 0x74, 0x06,
                0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
                0x7F, 0x75, 0x06,
                0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
                0x9E, 0x40,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ]
        );
    }
    #[test]
    fn test_create_auth_response_deserialize() {
        let data = vec![
            0x7F, 0x2D, 0x54,
            0x5D, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x9E, 0x40,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::deserialize(data.as_ref());
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        assert_eq!(auth_response.get_key_id(), &key_id);
        assert_eq!(auth_response.get_auth_entries(), None);
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_create_auth_response_with_rke_deserialize() {
        let data =  vec![
            0x7F, 0x2D, 0x5E,
            0x5D, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x7F, 0x70, 0x07,
            0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02,
            0x9E, 0x40,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::deserialize(data.as_ref());
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        assert_eq!(auth_response.get_key_id(), &key_id);
        assert_eq!(auth_response.get_auth_entries(), Some(&AuthEntries::new(
            Some(rke::RkeRequest::new(
                rke::RkeFunctions::DoorLock,
                rke::RkeActions::DoorLockAction(rke::DoorLockAction::Lock)
            ).unwrap()),
            None,
            None,
            None,
        )));
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_create_auth_response_with_subscribe_deserialize() {
        let data =  vec![
            0x7F, 0x2D, 0x5D,
            0x5D, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x7F, 0x73, 0x06,
            0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
            0x9E, 0x40,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::deserialize(data.as_ref());
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        assert_eq!(auth_response.get_key_id(), &key_id);
        assert_eq!(auth_response.get_auth_entries(), Some(&AuthEntries::new(
            None,
            Some(vehicle_status::VehicleStatusRequest::new(
                vehicle_status::VehicleStatusOperations::Subscribe,
                vehicle_status::VehicleStatusEntityId::DoorLock,
            )),
            None,
            None,
        )));
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_create_auth_response_with_query_deserialize() {
        let data = vec![
            0x7F, 0x2D, 0x5D,
            0x5D, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x7F, 0x74, 0x06,
            0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
            0x9E, 0x40,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::deserialize(data.as_ref());
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        assert_eq!(auth_response.get_key_id(), &key_id);
        assert_eq!(auth_response.get_auth_entries(), Some(&AuthEntries::new(
            None,
            None,
            Some(vehicle_status::VehicleStatusRequest::new(
                vehicle_status::VehicleStatusOperations::Query,
                vehicle_status::VehicleStatusEntityId::DoorLock,
            )),
            None,
        )));
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_create_auth_response_with_unsubscribe_deserialize() {
        let data =  vec![
            0x7F, 0x2D, 0x5D,
            0x5D, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x7F, 0x75, 0x06,
            0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
            0x9E, 0x40,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::deserialize(data.as_ref());
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        assert_eq!(auth_response.get_key_id(), &key_id);
        assert_eq!(auth_response.get_auth_entries(), Some(&AuthEntries::new(
            None,
            None,
            None,
            Some(vehicle_status::VehicleStatusRequest::new(
                vehicle_status::VehicleStatusOperations::Unsubscribe,
                vehicle_status::VehicleStatusEntityId::DoorLock,
            )),
        )));
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_create_auth_response_with_all_auth_entries_deserialize() {
        let data = vec![
            0x7F, 0x2D, 0x79,
            0x5D, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x7F, 0x70, 0x07,
            0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02,
            0x7F, 0x73, 0x06,
            0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
            0x7F, 0x74, 0x06,
            0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
            0x7F, 0x75, 0x06,
            0x30, 0x04, 0x84, 0x02, 0x00, 0x01,
            0x9E, 0x40,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let auth_response = AuthResponse::deserialize(data.as_ref());
        assert!(auth_response.is_ok());
        let auth_response = auth_response.unwrap();
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        assert_eq!(auth_response.get_key_id(), &key_id);
        assert_eq!(auth_response.get_auth_entries(), Some(&AuthEntries::new(
            Some(rke::RkeRequest::new(
                rke::RkeFunctions::DoorLock,
                rke::RkeActions::DoorLockAction(rke::DoorLockAction::Lock)
            ).unwrap()),
            Some(vehicle_status::VehicleStatusRequest::new(
                vehicle_status::VehicleStatusOperations::Subscribe,
                vehicle_status::VehicleStatusEntityId::DoorLock,
            )),
            Some(vehicle_status::VehicleStatusRequest::new(
                vehicle_status::VehicleStatusOperations::Query,
                vehicle_status::VehicleStatusEntityId::DoorLock,
            )),
            Some(vehicle_status::VehicleStatusRequest::new(
                vehicle_status::VehicleStatusOperations::Unsubscribe,
                vehicle_status::VehicleStatusEntityId::DoorLock,
            )),
        )));
        let signature = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        assert_eq!(auth_response.get_signature(), &signature);
    }
    #[test]
    fn test_create_auth_serialize() {
        let random = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let auth_request = AuthRequest::new(random.as_ref());
        assert!(auth_request.is_ok());
        let auth_request = auth_request.unwrap();
        let auth = Auth::Request(auth_request);
        let serialized_auth_request = auth.serialize();
        assert!(serialized_auth_request.is_ok());
        let serialized_auth_request = serialized_auth_request.unwrap();
        assert_eq!(serialized_auth_request, vec![
            0x8A, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ]);
    }
    #[test]
    fn test_create_auth_deserialize() {
        let data = vec![
            0x8A, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let auth = Auth::Request(AuthRequest::deserialize(data.as_ref()).unwrap());
        if let Auth::Request(auth_request) = auth {
            assert_eq!(auth_request.get_random(), vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            ]);
        }
    }
}
