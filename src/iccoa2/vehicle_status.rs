use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::{create_tlv_with_constructed_value, create_tlv_with_primitive_value, get_tlv_primitive_value};
use super::errors::*;

#[allow(dead_code)]
const ENTITY_MIDDLE_TAG: u8 = 0x30;
#[allow(dead_code)]
const ENTITY_SECOND_MIDDLE_TAG: u8 = 0xA0;
#[allow(dead_code)]
const ENTITY_REQUEST_TAG: u8 = 0x84;
#[allow(dead_code)]
const ALL_ENTITIES_REQUEST_TAG: u8 = 0x86;
#[allow(dead_code)]
const ENTITY_RESPONSE_TAG: u8 = 0x80;
#[allow(dead_code)]
const ENTITY_STATUS_RESPONSE_TAG: u8 = 0x89;
#[allow(dead_code)]
const RANDOM_NUMBER_TAG: u8 = 0x8A;
#[allow(dead_code)]
pub const SUBSCRIBE_REQUEST_TAG: u16 = 0x7F73;
#[allow(dead_code)]
pub const QUERY_REQUEST_TAG: u16 = 0x7F74;
#[allow(dead_code)]
pub const UNSUBSCRIBE_REQUEST_TAG: u16 = 0x7F75;
#[allow(dead_code)]
const VEHICLE_STATUS_RESPONSE_TAG: u16 = 0x7F77;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum VehicleStatusEntityId {
    All = 0x0000,
    DoorLock = 0x0001,
    CarWindow = 0x0002,
    BackTrunk = 0x0003,
    Engine = 0x0004,
    AirConditioner = 0x0005,
    CarLight = 0x0006,
    Custom = 0x1001,
}

impl TryFrom<u16> for VehicleStatusEntityId {
    type Error = String;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(VehicleStatusEntityId::All),
            0x0001 => Ok(VehicleStatusEntityId::DoorLock),
            0x0002 => Ok(VehicleStatusEntityId::CarWindow),
            0x0003 => Ok(VehicleStatusEntityId::BackTrunk),
            0x0004 => Ok(VehicleStatusEntityId::Engine),
            0x0005 => Ok(VehicleStatusEntityId::AirConditioner),
            0x0006 => Ok(VehicleStatusEntityId::CarLight),
            _ => {
                if value >= 0x1001 {
                    Ok(VehicleStatusEntityId::Custom)
                } else {
                    Err(format!("Unsupported Vehicle Entity Id from u16 {}", value))
                }
            }
        }
    }
}

impl From<VehicleStatusEntityId> for u16 {
    fn from(value: VehicleStatusEntityId) -> Self {
        match value {
            VehicleStatusEntityId::All => 0x0000,
            VehicleStatusEntityId::DoorLock => 0x0001,
            VehicleStatusEntityId::CarWindow => 0x0002,
            VehicleStatusEntityId::BackTrunk => 0x0003,
            VehicleStatusEntityId::Engine => 0x0004,
            VehicleStatusEntityId::AirConditioner => 0x0005,
            VehicleStatusEntityId::CarLight => 0x0006,
            VehicleStatusEntityId::Custom => 0x1001,
        }
    }
}

impl Display for VehicleStatusEntityId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VehicleStatusEntityId::All => write!(f, "All"),
            VehicleStatusEntityId::DoorLock => write!(f, "Door Lock"),
            VehicleStatusEntityId::CarWindow => write!(f, "Car Window"),
            VehicleStatusEntityId::BackTrunk => write!(f, "Back Trunk"),
            VehicleStatusEntityId::Engine => write!(f, "Engine"),
            VehicleStatusEntityId::AirConditioner => write!(f, "Air Conditioner"),
            VehicleStatusEntityId::CarLight => write!(f, "Car Light"),
            VehicleStatusEntityId::Custom => write!(f, "Custom"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum VehicleStatusOperations {
    Subscribe,
    Query,
    Unsubscribe,
}

impl TryFrom<u16> for VehicleStatusOperations {
    type Error = String;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            SUBSCRIBE_REQUEST_TAG => Ok(VehicleStatusOperations::Subscribe),
            QUERY_REQUEST_TAG => Ok(VehicleStatusOperations::Query),
            UNSUBSCRIBE_REQUEST_TAG => Ok(VehicleStatusOperations::Unsubscribe),
            _ => Err(format!("Unsupported vehicle status operation value: {}", value)),
        }
    }
}

impl Display for VehicleStatusOperations {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VehicleStatusOperations::Subscribe => write!(f, "Subscribe"),
            VehicleStatusOperations::Query => write!(f, "Query"),
            VehicleStatusOperations::Unsubscribe => write!(f, "Unsubscribe"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct VehicleStatusRequest {
    operation: VehicleStatusOperations,
    entity_id: VehicleStatusEntityId,
}

#[allow(dead_code)]
impl VehicleStatusRequest {
    pub fn new(operation: VehicleStatusOperations, entity_id: VehicleStatusEntityId) -> Self {
        VehicleStatusRequest {
            operation,
            entity_id,
        }
    }
    pub fn get_operation(&self) -> VehicleStatusOperations {
        self.operation
    }
    pub fn set_operation(&mut self, operation: VehicleStatusOperations) {
        self.operation = operation;
    }
    pub fn get_entity_id(&self) -> VehicleStatusEntityId {
        self.entity_id
    }
    pub fn set_entity_id(&mut self, entity_id: VehicleStatusEntityId) {
        self.entity_id = entity_id;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tlv = if self.get_entity_id() == VehicleStatusEntityId::All {
            create_tlv_with_primitive_value(ALL_ENTITIES_REQUEST_TAG, &[])
                .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status entity all tlv error: {}", e)))?
        } else {
            let entity_id_tlv = create_tlv_with_primitive_value(ENTITY_REQUEST_TAG, &u16::from(self.get_entity_id()).to_be_bytes())
                .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status entity id tlv error: {}", e)))?;
            create_tlv_with_constructed_value(u16::from(ENTITY_MIDDLE_TAG), &[entity_id_tlv])
                .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status entity middle tlv error: {}", e)))?
        };
        let vehicle_status_tag = match self.get_operation() {
            VehicleStatusOperations::Subscribe => {
                ber::Tag::try_from(SUBSCRIBE_REQUEST_TAG)
                    .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status subscribe tag error: {}", e)))?
            },
            VehicleStatusOperations::Query => {
                ber::Tag::try_from(QUERY_REQUEST_TAG)
                    .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status query tag error: {}", e)))?
            },
            VehicleStatusOperations::Unsubscribe => {
                ber::Tag::try_from(UNSUBSCRIBE_REQUEST_TAG)
                    .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status unsubscribe tag error: {}", e)))?
            },
        };
        let vehicle_status_value = ber::Value::Constructed(vec![tlv]);
        let vehicle_status_tlv = ber::Tlv::new(vehicle_status_tag, vehicle_status_value)
            .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status tlv error: {}", e)))?;
        Ok(vehicle_status_tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize original tlv data error: {}", e)))?;
        if !tlv.tag().is_constructed() {
            return Err(ErrorKind::VehicleStatusError("deserialize tlv tag is not constructed".to_string()).into());
        }
        let top_tag = tlv.tag().to_bytes();
        let operation = VehicleStatusOperations::try_from(
            u16::from_be_bytes(
                (&top_tag[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize translate operation tag to u16 error: {}", e)))?
            )
        ).map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize get operation tag error: {}", e)))?;
        let middle_tag = ber::Tag::try_from(ALL_ENTITIES_REQUEST_TAG)
            .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize create vehicle status entity middle tag error: {}", e)))?;
        match tlv.find(&middle_tag) {
            Some(_) => {
                Ok(VehicleStatusRequest {
                    operation,
                    entity_id: VehicleStatusEntityId::All,
                })
            },
            None => {
                let entity_id_tag = ber::Tag::try_from(ENTITY_REQUEST_TAG)
                    .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status entity id tag error: {}", e)))?;
                let entity_id_value = get_tlv_primitive_value(&tlv, &entity_id_tag)
                    .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize get entity id value error: {}", e)))?;
                let entity_id = VehicleStatusEntityId::try_from(
                    u16::from_be_bytes(
                        (&entity_id_value[0..2])
                            .try_into()
                            .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize translate entity id to u16 error: {}", e)))?
                    )
                ).map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize create entity id error: {}", e)))?;
                Ok(VehicleStatusRequest {
                    operation,
                    entity_id,
                })
            }
        }
    }
}

impl Display for VehicleStatusRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation: {}, Entity Id: {}", self.operation, self.entity_id)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct SubscribeVerificationResponse {
    inner: Vec<u8>,
}

#[allow(dead_code)]
impl SubscribeVerificationResponse {
    pub fn new(random: &[u8]) -> Self {
        SubscribeVerificationResponse {
            inner: random.to_vec(),
        }
    }
    pub fn get_verification_response(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_verification_response(&mut self, random: &[u8]) {
        self.inner = random.to_vec();
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tlv = create_tlv_with_primitive_value(RANDOM_NUMBER_TAG, self.get_verification_response())
            .map_err(|e| ErrorKind::RkeError(format!("create subscribe verification response tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize subscribe verification response from bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != RANDOM_NUMBER_TAG.to_be_bytes() {
            return Err(ErrorKind::RkeError("deserialized random number tag is not corrected".to_string()).into());
        }
        let value = get_tlv_primitive_value(&tlv, tlv.tag())
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke verification response value error: {}", e)))?;
        Ok(SubscribeVerificationResponse::new(value))
    }
}

impl Display for SubscribeVerificationResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.inner)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleStatusResponse {
    entity_id: VehicleStatusEntityId,
    status: u16,
    random: Option<SubscribeVerificationResponse>,
}

#[allow(dead_code)]
impl VehicleStatusResponse {
    pub fn new(entity_id: VehicleStatusEntityId, status: u16, random: Option<SubscribeVerificationResponse>) -> Self {
        VehicleStatusResponse {
            entity_id,
            status,
            random,
        }
    }
    pub fn get_entity_id(&self) -> VehicleStatusEntityId {
        self.entity_id
    }
    pub fn set_entity_id(&mut self, entity_id: VehicleStatusEntityId) {
        self.entity_id = entity_id;
    }
    pub fn get_status(&self) -> u16 {
        self.status
    }
    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }
    pub fn get_random(&self) -> Option<&SubscribeVerificationResponse> {
        if self.random.is_some() {
            self.random.as_ref()
        } else {
            None
        }
    }
    pub fn set_random(&mut self, random: Option<SubscribeVerificationResponse>) {
        self.random = random;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let entity_id_tlv = create_tlv_with_primitive_value(ENTITY_RESPONSE_TAG, &u16::from(self.get_entity_id()).to_be_bytes())
            .map_err(|e| ErrorKind::VehicleStatusError(format!("create entity id tlv error: {}", e)))?;
        let status_tlv = create_tlv_with_primitive_value(ENTITY_STATUS_RESPONSE_TAG, &self.get_status().to_be_bytes())
            .map_err(|e| ErrorKind::VehicleStatusError(format!("crate entity status tlv error: {}", e)))?;
        let second_middle_tlv = create_tlv_with_constructed_value(u16::from(ENTITY_SECOND_MIDDLE_TAG), &[entity_id_tlv, status_tlv])
            .map_err(|e| ErrorKind::VehicleStatusError(format!("create second middle tlv error: {}", e)))?;
        let middle_tlv = create_tlv_with_constructed_value(u16::from(ENTITY_MIDDLE_TAG), &[second_middle_tlv])
            .map_err(|e| ErrorKind::VehicleStatusError(format!("crate middle tlv error: {}", e)))?;
        let response_tlv = create_tlv_with_constructed_value(VEHICLE_STATUS_RESPONSE_TAG, &[middle_tlv])
            .map_err(|e| ErrorKind::VehicleStatusError(format!("create vehicle status response tlv error: {}", e)))?;
        if self.random.is_none() {
            Ok(response_tlv.to_vec())
        } else {
            let mut serialized_random = self.random.as_ref().unwrap().serialize()?;
            let mut response = response_tlv.to_vec();
            response.append(&mut serialized_random);
            Ok(response)
        }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let tlv_all = ber::Tlv::parse_all(data);
        if tlv_all.is_empty() {
            return Err(ErrorKind::VehicleStatusError("deserialize response tlv error".to_string()).into());
        }
        let tlv = &tlv_all[0];
        if tlv.tag().to_bytes() != VEHICLE_STATUS_RESPONSE_TAG.to_be_bytes() {
            return Err(ErrorKind::VehicleStatusError("deserialize response tag value error".to_string()).into());
        }
        if !tlv.value().is_constructed() {
            return Err(ErrorKind::VehicleStatusError("deserialize response value is not constructed".to_string()).into());
        }
        let entity_tag = ber::Tag::try_from(ENTITY_RESPONSE_TAG)
            .map_err(|e| ErrorKind::VehicleStatusError(format!("create response entity id tag error: {}", e)))?;
        let entity_value = get_tlv_primitive_value(tlv, &entity_tag)
            .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize get entity id value error: {}", e)))?;
        let entity_id = VehicleStatusEntityId::try_from(
            u16::from_be_bytes(
                (&entity_value[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize translate u16 entity id error: {}", e)))?
            )
        ).map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize translate entity id error: {}", e)))?;
        let status_tag = ber::Tag::try_from(ENTITY_STATUS_RESPONSE_TAG)
            .map_err(|e| ErrorKind::VehicleStatusError(format!("create response status tag error: {}", e)))?;
        let status_value = get_tlv_primitive_value(tlv, &status_tag)
            .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize get status value error: {}", e)))?;
        let status = u16::from_be_bytes(
            (&status_value[0..2])
                .try_into()
                .map_err(|e| ErrorKind::VehicleStatusError(format!("deserialize translate u16 status error: {}", e)))?
        );
        let random = if tlv_all.len() > 1 {
            let tlv = &tlv_all[1];
            let random_tag = ber::Tag::try_from(RANDOM_NUMBER_TAG)
                .map_err(|e| ErrorKind::VehicleStatusError(format!("create random number tag error: {}", e)))?;
            let random_value = get_tlv_primitive_value(tlv, &random_tag)
                .map_err(|e| ErrorKind::VehicleStatusError(format!("get random number value error: {}", e)))?;
            Some(SubscribeVerificationResponse::new(random_value))
        } else {
            None
        };
        Ok(VehicleStatusResponse {
            entity_id,
            status,
            random,
        })
    }
}

impl Display for VehicleStatusResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Entity Id: {}, Status: {}, Random: {:?}", self.entity_id, self.status, self.random)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum VehicleStatus {
    Request(VehicleStatusRequest),
    Response(VehicleStatusResponse),
    SubscribeVerificationResponse(SubscribeVerificationResponse),
}

#[allow(dead_code)]
impl VehicleStatus {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match self {
            VehicleStatus::Request(request) => request.serialize(),
            VehicleStatus::Response(response) => response.serialize(),
            VehicleStatus::SubscribeVerificationResponse(response) => response.serialize(),
        }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data[0] == RANDOM_NUMBER_TAG {
            Ok(VehicleStatus::SubscribeVerificationResponse(SubscribeVerificationResponse::deserialize(data)?))
        } else {
            let tag = u16::from_be_bytes(
                (&data[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::RkeError(format!("deserialize vehicle status tag error: {}", e)))?
            );
            match tag {
                SUBSCRIBE_REQUEST_TAG |
                QUERY_REQUEST_TAG |
                UNSUBSCRIBE_REQUEST_TAG => Ok(VehicleStatus::Request(VehicleStatusRequest::deserialize(data)?)),
                VEHICLE_STATUS_RESPONSE_TAG => Ok(VehicleStatus::Response(VehicleStatusResponse::deserialize(data)?)),
                _ => Err(ErrorKind::VehicleStatusError("deserialize vehicle status tag error".to_string()).into()),
            }
        }
    }
}

impl Display for VehicleStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VehicleStatus::Request(request) => write!(f, "Request: {}", request),
            VehicleStatus::Response(response) => write!(f, "Response: {}", response),
            VehicleStatus::SubscribeVerificationResponse(response) => write!(f, "Subscribe Verification Response: {}", response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_subscribe_tlv() {
        let operation = VehicleStatusOperations::Subscribe;
        let entity_id = VehicleStatusEntityId::DoorLock;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Subscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::DoorLock);

        let entity_id = VehicleStatusEntityId::CarWindow;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Subscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::CarWindow);

        let entity_id = VehicleStatusEntityId::BackTrunk;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Subscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::BackTrunk);

        let entity_id = VehicleStatusEntityId::Engine;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Subscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::Engine);

        let entity_id = VehicleStatusEntityId::AirConditioner;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Subscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::AirConditioner);

        let entity_id = VehicleStatusEntityId::CarLight;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Subscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::CarLight);
    }
    #[test]
    fn test_create_subscribe_all_tlv() {
        let operation = VehicleStatusOperations::Subscribe;
        let entity_id = VehicleStatusEntityId::All;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Subscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::All);
    }
    #[test]
    fn test_create_query_tlv() {
        let operation = VehicleStatusOperations::Query;
        let entity_id = VehicleStatusEntityId::DoorLock;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Query);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::DoorLock);

        let entity_id = VehicleStatusEntityId::CarWindow;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Query);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::CarWindow);

        let entity_id = VehicleStatusEntityId::BackTrunk;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Query);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::BackTrunk);

        let entity_id = VehicleStatusEntityId::Engine;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Query);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::Engine);

        let entity_id = VehicleStatusEntityId::AirConditioner;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Query);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::AirConditioner);

        let entity_id = VehicleStatusEntityId::CarLight;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Query);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::CarLight);
    }
    #[test]
    fn test_create_query_all_tlv() {
        let operation = VehicleStatusOperations::Query;
        let entity_id = VehicleStatusEntityId::All;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Query);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::All);
    }
    #[test]
    fn test_create_unsubscribe_tlv() {
        let operation = VehicleStatusOperations::Unsubscribe;
        let entity_id = VehicleStatusEntityId::DoorLock;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Unsubscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::DoorLock);

        let entity_id = VehicleStatusEntityId::CarWindow;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Unsubscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::CarWindow);

        let entity_id = VehicleStatusEntityId::BackTrunk;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Unsubscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::BackTrunk);

        let entity_id = VehicleStatusEntityId::Engine;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Unsubscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::Engine);

        let entity_id = VehicleStatusEntityId::AirConditioner;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Unsubscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::AirConditioner);

        let entity_id = VehicleStatusEntityId::CarLight;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Unsubscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::CarLight);
    }
    #[test]
    fn test_create_unsubscribe_all_tlv() {
        let operation = VehicleStatusOperations::Unsubscribe;
        let entity_id = VehicleStatusEntityId::All;
        let tlv = VehicleStatusRequest {
            operation,
            entity_id,
        };
        assert_eq!(tlv.get_operation(), VehicleStatusOperations::Unsubscribe);
        assert_eq!(tlv.get_entity_id(), VehicleStatusEntityId::All);
    }
    #[test]
    fn test_create_response_tlv() {
        let entity_id = VehicleStatusEntityId::DoorLock;
        let status = 0x0000;
        let response = VehicleStatusResponse::new(entity_id, status, None);
        assert_eq!(response.get_entity_id(), VehicleStatusEntityId::DoorLock);
        assert_eq!(response.get_status(), 0x0000);
        assert_eq!(response.get_random(), None);
    }
    #[test]
    fn test_create_response_with_random_tlv() {
        let entity_id = VehicleStatusEntityId::DoorLock;
        let status = 0x0000;
        let random = SubscribeVerificationResponse::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07].as_ref());
        let response = VehicleStatusResponse::new(entity_id, status, Some(random));
        assert_eq!(response.get_entity_id(), VehicleStatusEntityId::DoorLock);
        assert_eq!(response.get_status(), 0x0000);
        assert_eq!(response.get_random(), Some(&SubscribeVerificationResponse::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07].as_ref())));
    }
    #[test]
    fn test_subscribe_tlv_serialize() {
        let operation = VehicleStatusOperations::Subscribe;
        let entity_id = VehicleStatusEntityId::DoorLock;
        let tlv = VehicleStatus::Request(VehicleStatusRequest {
            operation,
            entity_id,
        });
        let serialized_tlv = tlv.serialize().unwrap();
        assert_eq!(serialized_tlv, vec![0x7F, 0x73, 0x06, 0x30, 0x04, 0x84, 0x02, 0x00, 0x01]);
    }
    #[test]
    fn test_subscribe_all_tlv_serialize() {
        let operation = VehicleStatusOperations::Subscribe;
        let entity_id = VehicleStatusEntityId::All;
        let tlv = VehicleStatus::Request(VehicleStatusRequest {
            operation,
            entity_id,
        });
        let serialized_tlv = tlv.serialize().unwrap();
        assert_eq!(serialized_tlv, vec![0x7F, 0x73, 0x02, 0x86, 0x00]);
    }
    #[test]
    fn test_query_tlv_serialize() {
        let operation = VehicleStatusOperations::Query;
        let entity_id = VehicleStatusEntityId::DoorLock;
        let tlv = VehicleStatus::Request(VehicleStatusRequest {
            operation,
            entity_id,
        });
        let serialized_tlv = tlv.serialize().unwrap();
        assert_eq!(serialized_tlv, vec![0x7F, 0x74, 0x06, 0x30, 0x04, 0x84, 0x02, 0x00, 0x01]);
    }
    #[test]
    fn test_query_all_tlv_serialize() {
        let operation = VehicleStatusOperations::Query;
        let entity_id = VehicleStatusEntityId::All;
        let tlv = VehicleStatus::Request(VehicleStatusRequest {
            operation,
            entity_id,
        });
        let serialized_tlv = tlv.serialize().unwrap();
        assert_eq!(serialized_tlv, vec![0x7F, 0x74, 0x02, 0x86, 0x00]);
    }
    #[test]
    fn test_unsubscribe_tlv_serialize() {
        let operation = VehicleStatusOperations::Unsubscribe;
        let entity_id = VehicleStatusEntityId::DoorLock;
        let tlv = VehicleStatus::Request(VehicleStatusRequest {
            operation,
            entity_id,
        });
        let serialized_tlv = tlv.serialize().unwrap();
        assert_eq!(serialized_tlv, vec![0x7F, 0x75, 0x06, 0x30, 0x04, 0x84, 0x02, 0x00, 0x01]);
    }
    #[test]
    fn test_unsubscribe_all_tlv_serialize() {
        let operation = VehicleStatusOperations::Unsubscribe;
        let entity_id = VehicleStatusEntityId::All;
        let tlv = VehicleStatus::Request(VehicleStatusRequest {
            operation,
            entity_id,
        });
        let serialized_tlv = tlv.serialize().unwrap();
        assert_eq!(serialized_tlv, vec![0x7F, 0x75, 0x02, 0x86, 0x00]);
    }
    #[test]
    fn test_verification_response_tlv_serialize() {
        let random = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let verification_response = VehicleStatus::SubscribeVerificationResponse(SubscribeVerificationResponse::new(random.as_ref()));
        let serialized_response = verification_response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x8A, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    #[test]
    fn test_reponse_tlv_serialize() {
        let entity_id = VehicleStatusEntityId::DoorLock;
        let status = 0x0000;
        let response = VehicleStatus::Response(VehicleStatusResponse::new(entity_id, status, None));
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x7F, 0x77, 0x0C, 0x30, 0x0A, 0xA0, 0x08, 0x80, 0x02, 0x00, 0x01, 0x89, 0x02, 0x00, 0x00]);
    }
    #[test]
    fn test_response_with_random_tlv_serialize() {
        let entity_id = VehicleStatusEntityId::DoorLock;
        let status = 0x0000;
        let random = SubscribeVerificationResponse::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07].as_ref());
        let response = VehicleStatus::Response(VehicleStatusResponse::new(entity_id, status, Some(random)));
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x7F, 0x77, 0x0C, 0x30, 0x0A, 0xA0, 0x08, 0x80, 0x02, 0x00, 0x01, 0x89, 0x02, 0x00, 0x00, 0x8A, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    #[test]
    fn test_subscribe_tlv_deserialize() {
        let data = vec![0x7F, 0x73, 0x06, 0x30, 0x04, 0x84, 0x02, 0x00, 0x01];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Request(request) = tlv {
            assert_eq!(request.get_operation(), VehicleStatusOperations::Subscribe);
            assert_eq!(request.get_entity_id(), VehicleStatusEntityId::DoorLock);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_subscribe_all_tlv_deserialize() {
        let data = vec![0x7F, 0x73, 0x02, 0x86, 0x00];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Request(request) = tlv {
            assert_eq!(request.get_operation(), VehicleStatusOperations::Subscribe);
            assert_eq!(request.get_entity_id(), VehicleStatusEntityId::All);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_query_tlv_deserialize() {
        let data = vec![0x7F, 0x74, 0x06, 0x30, 0x04, 0x84, 0x02, 0x00, 0x01];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Request(request) = tlv {
            assert_eq!(request.get_operation(), VehicleStatusOperations::Query);
            assert_eq!(request.get_entity_id(), VehicleStatusEntityId::DoorLock);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_query_all_tlv_deserialize() {
        let data = vec![0x7F, 0x74, 0x02, 0x86, 0x00];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Request(request) = tlv {
            assert_eq!(request.get_operation(), VehicleStatusOperations::Query);
            assert_eq!(request.get_entity_id(), VehicleStatusEntityId::All);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_unsubscribe_tlv_deserialize() {
        let data = vec![0x7F, 0x75, 0x06, 0x30, 0x04, 0x84, 0x02, 0x00, 0x01];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Request(request) = tlv {
            assert_eq!(request.get_operation(), VehicleStatusOperations::Unsubscribe);
            assert_eq!(request.get_entity_id(), VehicleStatusEntityId::DoorLock);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_unsubscribe_all_tlv_deserialize() {
        let data = vec![0x7F, 0x75, 0x02, 0x86, 0x00];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Request(request) = tlv {
            assert_eq!(request.get_operation(), VehicleStatusOperations::Unsubscribe);
            assert_eq!(request.get_entity_id(), VehicleStatusEntityId::All);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_verification_response_tlv_deserialize() {
        let data = vec![0x8A, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::SubscribeVerificationResponse(response) = tlv {
            assert_eq!(response.get_verification_response(), &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_response_tlv_deserialize() {
        let data = vec![0x7F, 0x77, 0x0C, 0x30, 0x0A, 0xA0, 0x08, 0x80, 0x02, 0x00, 0x01, 0x89, 0x02, 0x00, 0x00];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Response(response) = tlv {
            assert_eq!(response.get_entity_id(), VehicleStatusEntityId::DoorLock);
            assert_eq!(response.get_status(), 0x0000);
            assert_eq!(response.get_random(), None);
        } else {
            panic!("Wrong!!!");
        }
    }
    #[test]
    fn test_response_with_random_tlv_deserialize() {
        let data = vec![0x7F, 0x77, 0x0C, 0x30, 0x0A, 0xA0, 0x08, 0x80, 0x02, 0x00, 0x01, 0x89, 0x02, 0x00, 0x00, 0x8A, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let tlv = VehicleStatus::deserialize(data.as_ref());
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        if let VehicleStatus::Response(response) = tlv {
            assert_eq!(response.get_entity_id(), VehicleStatusEntityId::DoorLock);
            assert_eq!(response.get_status(), 0x0000);
            assert_eq!(response.get_random(), Some(&SubscribeVerificationResponse::new(&vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])));
        } else {
            panic!("Wrong!!!");
        }
    }
}
