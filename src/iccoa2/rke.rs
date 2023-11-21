use std::fmt::{Display, Formatter};
use iso7816_tlv::ber;
use crate::iccoa2::{create_tlv_with_constructed_value, create_tlv_with_primitive_value, get_tlv_primitive_value, Serde};
use super::errors::*;

#[allow(dead_code)]
const RKE_FUNCTION_TAG: u8 = 0x80;
#[allow(dead_code)]
const RKE_ACTION_TAG: u8 = 0x81;
#[allow(dead_code)]
const RKE_CONTINUED_CUSTOM_TAG: u8 = 0x88;
#[allow(dead_code)]
const RKE_RESPONSE_ACTION_TAG: u8 = 0x83;
#[allow(dead_code)]
const RKE_RESPONSE_STATUS_TAG: u8 = 0x89;
#[allow(dead_code)]
const RKE_RESPONSE_MIDDLE_TAG: u8 = 0xA0;
#[allow(dead_code)]
const RKE_VERIFICATION_RESPONSE_TAG: u8 = 0x8A;
#[allow(dead_code)]
pub const RKE_REQUEST_TAG: u16 = 0x7F70;
#[allow(dead_code)]
const RKE_CONTINUED_REQUEST_TAG: u16 = 0x7F76;
#[allow(dead_code)]
const RKE_RESPONSE_TAG: u16 = 0x7F72;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum RkeFunctions {
    DoorLock = 0x0001,
    CarWindow = 0x0002,
    BackTrunk = 0x0003,
    Engine = 0x0004,
    FindVehicle = 0x0005,
    Custom = 0x1001,
}

impl TryFrom<u16> for RkeFunctions {
    type Error = String;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(RkeFunctions::DoorLock),
            0x0002 => Ok(RkeFunctions::CarWindow),
            0x0003 => Ok(RkeFunctions::BackTrunk),
            0x0004 => Ok(RkeFunctions::Engine),
            0x0005 => Ok(RkeFunctions::FindVehicle),
            _ => {
                if value >= 0x1001 {
                    Ok(RkeFunctions::Custom)
                } else {
                    Err(format!("Invalid Rke Function from u16: {}", value))
                }
            }
        }
    }
}

impl From<RkeFunctions> for u16 {
    fn from(value: RkeFunctions) -> Self {
        match value {
            RkeFunctions::DoorLock => 0x0001,
            RkeFunctions::CarWindow => 0x0002,
            RkeFunctions::BackTrunk => 0x0003,
            RkeFunctions::Engine => 0x0004,
            RkeFunctions::FindVehicle => 0x0005,
            RkeFunctions::Custom => 0x1001,
        }
    }
}

impl Display for RkeFunctions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RkeFunctions::DoorLock => write!(f, "DoorLock"),
            RkeFunctions::CarWindow => write!(f, "CarWindow"),
            RkeFunctions::BackTrunk => write!(f, "BackTrunk"),
            RkeFunctions::Engine => write!(f, "Engine"),
            RkeFunctions::FindVehicle => write!(f, "FindVehicle"),
            RkeFunctions::Custom => write!(f, "Custom"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum DoorLockAction {
    Unlock = 0x01,
    Lock = 0x02,
}

impl TryFrom<u8> for DoorLockAction {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(DoorLockAction::Unlock),
            0x02 => Ok(DoorLockAction::Lock),
            _ => Err(format!("Invalid Door Lock Action value from u8: {}", value))
        }
    }
}

impl From<DoorLockAction> for u8 {
    fn from(value: DoorLockAction) -> Self {
        match value {
            DoorLockAction::Unlock => 0x01,
            DoorLockAction::Lock => 0x02,
        }
    }
}

impl Display for DoorLockAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DoorLockAction::Unlock => write!(f, "Unlock"),
            DoorLockAction::Lock => write!(f, "Lock"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum CarWindowAction {
    FullOpen = 0x01,
    FullClose = 0x02,
    PartialOpen = 0x03,
}

impl TryFrom<u8> for CarWindowAction {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(CarWindowAction::FullOpen),
            0x02 => Ok(CarWindowAction::FullClose),
            0x03 => Ok(CarWindowAction::PartialOpen),
            _ => Err(format!("Invalid Car Window Action from u8: {}", value))
        }
    }
}

impl From<CarWindowAction> for u8 {
    fn from(value: CarWindowAction) -> Self {
        match value {
            CarWindowAction::FullOpen => 0x01,
            CarWindowAction::FullClose => 0x02,
            CarWindowAction::PartialOpen => 0x03,
        }
    }
}

impl Display for CarWindowAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CarWindowAction::FullOpen => write!(f, "FullOpen"),
            CarWindowAction::FullClose => write!(f, "FullClose"),
            CarWindowAction::PartialOpen => write!(f, "PartialOpen"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum BackTrunkAction {
    Open = 0x01,
    Close = 0x02,
}

impl TryFrom<u8> for BackTrunkAction {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(BackTrunkAction::Open),
            0x02 => Ok(BackTrunkAction::Close),
            _ => Err(format!("Invalid Back Trunk Action from u8: {}", value))
        }
    }
}

impl From<BackTrunkAction> for u8 {
    fn from(value: BackTrunkAction) -> Self {
        match value {
            BackTrunkAction::Open => 0x01,
            BackTrunkAction::Close => 0x02,
        }
    }
}

impl Display for BackTrunkAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BackTrunkAction::Open => write!(f, "Open"),
            BackTrunkAction::Close => write!(f, "Close"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum EngineAction {
    Open = 0x01,
    Close = 0x02,
}

impl TryFrom<u8> for EngineAction {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(EngineAction::Open),
            0x02 => Ok(EngineAction::Close),
            _ => Err(format!("Invalid Engine Action from u8: {}", value))
        }
    }
}

impl From<EngineAction> for u8 {
    fn from(value: EngineAction) -> Self {
        match value {
            EngineAction::Open => 0x01,
            EngineAction::Close => 0x02,
        }
    }
}

impl Display for EngineAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineAction::Open => write!(f, "Open"),
            EngineAction::Close => write!(f, "Close"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum FindVehicleAction {
    Flashing = 0x01,
    Whistling = 0x02,
    FlashingAndWhistling = 0x03,
}

impl TryFrom<u8> for FindVehicleAction {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FindVehicleAction::Flashing),
            0x02 => Ok(FindVehicleAction::Whistling),
            0x03 => Ok(FindVehicleAction::FlashingAndWhistling),
            _ => Err(format!("Invalid Find Vehicle Action from u8: {}", value)),
        }
    }
}

impl From<FindVehicleAction> for u8 {
    fn from(value: FindVehicleAction) -> Self {
        match value {
            FindVehicleAction::Flashing => 0x01,
            FindVehicleAction::Whistling => 0x02,
            FindVehicleAction::FlashingAndWhistling => 0x03,
        }
    }
}

impl Display for FindVehicleAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FindVehicleAction::Flashing => write!(f, "Flashing"),
            FindVehicleAction::Whistling => write!(f, "Whistling"),
            FindVehicleAction::FlashingAndWhistling => write!(f, "Flashing and Whistling"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum RkeActions {
    DoorLockAction(DoorLockAction),
    CarWindowAction(CarWindowAction),
    BackTrunkAction(BackTrunkAction),
    EngineAction(EngineAction),
    FindVehicleAction(FindVehicleAction),
    Custom(u8),
}

impl RkeActions {
    pub fn try_from_u8(value: u8, rke_functions: RkeFunctions) -> Result<Self> {
        match rke_functions {
            RkeFunctions::DoorLock => Ok(RkeActions::DoorLockAction(DoorLockAction::try_from(value)?)),
            RkeFunctions::CarWindow => Ok(RkeActions::CarWindowAction(CarWindowAction::try_from(value)?)),
            RkeFunctions::BackTrunk => Ok(RkeActions::BackTrunkAction(BackTrunkAction::try_from(value)?)),
            RkeFunctions::Engine => Ok(RkeActions::EngineAction(EngineAction::try_from(value)?)),
            RkeFunctions::FindVehicle => Ok(RkeActions::FindVehicleAction(FindVehicleAction::try_from(value)?)),
            _ => Err(ErrorKind::RkeError("Unsupported rke action from rke function".to_string()).into())
        }
    }
}

impl From<RkeActions> for u8 {
    fn from(value: RkeActions) -> Self {
        match value {
            RkeActions::DoorLockAction(action) => action.into(),
            RkeActions::CarWindowAction(action) => action.into(),
            RkeActions::BackTrunkAction(action) => action.into(),
            RkeActions::EngineAction(action) => action.into(),
            RkeActions::FindVehicleAction(action) => action.into(),
            RkeActions::Custom(action) => action,
        }
    }
}

impl Display for RkeActions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RkeActions::DoorLockAction(action) => write!(f, "{action}"),
            RkeActions::CarWindowAction(action) => write!(f, "{action}"),
            RkeActions::BackTrunkAction(action) => write!(f, "{action}"),
            RkeActions::EngineAction(action) => write!(f, "{action}"),
            RkeActions::FindVehicleAction(action) => write!(f, "{action}"),
            RkeActions::Custom(action) => write!(f, "custom {action}"),
        }
    }
}

fn is_rke_function_action_match(rke_functions: RkeFunctions, rke_actions: RkeActions) -> bool {
    match rke_functions {
        RkeFunctions::DoorLock => {
            if rke_actions == RkeActions::DoorLockAction(DoorLockAction::Lock) ||
                rke_actions == RkeActions::DoorLockAction(DoorLockAction::Unlock) {
                return true;
            }
        }
        RkeFunctions::CarWindow => {
            if rke_actions == RkeActions::CarWindowAction(CarWindowAction::FullOpen) ||
                rke_actions == RkeActions::CarWindowAction(CarWindowAction::FullClose) ||
                rke_actions == RkeActions::CarWindowAction(CarWindowAction::PartialOpen) {
                return true;
            }
        },
        RkeFunctions::BackTrunk => {
            if rke_actions == RkeActions::BackTrunkAction(BackTrunkAction::Open) ||
                rke_actions == RkeActions::BackTrunkAction(BackTrunkAction::Close) {
                return true;
            }
        },
        RkeFunctions::Engine => {
            if rke_actions == RkeActions::EngineAction(EngineAction::Open) ||
                rke_actions == RkeActions::EngineAction(EngineAction::Close) {
                return true;
            }
        },
        RkeFunctions::FindVehicle => {
            if rke_actions == RkeActions::FindVehicleAction(FindVehicleAction::Flashing) ||
                rke_actions == RkeActions::FindVehicleAction(FindVehicleAction::Whistling) ||
                rke_actions == RkeActions::FindVehicleAction(FindVehicleAction::FlashingAndWhistling) {
                return true;
            }
        },
        RkeFunctions::Custom => {
            if rke_actions >= RkeActions::Custom(u8::MIN) &&
                rke_actions <= RkeActions::Custom(u8::MAX) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct RkeRequest {
    rke_function: RkeFunctions,
    rke_action: RkeActions,
}

#[allow(dead_code)]
impl RkeRequest {
    pub fn new(rke_function: RkeFunctions, rke_action: RkeActions) -> Result<Self> {
        if is_rke_function_action_match(rke_function, rke_action) {
            Ok(RkeRequest {
                rke_function,
                rke_action,
            })
        } else {
            Err(ErrorKind::RkeError(format!("rke function {} and action {} do not match", rke_function, rke_action)).into())
        }
    }
    pub fn get_rke_function(&self) -> RkeFunctions {
        self.rke_function
    }
    pub fn set_rke_function(&mut self, rke_functions: RkeFunctions) {
        self.rke_function = rke_functions;
    }
    pub fn get_rke_action(&self) -> RkeActions {
        self.rke_action
    }
    pub fn set_rke_action(&mut self, rke_actions: RkeActions) {
        self.rke_action = rke_actions;
    }
}

impl Serde for RkeRequest {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let function_tlv = create_tlv_with_primitive_value(RKE_FUNCTION_TAG, &u16::from(self.get_rke_function()).to_be_bytes())
            .map_err(|e| ErrorKind::RkeError(format!("create rke function tlv error: {}", e)))?;
        let action_tlv = create_tlv_with_primitive_value(RKE_ACTION_TAG, &[self.get_rke_action().into()])
            .map_err(|e| ErrorKind::RkeError(format!("create rke action tlv error: {}", e)))?;
        let rke_request_tlv = create_tlv_with_constructed_value(RKE_REQUEST_TAG, &[function_tlv, action_tlv])
            .map_err(|e| ErrorKind::RkeError(format!("create rke request tlv error: {}", e)))?;
        Ok(rke_request_tlv.to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let rke_request_tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke request from bytes error: {}", e)))?;
        if rke_request_tlv.tag().to_bytes() != RKE_REQUEST_TAG.to_be_bytes() {
            return Err(ErrorKind::RkeError("deserialized rke request tag is not corrected".to_string()).into());
        }
        if !rke_request_tlv.value().is_constructed() {
            return Err(ErrorKind::RkeError("deserialized rke request value is not constructed".to_string()).into());
        }

        let function_tag = ber::Tag::try_from(RKE_FUNCTION_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke function tag error: {}", e)))?;
        let request_function = get_tlv_primitive_value(&rke_request_tlv, &function_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke request function primitive value error: {}", e)))?;
        let rke_function = RkeFunctions::try_from(
            u16::from_be_bytes(
                (&request_function[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::RkeError(format!("deserialize rke request function primitive value error: {}", e)))?
            )
        ).map_err(|e| ErrorKind::RkeError(format!("deserialize rke request function primitive value error: {}", e)))?;

        let action_tag = ber::Tag::try_from(RKE_ACTION_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke action tag error: {}", e)))?;
        let request_action = get_tlv_primitive_value(&rke_request_tlv, &action_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke request action primitive value error: {}", e)))?;

        let rke_action = RkeActions::try_from_u8(request_action[0], rke_function)?;

        Ok(RkeRequest {
            rke_function,
            rke_action,
        })
    }
}

impl Display for RkeRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rke request function: {}, action: {}", self.rke_function, self.rke_action)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct RkeContinuedRequest {
    rke_request: RkeRequest,
    rke_custom: Vec<u8>,
}

#[allow(dead_code)]
impl RkeContinuedRequest {
    pub fn new(rke_request: RkeRequest, rke_custom: &[u8]) -> Self {
        RkeContinuedRequest {
            rke_request,
            rke_custom: rke_custom.to_vec(),
        }
    }
    pub fn get_rke_request(&self) -> RkeRequest {
        self.rke_request
    }
    pub fn set_rke_request(&mut self, rke_request: RkeRequest) {
        self.rke_request = rke_request;
    }
    pub fn get_rke_custom(&self) -> &[u8] {
        &self.rke_custom
    }
    pub fn set_rke_custom(&mut self, rke_custom: &[u8]) {
        self.rke_custom = rke_custom.to_vec();
    }
}

impl Serde for RkeContinuedRequest {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let function_tlv = create_tlv_with_primitive_value(RKE_FUNCTION_TAG, &u16::from(self.get_rke_request().get_rke_function()).to_be_bytes())
            .map_err(|e| ErrorKind::RkeError(format!("create rke continued function tlv error: {}", e)))?;
        let action_tlv = create_tlv_with_primitive_value(RKE_ACTION_TAG, &[self.get_rke_request().get_rke_action().into()])
            .map_err(|e| ErrorKind::RkeError(format!("create rke continued action tlv error: {}", e)))?;
        let custom_tlv = create_tlv_with_primitive_value(RKE_CONTINUED_CUSTOM_TAG, self.get_rke_custom())
            .map_err(|e| ErrorKind::RkeError(format!("create rke continued custom tlv error: {}", e)))?;
        let rke_request_tlv = create_tlv_with_constructed_value(RKE_CONTINUED_REQUEST_TAG, &[function_tlv, action_tlv, custom_tlv])
            .map_err(|e| ErrorKind::RkeError(format!("create rke continued request tlv error: {}", e)))?;
        Ok(rke_request_tlv.to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let rke_request_tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke continued request from bytes error: {}", e)))?;
        if rke_request_tlv.tag().to_bytes() != RKE_CONTINUED_REQUEST_TAG.to_be_bytes() {
            return Err(ErrorKind::RkeError("deserialized rke continued request tag is not corrected".to_string()).into());
        }
        if !rke_request_tlv.value().is_constructed() {
            return Err(ErrorKind::RkeError("deserialized rke continued request value is not constructed".to_string()).into());
        }

        let function_tag = ber::Tag::try_from(RKE_FUNCTION_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke function tag error: {}", e)))?;
        let request_function = get_tlv_primitive_value(&rke_request_tlv, &function_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke request function primitive value error: {}", e)))?;
        let rke_function = RkeFunctions::try_from(
            u16::from_be_bytes(
                (&request_function[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::RkeError(format!("deserialize rke request function primitive value error: {}", e)))?
            )
        ).map_err(|e| ErrorKind::RkeError(format!("deserialize rke request function primitive value error: {}", e)))?;

        let action_tag = ber::Tag::try_from(RKE_ACTION_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke action tag error: {}", e)))?;
        let request_action = get_tlv_primitive_value(&rke_request_tlv, &action_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke request action primitive value error: {}", e)))?;
        let rke_action = RkeActions::try_from_u8(request_action[0], rke_function)?;

        let custom_tag = ber::Tag::try_from(RKE_CONTINUED_CUSTOM_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke continued custom tag error: {}", e)))?;
        let request_custom = get_tlv_primitive_value(&rke_request_tlv, &custom_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke continued request custom primitive value error: {}", e)))?;
        let rke_custom = request_custom.to_vec();

        Ok(RkeContinuedRequest {
            rke_request: RkeRequest {
                rke_function,
                rke_action,
            },
            rke_custom,
        })
    }
}

impl Display for RkeContinuedRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rke Continue Request: {}, Custom: {:02X?}", self.rke_request, self.rke_custom)
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct RkeResponse {
    rke_function: RkeFunctions,
    rke_action: RkeActions,
    rke_status: u16,
}

#[allow(dead_code)]
impl RkeResponse {
    pub fn new(rke_function: RkeFunctions, rke_action: RkeActions, rke_status: u16) -> Result<Self> {
        if is_rke_function_action_match(rke_function, rke_action) {
            Ok(RkeResponse {
                rke_function,
                rke_action,
                rke_status,
            })
        } else {
            Err(ErrorKind::RkeError(format!("rke function {} and action {} do not match", rke_function, rke_action)).into())
        }
    }
    pub fn get_rke_function(&self) -> RkeFunctions {
        self.rke_function
    }
    pub fn set_rke_function(&mut self, rke_functions: RkeFunctions) {
        self.rke_function = rke_functions;
    }
    pub fn get_rke_action(&self) -> RkeActions {
        self.rke_action
    }
    pub fn set_rke_action(&mut self, rke_actions: RkeActions) {
        self.rke_action = rke_actions;
    }
    pub fn get_rke_status(&self) -> u16 {
        self.rke_status
    }
    pub fn set_rke_status(&mut self, rke_status: u16) {
        self.rke_status = rke_status;
    }
}

impl Serde for RkeResponse {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let function_tlv = create_tlv_with_primitive_value(RKE_FUNCTION_TAG, &u16::from(self.get_rke_function()).to_be_bytes())
            .map_err(|e| ErrorKind::RkeError(format!("create rke function tlv error: {}", e)))?;
        let action_tlv = create_tlv_with_primitive_value(RKE_RESPONSE_ACTION_TAG, &u16::from(u8::from(self.get_rke_action())).to_be_bytes())
            .map_err(|e| ErrorKind::RkeError(format!("create rke action tlv error: {}", e)))?;
        let status_tlv = create_tlv_with_primitive_value(RKE_RESPONSE_STATUS_TAG, &self.get_rke_status().to_be_bytes())
            .map_err(|e| ErrorKind::RkeError(format!("create rke response status tlv error: {}", e)))?;
        let response_middle_tlv = create_tlv_with_constructed_value(u16::from(RKE_RESPONSE_MIDDLE_TAG), &[function_tlv, action_tlv, status_tlv])
            .map_err(|e| ErrorKind::RkeError(format!("create rke response middle tlv error: {}", e)))?;
        let rke_response_tlv= create_tlv_with_constructed_value(RKE_RESPONSE_TAG, &[response_middle_tlv])
            .map_err(|e| ErrorKind::RkeError(format!("create rke response tlv error: {}", e)))?;
        Ok(rke_response_tlv.to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let rke_response_tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke response from bytes error: {}", e)))?;
        if rke_response_tlv.tag().to_bytes() != RKE_RESPONSE_TAG.to_be_bytes() {
            return Err(ErrorKind::RkeError("deserialized rke response tag is not corrected".to_string()).into());
        }
        if !rke_response_tlv.value().is_constructed() {
            return Err(ErrorKind::RkeError("deserialized rke response value is not constructed".to_string()).into());
        }

        let function_tag = ber::Tag::try_from(RKE_FUNCTION_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke function tag error: {}", e)))?;
        let response_function = get_tlv_primitive_value(&rke_response_tlv, &function_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke response function primitive value error: {}", e)))?;
        let rke_function = RkeFunctions::try_from(
            u16::from_be_bytes(
                (&response_function[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::RkeError(format!("deserialize rke response function primitive value error: {}", e)))?
            )
        ).map_err(|e| ErrorKind::RkeError(format!("deserialize rke response function primitive value error: {}", e)))?;

        let action_tag = ber::Tag::try_from(RKE_RESPONSE_ACTION_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke response action tag error: {}", e)))?;
        let response_action = get_tlv_primitive_value(&rke_response_tlv, &action_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke response action primitive value error: {}", e)))?;

        let rke_action = RkeActions::try_from_u8(
            u8::try_from(
                u16::from_be_bytes(
                    (&response_action[0..2])
                        .try_into()
                        .map_err(|e| ErrorKind::RkeError(format!("deserialize rke response action value error: {}", e)))?
                )
            ).map_err(|e| ErrorKind::RkeError(format!("deserialize rke response rke action primitive value error: {}", e)))?,
            rke_function)?;

        let status_tag = ber::Tag::try_from(RKE_RESPONSE_STATUS_TAG)
            .map_err(|e| ErrorKind::RkeError(format!("create rke response status tag error: {}", e)))?;
        let response_status = get_tlv_primitive_value(&rke_response_tlv, &status_tag)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke response status primitive value error: {}", e)))?;
        let rke_status = u16::from_be_bytes(
            (&response_status[0..2])
                .try_into()
                .map_err(|e| ErrorKind::RkeError(format!("deserialize rke response status value error: {}",e )))?);

        Ok(RkeResponse {
            rke_function,
            rke_action,
            rke_status,
        })
    }
}

impl Display for RkeResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rke response function: {}, action: {}, status: {}", self.rke_function, self.rke_action, self.rke_status)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct RkeVerificationResponse {
    inner: Vec<u8>,
}

#[allow(dead_code)]
impl RkeVerificationResponse {
    pub fn new(random: &[u8]) -> Self {
        RkeVerificationResponse {
            inner: random.to_vec(),
        }
    }
    pub fn get_rke_verification_response(&self) -> &[u8] {
        self.inner.as_ref()
    }
    pub fn set_rke_verification_response(&mut self, random: &[u8]) {
        self.inner = random.to_vec();
    }
}

impl Serde for RkeVerificationResponse {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let tlv = create_tlv_with_primitive_value(RKE_VERIFICATION_RESPONSE_TAG, self.get_rke_verification_response())
            .map_err(|e| ErrorKind::RkeError(format!("create rke verification response tlv error: {}", e)))?;
        Ok(tlv.to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let tlv = ber::Tlv::from_bytes(data)
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke verification response from bytes error: {}", e)))?;
        if tlv.tag().to_bytes() != RKE_VERIFICATION_RESPONSE_TAG.to_be_bytes() {
            return Err(ErrorKind::RkeError("deserialized rke request tag is not corrected".to_string()).into());
        }
        let value = get_tlv_primitive_value(&tlv, tlv.tag())
            .map_err(|e| ErrorKind::RkeError(format!("deserialize rke verification response value error: {}", e)))?;
        Ok(RkeVerificationResponse::new(value))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum Rke {
    Request(RkeRequest),
    ContinuedRequest(RkeContinuedRequest),
    VerificationResponse(RkeVerificationResponse),
    Response(RkeResponse),
}

impl Serde for Rke {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        match self {
            Rke::Request(request) => request.serialize(),
            Rke::ContinuedRequest(request) => request.serialize(),
            Rke::Response(response) => response.serialize(),
            Rke::VerificationResponse(response) => response.serialize(),
        }
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        if data[0] == RKE_VERIFICATION_RESPONSE_TAG {
            Ok(Rke::VerificationResponse(RkeVerificationResponse::deserialize(data)?))
        } else {
            let tag = u16::from_be_bytes(
                (&data[0..2])
                    .try_into()
                    .map_err(|e| ErrorKind::RkeError(format!("deserialize rke tag error: {}", e)))?
            );
            match tag {
                RKE_REQUEST_TAG => Ok(Rke::Request(RkeRequest::deserialize(data)?)),
                RKE_CONTINUED_REQUEST_TAG => Ok(Rke::ContinuedRequest(RkeContinuedRequest::deserialize(data)?)),
                RKE_RESPONSE_TAG => Ok(Rke::Response(RkeResponse::deserialize(data)?)),
                _ => {
                    Err(ErrorKind::RkeError("deserialize rke tag is invalid".to_string()).into())
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rke_request_tlv() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_function(), RkeFunctions::DoorLock);
        assert_eq!(request.get_rke_action(), RkeActions::DoorLockAction(DoorLockAction::Lock));
        let action = RkeActions::DoorLockAction(DoorLockAction::Unlock);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_action(), RkeActions::DoorLockAction(DoorLockAction::Unlock));

        let function = RkeFunctions::CarWindow;
        let action = RkeActions::CarWindowAction(CarWindowAction::FullOpen);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_function(), RkeFunctions::CarWindow);
        assert_eq!(request.get_rke_action(), RkeActions::CarWindowAction(CarWindowAction::FullOpen));
        let action = RkeActions::CarWindowAction(CarWindowAction::FullClose);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_action(), RkeActions::CarWindowAction(CarWindowAction::FullClose));
        let action = RkeActions::CarWindowAction(CarWindowAction::PartialOpen);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_action(), RkeActions::CarWindowAction(CarWindowAction::PartialOpen));

        let function = RkeFunctions::BackTrunk;
        let action = RkeActions::BackTrunkAction(BackTrunkAction::Open);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_function(), RkeFunctions::BackTrunk);
        assert_eq!(request.get_rke_action(), RkeActions::BackTrunkAction(BackTrunkAction::Open));
        let action = RkeActions::BackTrunkAction(BackTrunkAction::Close);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_action(), RkeActions::BackTrunkAction(BackTrunkAction::Close));

        let function = RkeFunctions::Engine;
        let action = RkeActions::EngineAction(EngineAction::Open);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_function(), RkeFunctions::Engine);
        assert_eq!(request.get_rke_action(), RkeActions::EngineAction(EngineAction::Open));
        let action = RkeActions::EngineAction(EngineAction::Close);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_action(), RkeActions::EngineAction(EngineAction::Close));

        let function = RkeFunctions::FindVehicle;
        let action = RkeActions::FindVehicleAction(FindVehicleAction::Flashing);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_function(), RkeFunctions::FindVehicle);
        assert_eq!(request.get_rke_action(), RkeActions::FindVehicleAction(FindVehicleAction::Flashing));
        let action = RkeActions::FindVehicleAction(FindVehicleAction::Whistling);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_action(), RkeActions::FindVehicleAction(FindVehicleAction::Whistling));
        let action = RkeActions::FindVehicleAction(FindVehicleAction::FlashingAndWhistling);
        let request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_action(), RkeActions::FindVehicleAction(FindVehicleAction::FlashingAndWhistling));

        let function = RkeFunctions::FindVehicle;
        let action = RkeActions::EngineAction(EngineAction::Open);
        let request = RkeRequest::new(function, action);
        assert!(request.is_err());
    }
    #[test]
    fn test_update_rke_request_tlv() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let mut request = RkeRequest::new(function, action).unwrap();
        assert_eq!(request.get_rke_function(), RkeFunctions::DoorLock);
        assert_eq!(request.get_rke_action(), RkeActions::DoorLockAction(DoorLockAction::Lock));
        request.set_rke_function(RkeFunctions::Engine);
        request.set_rke_action(RkeActions::EngineAction(EngineAction::Open));
        assert_eq!(request.get_rke_function(), RkeFunctions::Engine);
        assert_eq!(request.get_rke_action(), RkeActions::EngineAction(EngineAction::Open));
    }
    #[test]
    fn test_create_rke_continued_request_tlv() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let request = RkeRequest::new(function, action).unwrap();
        let custom = vec![0x00, 0x01, 0x02, 0x03];
        let continued_request = RkeContinuedRequest::new(request, custom.as_ref());
        assert_eq!(continued_request.get_rke_request().get_rke_function(), RkeFunctions::DoorLock);
        assert_eq!(continued_request.get_rke_request().get_rke_action(), RkeActions::DoorLockAction(DoorLockAction::Lock));
        assert_eq!(*continued_request.get_rke_custom(), vec![0x00, 0x01, 0x02, 0x03]);
    }
    #[test]
    fn test_update_rke_continued_request_tlv() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let request = RkeRequest::new(function, action).unwrap();
        let custom = vec![0x00, 0x01, 0x02, 0x03];
        let mut continued_request = RkeContinuedRequest::new(request, custom.as_ref());
        assert_eq!(continued_request.get_rke_request().get_rke_function(), RkeFunctions::DoorLock);
        assert_eq!(continued_request.get_rke_request().get_rke_action(), RkeActions::DoorLockAction(DoorLockAction::Lock));
        assert_eq!(*continued_request.get_rke_custom(), vec![0x00, 0x01, 0x02, 0x03]);

        let function = RkeFunctions::FindVehicle;
        let action = RkeActions::FindVehicleAction(FindVehicleAction::Whistling);
        let request = RkeRequest::new(function, action).unwrap();
        continued_request.set_rke_request(request);
        continued_request.set_rke_custom(vec![0x03, 0x02, 0x01, 0x00].as_ref());
        assert_eq!(continued_request.get_rke_request().get_rke_function(), RkeFunctions::FindVehicle);
        assert_eq!(continued_request.get_rke_request().get_rke_action(), RkeActions::FindVehicleAction(FindVehicleAction::Whistling));
        assert_eq!(*continued_request.get_rke_custom(), vec![0x03, 0x02, 0x01, 0x00]);
    }
    #[test]
    fn test_create_rke_response_tlv() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let status = 0x0000;
        let response = RkeResponse::new(function, action, status);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_rke_function(), RkeFunctions::DoorLock);
        assert_eq!(response.get_rke_action(), RkeActions::DoorLockAction(DoorLockAction::Lock));
        assert_eq!(response.get_rke_status(), 0x0000);

        let function = RkeFunctions::FindVehicle;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let status = 0x0000;
        let response = RkeResponse::new(function, action, status);
        assert!(response.is_err());
    }
    #[test]
    fn test_update_rke_response_tlv() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let status = 0x0000;
        let response = RkeResponse::new(function, action, status);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_rke_function(), RkeFunctions::DoorLock);
        assert_eq!(response.get_rke_action(), RkeActions::DoorLockAction(DoorLockAction::Lock));
        assert_eq!(response.get_rke_status(), 0x0000);

        let function = RkeFunctions::FindVehicle;
        let action = RkeActions::FindVehicleAction(FindVehicleAction::Whistling);
        let status = 0xFFFF;
        let response = RkeResponse::new(function, action, status);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_rke_function(), RkeFunctions::FindVehicle);
        assert_eq!(response.get_rke_action(), RkeActions::FindVehicleAction(FindVehicleAction::Whistling));
        assert_eq!(response.get_rke_status(), 0xFFFF);
    }
    #[test]
    fn test_rke_request_tlv_serialize() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let request = RkeRequest::new(function, action).unwrap();
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(serialized_request, vec![0x7F, 0x70, 0x07, 0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02]);
    }
    #[test]
    fn test_rke_continued_request_tlv_serialize() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let request = RkeRequest::new(function, action).unwrap();
        let custom = vec![0x00, 0x01, 0x02, 0x03];
        let continued_request = RkeContinuedRequest::new(request, custom.as_ref());
        let serialized_continued_request = continued_request.serialize();
        assert!(serialized_continued_request.is_ok());
        let serialized_continued_request = serialized_continued_request.unwrap();
        assert_eq!(serialized_continued_request, vec![0x7F, 0x76, 0x0D, 0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02, 0x88, 0x04, 0x00, 0x01, 0x02, 0x03]);
    }
    #[test]
    fn test_rke_response_tlv_serialize() {
        let function = RkeFunctions::DoorLock;
        let action = RkeActions::DoorLockAction(DoorLockAction::Lock);
        let status = 0x0000;
        let response = RkeResponse::new(function, action, status).unwrap();
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x7F, 0x72, 0x0E, 0xA0, 0x0C, 0x80, 0x02, 0x00, 0x01, 0x83, 0x02, 0x00, 0x02, 0x89, 0x02, 0x00, 0x00]);
    }
    #[test]
    fn test_rke_verification_response_tlv_serialize() {
        let random = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let response = Rke::VerificationResponse(RkeVerificationResponse::new(random.as_ref()));
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(serialized_response, vec![0x8A, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    #[test]
    fn test_rke_request_tlv_deserialize() {
        let data = vec![0x7F, 0x70, 0x07, 0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02];
        let request = Rke::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        match request {
            Rke::Request(request) => {
                assert_eq!(request, RkeRequest {
                    rke_function: RkeFunctions::DoorLock,
                    rke_action: RkeActions::DoorLockAction(DoorLockAction::Lock),
                });
            },
            _ => panic!("Wrong!!!"),
        }
    }
    #[test]
    fn test_rke_continued_request_tlv_deserialize() {
        let data = vec![0x7F, 0x76, 0x0D, 0x80, 0x02, 0x00, 0x01, 0x81, 0x01, 0x02, 0x88, 0x04, 0x00, 0x01, 0x02, 0x03];
        let request = Rke::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        match request {
            Rke::ContinuedRequest(request) => {
                assert_eq!(request, RkeContinuedRequest {
                    rke_request: RkeRequest {
                        rke_function: RkeFunctions::DoorLock,
                        rke_action: RkeActions::DoorLockAction(DoorLockAction::Lock),
                    },
                    rke_custom: vec![0x00, 0x01, 0x02, 0x03],
                });
            },
            _ => panic!("Wrong!!!"),
        }
    }
    #[test]
    fn test_rke_response_tlv_deserialize() {
        let data = vec![0x7F, 0x72, 0x0E, 0xA0, 0x0C, 0x80, 0x02, 0x00, 0x01, 0x83, 0x02, 0x00, 0x02, 0x89, 0x02, 0x00, 0x00];
        let response = Rke::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        match response {
            Rke::Response(response) => {
                assert_eq!(response, RkeResponse {
                    rke_function: RkeFunctions::DoorLock,
                    rke_action: RkeActions::DoorLockAction(DoorLockAction::Lock),
                    rke_status: 0x0000,
                });
            },
            _ => panic!("Wrong"),
        }
    }
    #[test]
    fn test_rke_verification_response_tlv_deserialize() {
        let data = vec![0x8A, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let response = Rke::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response, Rke::VerificationResponse(RkeVerificationResponse {
            inner: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        }));
    }
}