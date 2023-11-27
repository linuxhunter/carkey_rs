use std::fmt::{Display, Formatter};
use crate::iccoa2::Serde;
use crate::iccoa2::errors::*;
use crate::iccoa2::instructions::common;
use crate::iccoa2::instructions::common::ResponseApduTrailer;

const CONTROL_FLOW_INS: u8 = 0x61;
const CONTROL_FLOW_LE: u8 = 0x00;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum ControlFlowP1P2 {
    ExecuteSuccess = 0x0000,
    StandardAuthSuccess = 0x0001,
    FastAuthSuccess = 0x0002,
    VehicleGetCertificateChainSuccess = 0x0003,
    ExecuteFailed = 0x1000,
    StandardAuthFailedWithUnknownVehicle = 0x1001,
    StandardAuthFailedWithInvalidAuthInfo = 0x1002,
    FastAuthFailedWithUnknownVehicle = 0x1003,
    FastAuthFailedWithInvalidAuthInfo = 0x1004,
    Reserved = 0x4000,
}

impl TryFrom<u16> for ControlFlowP1P2 {
    type Error = String;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(ControlFlowP1P2::ExecuteSuccess),
            0x0001 => Ok(ControlFlowP1P2::StandardAuthSuccess),
            0x0002 => Ok(ControlFlowP1P2::FastAuthSuccess),
            0x0003 => Ok(ControlFlowP1P2::VehicleGetCertificateChainSuccess),
            0x1000 => Ok(ControlFlowP1P2::ExecuteFailed),
            0x1001 => Ok(ControlFlowP1P2::StandardAuthFailedWithUnknownVehicle),
            0x1002 => Ok(ControlFlowP1P2::StandardAuthFailedWithInvalidAuthInfo),
            0x1003 => Ok(ControlFlowP1P2::FastAuthFailedWithUnknownVehicle),
            0x1004 => Ok(ControlFlowP1P2::FastAuthFailedWithInvalidAuthInfo),
            _ => {
                if (0x4000..=0x40FF).contains(&value) {
                    Ok(ControlFlowP1P2::Reserved)
                } else {
                    Err("Unsupported Control Flow P1 and P2".to_string())
                }
            }
        }
    }
}

impl From<ControlFlowP1P2> for u16 {
    fn from(value: ControlFlowP1P2) -> Self {
        match value {
            ControlFlowP1P2::ExecuteSuccess => 0x0000,
            ControlFlowP1P2::StandardAuthSuccess => 0x0001,
            ControlFlowP1P2::FastAuthSuccess => 0x0002,
            ControlFlowP1P2::VehicleGetCertificateChainSuccess => 0x0003,
            ControlFlowP1P2::ExecuteFailed => 0x1000,
            ControlFlowP1P2::StandardAuthFailedWithUnknownVehicle => 0x1001,
            ControlFlowP1P2::StandardAuthFailedWithInvalidAuthInfo => 0x1002,
            ControlFlowP1P2::FastAuthFailedWithUnknownVehicle => 0x1003,
            ControlFlowP1P2::FastAuthFailedWithInvalidAuthInfo => 0x1004,
            ControlFlowP1P2::Reserved => 0x4000,
        }
    }
}

impl TryFrom<(u8, u8)> for ControlFlowP1P2 {
    type Error = String;

    fn try_from(value: (u8, u8)) -> std::result::Result<Self, Self::Error> {
        match value {
            (0x00, 0x00) => Ok(ControlFlowP1P2::ExecuteSuccess),
            (0x00, 0x01) => Ok(ControlFlowP1P2::StandardAuthSuccess),
            (0x00, 0x02) => Ok(ControlFlowP1P2::FastAuthSuccess),
            (0x00, 0x03) => Ok(ControlFlowP1P2::VehicleGetCertificateChainSuccess),
            (0x10, 0x00) => Ok(ControlFlowP1P2::ExecuteFailed),
            (0x10, 0x01) => Ok(ControlFlowP1P2::StandardAuthFailedWithUnknownVehicle),
            (0x10, 0x02) => Ok(ControlFlowP1P2::StandardAuthFailedWithInvalidAuthInfo),
            (0x10, 0x03) => Ok(ControlFlowP1P2::FastAuthFailedWithUnknownVehicle),
            (0x10, 0x04) => Ok(ControlFlowP1P2::FastAuthFailedWithInvalidAuthInfo),
            _ => {
                if value.0 == 0x40 {
                    Ok(ControlFlowP1P2::Reserved)
                } else {
                    Err("Unsupported Control Flow P1 and P2".to_string())
                }
            }
        }
    }
}

impl From<ControlFlowP1P2> for (u8, u8) {
    fn from(value: ControlFlowP1P2) -> Self {
        match value {
            ControlFlowP1P2::ExecuteSuccess => (0x00, 0x00),
            ControlFlowP1P2::StandardAuthSuccess => (0x00, 0x01),
            ControlFlowP1P2::FastAuthSuccess => (0x00, 0x02),
            ControlFlowP1P2::VehicleGetCertificateChainSuccess => (0x00, 0x03),
            ControlFlowP1P2::ExecuteFailed => (0x10, 0x00),
            ControlFlowP1P2::StandardAuthFailedWithUnknownVehicle => (0x10, 0x01),
            ControlFlowP1P2::StandardAuthFailedWithInvalidAuthInfo => (0x10, 0x02),
            ControlFlowP1P2::FastAuthFailedWithUnknownVehicle => (0x10, 0x03),
            ControlFlowP1P2::FastAuthFailedWithInvalidAuthInfo => (0x10, 0x04),
            ControlFlowP1P2::Reserved => (0x40, 0x00),
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CommandApduControlFlow {
    cla: u8,
    p1p2: ControlFlowP1P2,
}

#[allow(dead_code)]
impl CommandApduControlFlow {
    pub fn new(cla: u8, p1p2: ControlFlowP1P2) -> Self {
        CommandApduControlFlow {
            cla,
            p1p2,
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_p1p2(&self) -> (u8, u8) {
        self.p1p2.into()
    }
    pub fn set_p1p2(&mut self, p1p2: ControlFlowP1P2) {
        self.p1p2 = p1p2;
    }
}

impl Serde for CommandApduControlFlow {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let header = common::CommandApduHeader::new(
            self.cla,
            CONTROL_FLOW_INS,
            self.get_p1p2().0,
            self.get_p1p2().1,
        );
        let trailer = common::CommandApduTrailer::new(
            None,
            Some(CONTROL_FLOW_LE),
        );
        common::CommandApdu::new(
            header,
            Some(trailer),
        ).serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let request = common::CommandApdu::deserialize(data)?;
        let header = request.get_header();
        let trailer = request.get_trailer();
        if header.get_ins() != CONTROL_FLOW_INS {
            return Err(ErrorKind::ApduInstructionErr("deserialize control flow request error".to_string()).into());
        }
        if let Some(trailer) = trailer {
            if trailer.get_data().is_some() {
                return Err(ErrorKind::ApduInstructionErr("deserialize control flow request error".to_string()).into());
            }
        } else {
            return Err(ErrorKind::ApduInstructionErr("deserialize control flow request error".to_string()).into());
        }
        let cla = header.get_cla();
        let p1p2 = (header.get_p1(), header.get_p2()).try_into()
            .map_err(|e| ErrorKind::ApduInstructionErr(format!("get p1 or p2 error: {}", e)))?;
        Ok(CommandApduControlFlow::new(
            cla,
            p1p2,
        ))
    }
}

impl Display for CommandApduControlFlow {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "cla: {}, p1: {}, p2: {}", self.get_cla(), self.get_p1p2().0, self.get_p1p2().1)
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct ResponseApduControlFlow {
    status: ResponseApduTrailer,
}

#[allow(dead_code)]
impl ResponseApduControlFlow {
    pub fn new(status: ResponseApduTrailer) -> Self {
        ResponseApduControlFlow {
            status,
        }
    }
    pub fn get_status(&self) -> &ResponseApduTrailer {
        &self.status
    }
    pub fn set_status(&mut self, status: ResponseApduTrailer) {
        self.status = status;
    }
}

impl Serde for ResponseApduControlFlow {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let response = common::ResponseApdu::new(
            None,
            *self.get_status(),
        );
        response.serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let response = common::ResponseApdu::deserialize(data)?;
        if response.get_body().is_some() {
            return Err(ErrorKind::ApduInstructionErr("response control flow format error".to_string()).into());
        }
        Ok(ResponseApduControlFlow::new(
            *response.get_trailer()
        ))
    }
}

impl Display for ResponseApduControlFlow {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "status = {}", self.get_status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_control_flow_request() {
        let cla = 0x80;
        let p1p2 = ControlFlowP1P2::ExecuteSuccess;
        let request = CommandApduControlFlow::new(
            cla,
            p1p2,
        );
        assert_eq!(request.get_cla(), 0x80);
        assert_eq!(request.get_p1p2(), ControlFlowP1P2::ExecuteSuccess.into());
    }
    #[test]
    fn test_update_control_flow_request() {
        let cla = 0x80;
        let p1p2 = ControlFlowP1P2::ExecuteSuccess;
        let mut request = CommandApduControlFlow::new(
            cla,
            p1p2,
        );
        let new_cla = 0x90;
        let new_p1p2 = ControlFlowP1P2::ExecuteFailed;
        request.set_cla(new_cla);
        request.set_p1p2(new_p1p2);
        assert_eq!(request.get_cla(), 0x90);
        assert_eq!(request.get_p1p2(), ControlFlowP1P2::ExecuteFailed.into());
    }
    #[test]
    fn test_control_flow_request_serialize() {
        let cla = 0x80;
        let p1p2 = ControlFlowP1P2::ExecuteSuccess;
        let request = CommandApduControlFlow::new(
            cla,
            p1p2,
        );
        let serialized_request = request.serialize();
        assert!(serialized_request.is_ok());
        let serialized_request = serialized_request.unwrap();
        assert_eq!(
            serialized_request,
            vec![
                0x80, 0x61, 0x00, 0x00,
                0x00,
            ],
        )
    }
    #[test]
    fn test_control_flow_request_deserialize() {
        let data = vec![
            0x80, 0x61, 0x00, 0x00,
            0x00,
        ];
        let request = CommandApduControlFlow::deserialize(data.as_ref());
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.get_cla(), 0x80);
        assert_eq!(request.get_p1p2(), ControlFlowP1P2::ExecuteSuccess.into());
    }
    #[test]
    fn test_create_control_flow_response() {
        let status = ResponseApduTrailer::new(
            0x90, 0x00
        );
        let response = ResponseApduControlFlow::new(status);
        assert_eq!(response.get_status(), &ResponseApduTrailer::new(0x90, 0x00));
    }
    #[test]
    fn test_control_flow_response_serialize() {
        let status = ResponseApduTrailer::new(
            0x90, 0x00
        );
        let response = ResponseApduControlFlow::new(status);
        let serialized_response = response.serialize();
        assert!(serialized_response.is_ok());
        let serialized_response = serialized_response.unwrap();
        assert_eq!(
            serialized_response,
            vec![
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_control_flow_response_deserialize() {
        let data = vec![
            0x90, 0x00,
        ];
        let response = ResponseApduControlFlow::deserialize(data.as_ref());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), &ResponseApduTrailer::new(0x90, 0x00));
    }
}
