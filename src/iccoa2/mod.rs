use error_chain::error_chain;
use iso7816_tlv::ber;
use crate::iccoa2::errors::ErrorKind;

pub mod message;
pub mod apdu;
pub mod measure;
pub mod rke;
pub mod vehicle_status;
pub mod auth;
pub mod custom;
pub mod identifier;
pub mod instructions;

mod errors {
    use super::*;

    error_chain! {
        errors {
            BleMessageError(t: String)
            ApduInstructionErr(t: String)
            ApduError(t: String)
            MeasureError(t: String)
            RkeError(t: String)
            VehicleStatusError(t: String)
            CustomError(t: String)
            AuthError(t: String)
            IdentifierError(t: String)
        }
    }
}

pub trait Serde {
    type Output;
    fn serialize(&self) -> errors::Result<Vec<u8>>;
    fn deserialize(data: &[u8]) -> errors::Result<Self::Output>;
}

pub fn get_tlv_primitive_value<'a>(data: &'a ber::Tlv, tag: & ber::Tag) -> errors::Result<&'a Vec<u8>> {
    match data.find(tag) {
        Some(tlv) => {
            match tlv.value() {
                ber::Value::Primitive(value) => {
                    Ok(value)
                },
                _ => {
                    Err(ErrorKind::MeasureError("deserialize measure duration error".to_string()).into())
                }
            }
        },
        None => {
            Err(ErrorKind::MeasureError("deserialize measure duration error".to_string()).into())
        }
    }
}

pub fn create_tlv_with_primitive_value(tag: u8, value: &[u8]) -> errors::Result<ber::Tlv> {
    let ber_tag = ber::Tag::try_from(tag)
        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create tag with {tag} error: {}", e)))?;
    let ber_value = ber::Value::Primitive(value.to_vec());
    let ber_tlv = ber::Tlv::new(ber_tag, ber_value)
        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create tlv with tag {}, value: {:02X?} error: {}", tag, value, e)))?;
    Ok(ber_tlv)
}

pub fn create_tlv_with_constructed_value(tag: u16, value: &[ber::Tlv]) -> errors::Result<ber::Tlv> {
    let ber_tag = ber::Tag::try_from(tag)
        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create tag with {tag} error: {}", e)))?;
    let ber_value = ber::Value::Constructed(value.to_vec());
    let ber_tlv = ber::Tlv::new(ber_tag, ber_value)
        .map_err(|e| ErrorKind::ApduInstructionErr(format!("create tlv with tag {}, value: {:02X?} error: {}", tag, value, e)))?;
    Ok(ber_tlv)
}
