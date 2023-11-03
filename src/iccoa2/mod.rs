use error_chain::error_chain;
use iso7816_tlv::ber;
use crate::iccoa2::errors::ErrorKind;

pub mod message;
mod apdu;
mod measure;
mod rke;
mod vehicle_status;
mod auth;
mod custom;
mod identifier;
mod instructions;

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

pub fn get_tlv_primitive_value<'a, 'b>(data: &'a ber::Tlv, tag: &'b ber::Tag) -> errors::Result<&'a Vec<u8>> {
    match data.find(&tag) {
        Some(tlv) => {
            match tlv.value() {
                ber::Value::Primitive(value) => {
                    Ok(value)
                },
                _ => {
                    return Err(ErrorKind::MeasureError(format!("deserialize measure duration error")).into());
                }
            }
        },
        None => {
            return Err(ErrorKind::MeasureError(format!("deserialize measure duration error")).into());
        }
    }
}
