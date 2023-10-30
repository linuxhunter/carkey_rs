use iso7816_tlv::ber;
use super::errors::*;

#[derive(Debug)]
struct ApduUnit {
    length: u8,
    value: ber::Tlv,
}

#[derive(Debug)]
pub struct Apdu {
    inner: Vec<ApduUnit>,
}

impl Apdu {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        todo!()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        todo!()
    }
}