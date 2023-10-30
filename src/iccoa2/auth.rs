use iso7816_tlv::ber;
use super::errors::*;

#[derive(Debug)]
pub struct Auth {
    inner: ber::Tlv,
}

impl Auth {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        todo!()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        todo!()
    }
}