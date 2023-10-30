use iso7816_tlv::ber;
use super::errors::*;

#[derive(Debug)]
pub struct Subscribe {
    inner: ber::Tlv,
}

impl Subscribe {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        todo!()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        todo!()
    }
}