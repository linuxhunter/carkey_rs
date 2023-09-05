#![recursion_limit = "1024"]

use error_chain::error_chain;

pub mod status;
pub mod objects;
pub mod pairing;
pub mod auth;
pub mod command;
pub mod notification;
pub mod bluetooth_io;
pub mod utils;

mod errors {
    use super::*;

    error_chain! {
        foreign_links {
            Io(std::io::Error);
        }
        errors {
            ICCOAObjectError(t: String)
            ICCOAPairingError(t: String)
            ICCOAAuthError(t: String)
            ICCOACommandError(t: String)
            ICCOANotificationError(t: String)
            ICCOAEncryptError(t: String)
        }
    }
}

lazy_static! {
    static ref TLV_PAYLOAD_LENGTH_MINIMUM: usize = 2;
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct TLVPayload {
    tag: u8,
    value: Vec<u8>,
}

impl TLVPayload {
    pub fn new() -> Self {
        TLVPayload {
            ..Default::default()
        }
    }
    pub fn builder() -> TLVPayloadBuilder {
        TLVPayloadBuilder {
            ..Default::default()
        }
    }
    pub fn get_total_length(&self) -> usize {
        let mut length_bytes = 0x00;
        if self.value.len() < 0x80 {
            length_bytes = 1;
        } else if self.value.len() < 0x100 {
            length_bytes = 2;
        } else {
            length_bytes = 3;
        }
        1+length_bytes+self.value.len()
    }
    pub fn get_tag(&self) -> u8 {
        self.tag
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.tag);
        if self.value.len() < 0x80 {
            buffer.push(self.value.len() as u8);
        } else if self.value.len() < 0x100 {
            buffer.push(0x81);
            buffer.push(self.value.len() as u8);
        } else {
            buffer.push(0x82);
            let length = self.value.len() as u16;
            buffer.append(&mut length.to_be_bytes().to_vec());
        }
        buffer.append(&mut self.value.to_vec());

        buffer
    }
    pub fn deserialize(buffer: &[u8]) -> errors::Result<Self> {
        if buffer.len() < *TLV_PAYLOAD_LENGTH_MINIMUM {
            return Err(errors::ErrorKind::ICCOAPairingError("pairing payload length error".to_string()).into());
        }
        let mut payload = TLVPayload::new();
        let mut index = 0x00;
        payload.tag = buffer[index];
        index += 1;
        let mut length = 0x00;
        if buffer[index] < 128 {
            length = buffer[index] as usize;
            index += 1;
        } else if buffer[index] == 0x81 {
            length = buffer[index+1] as usize;
            index += 2;
        } else {
            length = (u16::from_be_bytes([buffer[index+1], buffer[index+2]])) as usize;
            index += 3;
        }
        payload.value = buffer[index..index+length].to_vec();

        Ok(payload)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct TLVPayloadBuilder {
    tag: u8,
    value: Vec<u8>,
}

impl TLVPayloadBuilder {
    pub fn new() -> Self {
        TLVPayloadBuilder {
            ..Default::default()
        }
    }
    pub fn set_tag(mut self, tag: u8) -> TLVPayloadBuilder {
        self.tag = tag;
        self
    }
    pub fn set_value(mut self, value: &[u8]) -> TLVPayloadBuilder {
        self.value = value.to_vec();
        self
    }
    pub fn build(&self) -> TLVPayload {
        TLVPayload {
            tag: self.tag,
            value: self.value.to_vec(),
        }
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_ber_tlv() {
        let payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&[0x01; 16]).build();
        println!("serialized payload = {:02X?}", payload.serialize());
        let deserialized_payload = TLVPayload::deserialize(&payload.serialize()).unwrap();
        println!("deserialized_payload = {:?}", deserialized_payload);

        let payload2 = TLVPayloadBuilder::new().set_tag(0x56).set_value(&[0x02; 250]).build();
        println!("serialized payload2 = {:02X?}", payload2.serialize());
        let deserialized_payload2 = TLVPayload::deserialize(&payload2.serialize()).unwrap();
        println!("deserialized_payload2 = {:?}", deserialized_payload2);

        let payload3 = TLVPayloadBuilder::new().set_tag(0x57).set_value(&[0x03; 1024]).build();
        println!("serialized payload3 = {:02X?}", payload3.serialize());
        let deserialized_payload3 = TLVPayload::deserialize(&payload3.serialize()).unwrap();
        println!("deserialized_payload3 = {:?}", deserialized_payload3);
    }
}