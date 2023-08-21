#![recursion_limit = "1024"]

use error_chain::error_chain;

mod status;
mod objects;
mod pairing;
mod auth;
mod command;
mod notification;
mod bluetooth_io;

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
    pub fn length(&self) -> usize {
        1+1+self.value.len()
    }
    pub fn get_tag(&self) -> u8 {
        self.tag
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.tag);
        buffer.push(self.value.len() as u8);
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
        let length = buffer[index] as usize;
        index += 1;
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
