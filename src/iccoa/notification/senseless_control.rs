use crate::iccoa::objects::{ICCOA, create_iccoa_header, Mark, create_iccoa_body_message_data, create_iccoa_body, MessageType, create_iccoa};

use super::super::errors::*;

lazy_static! {
    static ref SENSELESS_CONTROL_RESULT_LENGTH_MINIUM: usize = 4;
    static ref SENSELESS_CONTROL_EVENT_LENGTH_MINIUM: usize = 6;
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SenselessControlResult {
    tag: u8,
    value: Vec<u8>,
}

impl SenselessControlResult {
    pub fn new() -> Self {
        SenselessControlResult {
            ..Default::default()
        }
    }
    pub fn builder() -> SenselessControlResultBuilder {
        SenselessControlResultBuilder {
            ..Default::default()
        }
    }
    pub fn length(&self) -> usize {
        1 + 2 + self.value.len()
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.tag);
        let length = self.value.len() as u16;
        buffer.append(&mut length.to_be_bytes().to_vec());
        buffer.append(&mut self.value.to_vec());

        buffer
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < *SENSELESS_CONTROL_RESULT_LENGTH_MINIUM {
            return Err(ErrorKind::ICCOANotificationError("senseless result length error".to_string()).into());
        }
        let mut senseless_result = SenselessControlResult::new();
        senseless_result.tag = buffer[0];
        let length = u16::from_be_bytes(buffer[1..3].try_into().map_err(|_| ErrorKind::ICCOANotificationError("senseless result length error".to_string()))?);
        senseless_result.value = buffer[3..3+length as usize].to_vec();

        Ok(senseless_result)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SenselessControlResultBuilder {
    tag: u8,
    value: Vec<u8>,
}

impl SenselessControlResultBuilder {
    pub fn new() -> Self {
        SenselessControlResultBuilder {
            ..Default::default()
        }
    }
    pub fn success(mut self) -> SenselessControlResultBuilder {
        SenselessControlResultBuilder {
            tag: 0x00,
            value: vec![0x00],
        }
    }
    pub fn executing(mut self) -> SenselessControlResultBuilder {
        SenselessControlResultBuilder {
            tag: 0x02,
            value: vec![0x00],
        }
    }
    pub fn failure(mut self, status: u8) -> SenselessControlResultBuilder {
        SenselessControlResultBuilder {
            tag: 0x03,
            value: vec![status],
        }
    }
    pub fn build(&self) -> SenselessControlResult {
        SenselessControlResult {
            tag: self.tag,
            value: self.value.to_vec(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SenselessControlEvent {
    tag: u8,
    value: SenselessControlResult,
}

impl SenselessControlEvent {
    pub fn new() -> Self {
        SenselessControlEvent {
            ..Default::default()
        }
    }
    pub fn builder() -> SenselessControlEventBuilder {
        SenselessControlEventBuilder {
            ..Default::default()
        }
    }
    pub fn length(&self) -> usize {
        1 + 1 + self.value.length()
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.tag);
        let length = self.value.length() as u8;
        buffer.push(length);
        buffer.append(&mut self.value.serialize());

        buffer
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < *SENSELESS_CONTROL_EVENT_LENGTH_MINIUM {
            return Err(ErrorKind::ICCOANotificationError("senseless control event length error".to_string()).into());
        }
        let mut senseless_control_event = SenselessControlEvent::new();
        senseless_control_event.tag = buffer[0];
        let length = buffer[1];
        let senseless_control_result = SenselessControlResult::deserialize(&buffer[2..2+length as usize])?;
        senseless_control_event.value = senseless_control_result;

        Ok(senseless_control_event)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SenselessControlEventBuilder {
    tag: u8,
    value: SenselessControlResult,
}

impl SenselessControlEventBuilder {
    pub fn new() -> Self {
        SenselessControlEventBuilder {
            ..Default::default()
        }
    }
    pub fn passive_unlock(mut self, result: SenselessControlResult) -> SenselessControlEventBuilder {
        SenselessControlEventBuilder {
            tag: 0x00,
            value: result,
        }
    }
    pub fn passive_lock(mut self, result: SenselessControlResult) -> SenselessControlEventBuilder {
        SenselessControlEventBuilder {
            tag: 0x01,
            value: result,
        }
    }
    pub fn near_auto_unlock(mut self, result: SenselessControlResult) -> SenselessControlEventBuilder {
        SenselessControlEventBuilder {
            tag: 0x10,
            value: result,
        }
    }
    pub fn far_auto_lock(mut self, result: SenselessControlResult) -> SenselessControlEventBuilder {
        SenselessControlEventBuilder {
            tag: 0x11,
            value: result,
        }
    }
    pub fn one_button_start(mut self, result: SenselessControlResult) -> SenselessControlEventBuilder {
        SenselessControlEventBuilder {
            tag: 0x20,
            value: result,
        }
    }
    pub fn welcome(mut self, result: SenselessControlResult) -> SenselessControlEventBuilder {
        SenselessControlEventBuilder {
            tag: 0x30,
            value: result,
        }
    }
    pub fn build(&self) -> SenselessControlEvent {
        SenselessControlEvent {
            tag: self.tag,
            value: self.value.to_owned(),
        }
    }
}

pub fn create_iccoa_senseless_control_event_notification(transaction_id: u16, event: &SenselessControlEvent) -> Result<ICCOA> {
    let header = create_iccoa_header(
        crate::iccoa::objects::PacketType::EVENT_PACKET,
        transaction_id,
        1+3+event.length() as u16,
        Mark {
            encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x02,
        &event.serialize(),
    );
    let body = create_iccoa_body(
        MessageType::NOTIFICATION,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

#[cfg(test)]
mod tests {
    use crate::iccoa::objects::{Header, Body, PacketType, MessageData};

    use super::*;

    #[test]
    fn test_senseless_control_result_success() {
        let result = SenselessControlResultBuilder::new().success().build();
        assert_eq!(result, SenselessControlResult {
            tag: 0x00,
            value: vec![0x00],
        });
    }
    #[test]
    fn test_senseless_control_result_executing() {
        let result = SenselessControlResultBuilder::new().executing().build();
        assert_eq!(result, SenselessControlResult {
            tag: 0x02,
            value: vec![0x00],
        });
    }
    #[test]
    fn test_senseless_control_result_failure() {
        let status = 0x01;
        let result = SenselessControlResultBuilder::new().failure(status).build();
        assert_eq!(result, SenselessControlResult {
            tag: 0x03,
            value: vec![0x01],
        });
    }
    #[test]
    fn test_senseless_control_event_passive_unlock() {
        let transaction_id = 0x0001;
        let result = SenselessControlResultBuilder::new().success().build();
        let event = SenselessControlEventBuilder::new().passive_unlock(result).build();
        let iccoa = create_iccoa_senseless_control_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0001,
                pdu_length: 12+1+3+event.length() as u16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::NOTIFICATION,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x00, 0x04, 0x00, 0x00, 0x01, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_senseless_control_event_pasive_lock() {
        let transaction_id = 0x0002;
        let result = SenselessControlResultBuilder::new().success().build();
        let event = SenselessControlEventBuilder::new().passive_lock(result).build();
        let iccoa = create_iccoa_senseless_control_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0002,
                pdu_length: 12+1+3+event.length() as u16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::NOTIFICATION,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x01, 0x04, 0x00, 0x00, 0x01, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_senseless_control_event_near_auto_unlock() {
        let transaction_id = 0x0003;
        let result = SenselessControlResultBuilder::new().success().build();
        let event = SenselessControlEventBuilder::new().near_auto_unlock(result).build();
        let iccoa = create_iccoa_senseless_control_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0003,
                pdu_length: 12+1+3+event.length() as u16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::NOTIFICATION,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x10, 0x04, 0x00, 0x00, 0x01, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_senseless_control_event_far_auto_lock() {
        let transaction_id = 0x0004;
        let result = SenselessControlResultBuilder::new().success().build();
        let event = SenselessControlEventBuilder::new().far_auto_lock(result).build();
        let iccoa = create_iccoa_senseless_control_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+3+event.length() as u16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::NOTIFICATION,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x11, 0x04, 0x00, 0x00, 0x01, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_senseless_control_event_one_key_start() {
        let transaction_id = 0x0005;
        let result = SenselessControlResultBuilder::new().success().build();
        let event = SenselessControlEventBuilder::new().one_button_start(result).build();
        let iccoa = create_iccoa_senseless_control_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+event.length() as u16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::NOTIFICATION,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x20, 0x04, 0x00, 0x00, 0x01, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_senseless_control_event_welcome() {
        let transaction_id = 0x0006;
        let result = SenselessControlResultBuilder::new().success().build();
        let event = SenselessControlEventBuilder::new().welcome(result).build();
        let iccoa = create_iccoa_senseless_control_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0006,
                pdu_length: 12+1+3+event.length() as u16+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::NOTIFICATION,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        0x30, 0x04, 0x00, 0x00, 0x01, 0x00,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
}