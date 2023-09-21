use std::os::linux::raw::stat;
use crate::iccoa::{objects::{ICCOA, create_iccoa_header, Mark, create_iccoa_body_message_data, create_iccoa_body, MessageType, create_iccoa}, status::StatusBuilder};

use super::{super::errors::*, CarDoorWindowStatus, CarDoorStatus, CarDoorLockStatus};

lazy_static! {
    static ref VEHICLE_UNSAFE_EVENT_LENGTH_MINIUM: usize = 3;
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct VehicleUnsafeEvent {
    tag: u8,
    value: Vec<u8>,
}

impl VehicleUnsafeEvent {
    pub fn new() -> Self {
        VehicleUnsafeEvent {
            ..Default::default()
        }
    }
    pub fn builder() -> VehicleUnsafeEventBuilder {
        VehicleUnsafeEventBuilder {
            ..Default::default()
        }
    }
    pub fn length(&self) -> usize {
        1 + 1 + self.value.len()
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.tag);
        buffer.push(1);
        buffer.append(&mut self.value.to_vec());

        buffer
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < *VEHICLE_UNSAFE_EVENT_LENGTH_MINIUM {
            return Err(ErrorKind::ICCOANotificationError("vehicle unsafe event length error".to_string()).into());
        }
        let mut vehicle_unsafe_event = VehicleUnsafeEvent::new();
        vehicle_unsafe_event.tag = buffer[0];
        let length = buffer[1];
        vehicle_unsafe_event.value = buffer[2..2+length as usize].to_vec();

        Ok(vehicle_unsafe_event)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct VehicleUnsafeEventBuilder(VehicleUnsafeEvent);

impl VehicleUnsafeEventBuilder {
    pub fn new() -> Self {
        VehicleUnsafeEventBuilder(VehicleUnsafeEvent {
            ..Default::default()
        })
    }
    pub fn power_state(mut self, state: u8) -> Self {
        self.0.tag = 0x03;
        self.0.value = vec![state];
        self
    }
    pub fn door_lock_status(mut self, status: CarDoorLockStatus) -> Self {
        self.0.tag = 0x04;
        self.0.value = vec![status.as_u8()];
        self
    }
    pub fn door_status(mut self, status: CarDoorStatus) -> Self {
        self.0.tag = 0x05;
        self.0.value = vec![status.as_u8()];
        self
    }
    pub fn door_window_status(mut self, status: CarDoorWindowStatus) -> Self {
        self.0.tag = 0x06;
        self.0.value = vec![status.as_u8()];
        self
    }
    pub fn front_hatch_status(mut self, status: u8) -> Self {
        self.0.tag = 0x07;
        self.0.value = vec![status];
        self
    }
    pub fn back_trunk_status(mut self, status: u8) -> Self {
        self.0.tag = 0x08;
        self.0.value = vec![status];
        self
    }
    pub fn sunroof_status(mut self, status: u8) -> Self {
        self.0.tag = 0x09;
        self.0.value = vec![status];
        self
    }
    pub fn headlights_status(mut self, status: u8) -> Self {
        self.0.tag = 0x0A;
        self.0.value = vec![status];
        self
    }
    pub fn build(self) -> VehicleUnsafeEvent {
        self.0
    }
}

pub fn create_iccoa_vehicle_unsafe_event_notification(transaction_id: u16, event: &VehicleUnsafeEvent) -> Result<ICCOA> {
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
        StatusBuilder::new().success().build(),
        0x03,
        &event.serialize()
    );
    let body = create_iccoa_body(
        MessageType::NOTIFICATION,
        message_data
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_vehicle_unsafe_power_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().power_state(0x5A).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

pub fn create_iccoa_vehicle_unsafe_door_lock_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().door_lock_status(
        CarDoorLockStatus::FRONT_LEFT_UNLOCK |
        CarDoorLockStatus::FRONT_RIGHT_UNLOCK |
        CarDoorLockStatus::BACK_LEFT_UNLOCK |
        CarDoorLockStatus::BACK_RIGHT_UNLOCK
    ).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

pub fn create_iccoa_vehicle_unsafe_door_open_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().door_status(
        CarDoorStatus::FRONT_LEFT_OPEN |
        CarDoorStatus::FRONT_RIGHT_OPEN |
        CarDoorStatus::BACK_LEFT_OPEN |
        CarDoorStatus::BACK_RIGHT_OPEN
    ).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

pub fn create_iccoa_vehicle_unsafe_door_window_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().door_window_status(
        CarDoorWindowStatus::FRONT_LEFT_OPEN |
        CarDoorWindowStatus::FRONT_RIGHT_OPEN |
        CarDoorWindowStatus::BACK_LEFT_OPEN |
        CarDoorWindowStatus::BACK_RIGHT_OPEN
    ).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

pub fn create_iccoa_vehicle_unsafe_front_hatch_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().front_hatch_status(0x01).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

pub fn create_iccoa_vehicle_unsafe_back_trunk_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().back_trunk_status(0x01).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

pub fn create_iccoa_vehicle_unsafe_sunroof_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().sunroof_status(0x01).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

pub fn create_iccoa_vehicle_unsafe_headlight_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let event = VehicleUnsafeEventBuilder::new().headlights_status(0x01).build();
    create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event)
}

#[cfg(test)]
mod tests {
    use crate::iccoa::objects::{Header, Body, PacketType, MessageData};

    use super::*;

    #[test]
    fn test_vehicle_unsafe_event_power_state() {
        let transaction_id = 0x0001;
        let event = VehicleUnsafeEventBuilder::new().power_state(0x5A).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0001,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x03, 0x01, 0x5A
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_vehicle_unsafe_event_door_lock_status() {
        let transaction_id = 0x0002;
        let event = VehicleUnsafeEventBuilder::new().door_lock_status(
            CarDoorLockStatus::FRONT_LEFT_UNLOCK |
            CarDoorLockStatus::FRONT_RIGHT_UNLOCK |
            CarDoorLockStatus::BACK_LEFT_UNLOCK |
            CarDoorLockStatus::BACK_RIGHT_UNLOCK
        ).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0002,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x04, 0x01, 0x0F
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_vehicle_unsafe_event_door_open_status() {
        let transaction_id = 0x0003;
        let event = VehicleUnsafeEventBuilder::new().door_status(
            CarDoorStatus::FRONT_LEFT_OPEN |
            CarDoorStatus::FRONT_RIGHT_OPEN |
            CarDoorStatus::BACK_LEFT_OPEN |
            CarDoorStatus::BACK_RIGHT_OPEN
        ).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0003,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x05, 0x01, 0x0F
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_vehicle_unsafe_event_door_window() {
        let transaction_id = 0x0004;
        let event = VehicleUnsafeEventBuilder::new().door_window_status(
            CarDoorWindowStatus::FRONT_LEFT_OPEN |
            CarDoorWindowStatus::FRONT_RIGHT_OPEN |
            CarDoorWindowStatus::BACK_LEFT_OPEN |
            CarDoorWindowStatus::BACK_RIGHT_OPEN
        ).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x06, 0x01, 0x0F
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_vehicle_unsafe_event_front_hatch_status() {
        let transaction_id = 0x0005;
        let event = VehicleUnsafeEventBuilder::new().front_hatch_status(0x01).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x07, 0x01, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_vehicle_unsafe_event_back_trunk_status() {
        let transaction_id = 0x0006;
        let event = VehicleUnsafeEventBuilder::new().back_trunk_status(0x01).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0006,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x08, 0x01, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_vehicle_unsafe_event_sunroof_status() {
        let transaction_id = 0x0007;
        let event = VehicleUnsafeEventBuilder::new().sunroof_status(0x01).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0007,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x09, 0x01, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_vehicle_unsafe_event_headlights_status() {
        let transaction_id = 0x0008;
        let event = VehicleUnsafeEventBuilder::new().headlights_status(0x01).build();
        let event_length = event.length() as u16;
        let iccoa = create_iccoa_vehicle_unsafe_event_notification(transaction_id, &event).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0008,
                pdu_length: 12+1+3+event_length+8,
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
                    tag: 0x03,
                    value: vec![
                        0x0A, 0x01, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
}
