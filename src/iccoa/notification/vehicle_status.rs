use crate::iccoa::{objects::{create_iccoa_header, Mark, create_iccoa_body_message_data, create_iccoa_body, create_iccoa, ICCOA, MessageType}, status::StatusBuilder};

use super::{super::errors::*, CarDoorLockStatus, CarDoorStatus, CarDoorWindowStatus};

lazy_static! {
    static ref VEHICLE_STATUS_LENGTH_MINIUM: usize = 3;
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct VehicleStatus {
    tag: u8,
    value: Vec<u8>,
}

impl VehicleStatus {
        pub fn new() -> Self {
            VehicleStatus {
                ..Default::default()
            }
        }
        pub fn builder() -> VehicleStatusBuilder {
            VehicleStatusBuilder {
                ..Default::default()
            }
        }
        pub fn length(&self) -> usize {
            1 + 1 + self.value.len()
        }
        pub fn serialize(&self) -> Vec<u8> {
            let mut buffer = Vec::new();
            buffer.push(self.tag);
            buffer.push(self.value.len() as u8);
            buffer.append(&mut self.value.to_vec());
            buffer
        }
        pub fn deserialize(buffer: &[u8]) -> Result<Self> {
            if buffer.len() < *VEHICLE_STATUS_LENGTH_MINIUM {
                return Err(ErrorKind::ICCOANotificationError("vehicle status length error".to_string()).into());
            }
            let mut vehicle_status = VehicleStatus::new();
            vehicle_status.tag = buffer[0];
            let length = buffer[1];
            vehicle_status.value = buffer[2..2+length as usize].to_vec();
            Ok(vehicle_status)
        }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct VehicleStatusBuilder {
    tag: u8,
    value: Vec<u8>,
}

impl VehicleStatusBuilder {
    pub fn new() -> Self {
        VehicleStatusBuilder {
            ..Default::default()
        }
    }
    pub fn total_mileage(mut self, total_mileage: u32) -> VehicleStatusBuilder {
        self.tag = 0x00;
        self.value = total_mileage.to_be_bytes().to_vec();
        self
    }
    pub fn rechange_mileage(mut self, rechange_mileage: u16) -> VehicleStatusBuilder {
        self.tag = 0x01;
        self.value = rechange_mileage.to_be_bytes().to_vec();
        self
    }
    pub fn remaining_battery(mut self, status: u8) -> VehicleStatusBuilder {
        self.tag = 0x02;
        self.value = vec![status];
        self
    }
    pub fn power_state(mut self, state: u8) -> VehicleStatusBuilder {
        self.tag = 0x03;
        self.value = vec![state];
        self
    }
    pub fn door_lock_status(mut self, status: CarDoorLockStatus) -> VehicleStatusBuilder {
        self.tag = 0x04;
        self.value = vec![status.as_u8()];
        self
    }
    pub fn door_open_status(mut self, status: CarDoorStatus) -> VehicleStatusBuilder {
        self.tag = 0x05;
        self.value = vec![status.as_u8()];
        self
    }
    pub fn door_window_status(mut self, status: CarDoorWindowStatus) -> VehicleStatusBuilder {
        self.tag = 0x06;
        self.value = vec![status.as_u8()];
        self
    }
    pub fn front_hatch_status(mut self, status: u8) -> VehicleStatusBuilder {
        self.tag = 0x07;
        self.value = vec![status];
        self
    }
    pub fn back_trunk_status(mut self, status: u8) -> VehicleStatusBuilder {
        self.tag = 0x08;
        self.value = vec![status];
        self
    }
    pub fn sunroof_status(mut self, status: u8) -> VehicleStatusBuilder {
        self.tag = 0x09;
        self.value = vec![status];
        self
    }
    pub fn headlights_status(mut self, status: u8) -> VehicleStatusBuilder {
        self.tag = 0x0A;
        self.value = vec![status];
        self
    }
    pub fn build(&self) -> VehicleStatus {
        VehicleStatus {
            tag: self.tag,
            value: self.value.to_vec(),
        }
    }
}

pub fn create_iccoa_vehicle_status_notification(transaction_id: u16, vehicle_status: &[VehicleStatus]) -> Result<ICCOA> {
    let mut total_length = 0x00;
    let mut vehicle_status_serialized_data = Vec::new();
    vehicle_status.iter().for_each(|status| {
        total_length += status.length();
        vehicle_status_serialized_data.append(&mut status.serialize());
    });
    let header = create_iccoa_header(
        crate::iccoa::objects::PacketType::EVENT_PACKET,
        transaction_id,
        1+3+total_length as u16,
        Mark {
            encrypt_type: crate::iccoa::objects::EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        },
    );
    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        0x01,
        &vehicle_status_serialized_data,
    );
    let body = create_iccoa_body(
        MessageType::NOTIFICATION,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_total_mileage_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().total_mileage(0x01).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_rechange_mileage_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().rechange_mileage(0x5A).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_remaining_battery_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().remaining_battery(90).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_power_state_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().power_state(0x01).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_door_lock_status_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().door_lock_status(
        CarDoorLockStatus::FRONT_LEFT_UNLOCK |
        CarDoorLockStatus::FRONT_RIGHT_UNLOCK |
        CarDoorLockStatus::BACK_LEFT_UNLOCK |
        CarDoorLockStatus::BACK_RIGHT_UNLOCK,
    ).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_door_open_status_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().door_open_status(
        CarDoorStatus::FRONT_LEFT_OPEN |
        CarDoorStatus::FRONT_RIGHT_OPEN |
        CarDoorStatus::BACK_LEFT_OPEN |
        CarDoorStatus::BACK_RIGHT_OPEN,
    ).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_door_window_status_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().door_window_status(
        CarDoorWindowStatus::FRONT_LEFT_OPEN |
        CarDoorWindowStatus::FRONT_RIGHT_OPEN |
        CarDoorWindowStatus::BACK_LEFT_OPEN |
        CarDoorWindowStatus::BACK_RIGHT_OPEN,
    ).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_front_hatch_status_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().front_hatch_status(0x01).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_back_trunk_status_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().back_trunk_status(0x01).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_sunroof_status_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().sunroof_status(0x01).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

pub fn create_iccoa_headlight_status_notification() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let vehicle_status = VehicleStatusBuilder::new().headlights_status(0x01).build();
    create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status])
}

#[cfg(test)]
mod tests {
    use crate::iccoa::objects::{Header, Body, MessageData};

    use super::*;

    #[test]
    fn test_vehicle_status_total_mileage() {
        let transaction_id = 0x0001;
        let vehicle_status = VehicleStatusBuilder::new().total_mileage(0x01).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0001,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_vehicle_status_rechange_mileage() {
        let transaction_id = 0x0002;
        let vehicle_status = VehicleStatusBuilder::new().rechange_mileage(0x5A).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0002,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x01, 0x02, 0x00, 0x5A,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_remaining_battery() {
        let transaction_id = 0x0003;
        let vehicle_status = VehicleStatusBuilder::new().remaining_battery(90).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0003,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x02, 0x01, 0x5A,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_power_state() {
        let transaction_id = 0x0004;
        let vehicle_status = VehicleStatusBuilder::new().power_state(0x01).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x03, 0x01, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_door_lock() {
        let transaction_id = 0x0005;
        let vehicle_status = VehicleStatusBuilder::new().door_lock_status(
            CarDoorLockStatus::FRONT_LEFT_UNLOCK |
            CarDoorLockStatus::FRONT_RIGHT_UNLOCK |
            CarDoorLockStatus::BACK_LEFT_UNLOCK |
            CarDoorLockStatus::BACK_RIGHT_UNLOCK,
        ).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x04, 0x01, 0x0F,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_door_status() {
        let transaction_id = 0x0006;
        let vehicle_status = VehicleStatusBuilder::new().door_open_status(
            CarDoorStatus::FRONT_LEFT_OPEN |
            CarDoorStatus::FRONT_RIGHT_OPEN |
            CarDoorStatus::BACK_LEFT_OPEN |
            CarDoorStatus::BACK_RIGHT_OPEN,
        ).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0006,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x05, 0x01, 0x0F,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_door_window() {
        let transaction_id = 0x0007;
        let vehicle_status = VehicleStatusBuilder::new().door_window_status(
            CarDoorWindowStatus::FRONT_LEFT_OPEN |
            CarDoorWindowStatus::FRONT_RIGHT_OPEN |
            CarDoorWindowStatus::BACK_LEFT_OPEN |
            CarDoorWindowStatus::BACK_RIGHT_OPEN,
        ).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0007,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x06, 0x01, 0x0F,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_front_hatch() {
        let transaction_id = 0x0008;
        let vehicle_status = VehicleStatusBuilder::new().front_hatch_status(0x01).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0008,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x07, 0x01, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_back_trunk() {
        let transaction_id = 0x0009;
        let vehicle_status = VehicleStatusBuilder::new().back_trunk_status(0x01).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x0009,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x08, 0x01, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_sunroof() {
        let transaction_id = 0x000A;
        let vehicle_status = VehicleStatusBuilder::new().sunroof_status(0x01).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x000A,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x09, 0x01, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_headlights() {
        let transaction_id = 0x000B;
        let vehicle_status = VehicleStatusBuilder::new().headlights_status(0x01).build();
        let vehicle_status_length = vehicle_status.length() as u16;
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, &[vehicle_status]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x000B,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x0A, 0x01, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_vehicle_status_all() {
        let transaction_id = 0x000C;
        let total_mileage = VehicleStatusBuilder::new().total_mileage(0x01).build();
        let rechange_mileage = VehicleStatusBuilder::new().rechange_mileage(0x5A).build();
        let remaining_battery = VehicleStatusBuilder::new().remaining_battery(0x5A).build();
        let power_state = VehicleStatusBuilder::new().power_state(0x01).build();
        let door_lock_status = VehicleStatusBuilder::new().door_lock_status(
            CarDoorLockStatus::FRONT_LEFT_UNLOCK |
            CarDoorLockStatus::FRONT_RIGHT_UNLOCK,
        ).build();
        let door_open_status = VehicleStatusBuilder::new().door_open_status(
            CarDoorStatus::FRONT_LEFT_OPEN |
            CarDoorStatus::FRONT_RIGHT_OPEN,
        ).build();
        let door_window_status = VehicleStatusBuilder::new().door_window_status(
            CarDoorWindowStatus::FRONT_LEFT_OPEN |
            CarDoorWindowStatus::FRONT_RIGHT_OPEN,
        ).build();
        let front_hatch_status = VehicleStatusBuilder::new().front_hatch_status(0x01).build();
        let back_trunk_status = VehicleStatusBuilder::new().back_trunk_status(0x01).build();
        let sunroof_status = VehicleStatusBuilder::new().sunroof_status(0x01).build();
        let headlights_status = VehicleStatusBuilder::new().headlights_status(0x01).build();
        let vehicle_status = &[
            total_mileage,
            rechange_mileage,
            remaining_battery,
            power_state,
            door_lock_status,
            door_open_status,
            door_window_status,
            front_hatch_status,
            back_trunk_status,
            sunroof_status,
            headlights_status,
        ];
        let mut vehicle_status_length = 0x00;
        vehicle_status.iter().for_each(|status| {
            vehicle_status_length += status.length() as u16;
        });
        let iccoa = create_iccoa_vehicle_status_notification(transaction_id, vehicle_status).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::EVENT_PACKET,
                dest_transaction_id: 0x000C,
                pdu_length: 12+1+3+vehicle_status_length+8,
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
                    tag: 0x01,
                    value: vec![
                        0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
                        0x01, 0x02, 0x00, 0x5A,
                        0x02, 0x01, 0x5A,
                        0x03, 0x01, 0x01,
                        0x04, 0x01, 0x03,
                        0x05, 0x01, 0x03,
                        0x06, 0x01, 0x03,
                        0x07, 0x01, 0x01,
                        0x08, 0x01, 0x01,
                        0x09, 0x01, 0x01,
                        0x0A, 0x01, 0x01,
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
}