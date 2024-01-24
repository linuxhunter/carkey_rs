use std::fmt::{Display, Formatter};

pub mod objects;
pub mod auth;
pub mod command;
pub mod notification;
pub mod bluetooth_io;
pub mod ble_send_demo;
pub mod vehicle_info;
pub mod card_info;
pub mod session;
pub mod dkey_info;
pub mod tsp;

mod errors {
    use error_chain::error_chain;

    error_chain! {
        errors {
            VehicleInfoError(t: String)
            CardInfoError(t: String)
            ObjectError(t: String)
            AuthError(t: String)
            EncryptDecryptError(t: String)
            CommandError(t: String)
            NotificationError(t: String)
            BluetoothIOError(t: String)
            SessionError(t: String)
            DKeyError(t: String)
        }
    }
}

pub trait Serde {
    type Output;
    fn serialize(&self) -> errors::Result<Vec<u8>>;
    fn deserialize(data: &[u8]) -> errors::Result<Self::Output>;
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum MessageType {
    #[default]
    Auth = 0x01,
    Command = 0x02,
    Notification = 0x03,
    Rfu = 0x04,
}

impl TryFrom<u8> for MessageType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageType::Auth),
            0x02 => Ok(MessageType::Command),
            0x03 => Ok(MessageType::Notification),
            _ => Ok(MessageType::Rfu),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Auth => 0x01,
            MessageType::Command => 0x02,
            MessageType::Notification => 0x03,
            MessageType::Rfu => 0x04,
        }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Auth => write!(f, "Auth"),
            MessageType::Command => write!(f, "Command"),
            MessageType::Notification => write!(f, "Notification"),
            MessageType::Rfu => write!(f, "RFU"),
        }
    }
}
