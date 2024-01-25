use std::fmt::{Display, Formatter};
use futures::{SinkExt, StreamExt};
use http::Uri;
use log::{debug, info};
use tokio_websockets::{ClientBuilder, Message};
use crate::icce::card_info::{CardId, CardSeId, set_card_id, set_card_se_id};
use crate::icce::dkey_info::{get_dkey, remove_dkey, save_dkey};
use crate::icce::{Serde, session};
use crate::icce::errors::*;

const NOTIFICATION_LENGTH: usize = 0x02;
const TSP_SERVER_ADDRESS: &str = "169.254.101.250";
const TSP_SERVER_PORT: u16 = 12345;

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum Operations {
    #[default]
    Delete = 0x01,
    Disable = 0x02,
    Enable = 0x03,
    IssueCertificate = 0x04,
}

impl TryFrom<u8> for Operations {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Operations::Delete),
            0x02 => Ok(Operations::Disable),
            0x03 => Ok(Operations::Enable),
            0x04 => Ok(Operations::IssueCertificate),
            _ => Err("Invalid Operations Type".to_string()),
        }
    }
}

impl From<Operations> for u8 {
    fn from(value: Operations) -> Self {
        match value {
            Operations::Delete => 0x01,
            Operations::Disable => 0x02,
            Operations::Enable => 0x03,
            Operations::IssueCertificate => 0x04,
        }
    }
}

impl TryFrom<&str> for Operations {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("delete") {
            Ok(Operations::Delete)
        } else if value.eq_ignore_ascii_case("disable") {
            Ok(Operations::Disable)
        } else if value.eq_ignore_ascii_case("enable") {
            Ok(Operations::Enable)
        } else if value.eq_ignore_ascii_case("issue") {
            Ok(Operations::IssueCertificate)
        } else {
            Err("Invalid Operations Type".to_string())
        }
    }
}

impl Display for Operations {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Operations::Delete => write!(f, "Delete"),
            Operations::Disable => write!(f, "Disable"),
            Operations::Enable => write!(f, "Enable"),
            Operations::IssueCertificate => write!(f, "Issue CarKey"),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum Objects {
    #[default]
    Owner = 0x01,
    Friend = 0x02,
    Middle = 0x03,
}

impl TryFrom<u8> for Objects {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Objects::Owner),
            0x02 => Ok(Objects::Friend),
            0x03 => Ok(Objects::Middle),
            _ => Err("Invalid Objects Type".to_string()),
        }
    }
}

impl From<Objects> for u8 {
    fn from(value: Objects) -> Self {
        match value {
            Objects::Owner => 0x01,
            Objects::Friend => 0x02,
            Objects::Middle => 0x03,
        }
    }
}

impl TryFrom<&str> for Objects {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("owner") {
            Ok(Objects::Owner)
        } else if value.eq_ignore_ascii_case("friend") {
            Ok(Objects::Friend)
        } else if value.eq_ignore_ascii_case("middle") {
            Ok(Objects::Middle)
        } else {
            Err("Invalid Objects Type".to_string())
        }
    }
}

impl From<Objects> for &'static str {
    fn from(value: Objects) -> Self {
        match value {
            Objects::Owner => "owner",
            Objects::Friend => "friend",
            Objects::Middle => "middle",
        }
    }
}

impl Display for Objects {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Objects::Owner => write!(f, "Owner"),
            Objects::Friend => write!(f, "Friend"),
            Objects::Middle => write!(f, "Middle"),
        }
    }
}

#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub struct Notification {
    operation: Operations,
    object: Objects,
    data: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl Notification {
    pub fn new(operation: Operations, object: Objects, data: Option<Vec<u8>>) -> Self {
        Notification {
            operation,
            object,
            data,
        }
    }
    pub fn get_operation(&self) -> Operations {
        self.operation
    }
    pub fn set_operation(&mut self, operation: Operations) {
        self.operation = operation;
    }
    pub fn get_object(&self) -> Objects {
        self.object
    }
    pub fn set_object(&mut self, object: Objects) {
        self.object = object;
    }
    pub fn get_data(&self) -> Option<&[u8]> {
        if let Some(ref data) = self.data {
            Some(data)
        } else {
            None
        }
    }
    pub fn set_data(&mut self, data: Option<Vec<u8>>) {
        self.data = data;
    }
    pub fn operate(&self) -> Result<()> {
        match self.operation {
            Operations::IssueCertificate => {
               if let Some(dkey_info) = self.get_data() {
                   let card_seid = &dkey_info[0..8];
                   let card_id = &dkey_info[8..24];
                   let dkey = &dkey_info[24..];
                   debug!("Issue DKey!!!!!!");
                   debug!("card_seid = {:02x?}", card_seid);
                   debug!("card_id = {:02x?}", card_id);
                   debug!("dkey = {:02x?}", dkey);
                   set_card_se_id(&CardSeId::new(card_seid));
                   set_card_id(&CardId::new(card_id));
                   save_dkey(card_seid, card_id, dkey);
               }
            },
            Operations::Delete => {
                if let Some(dkey_info) = self.get_data() {
                    let card_seid = &dkey_info[0..8];
                    let card_id = &dkey_info[8..24];
                    debug!("Delete DKey!!!!!!");
                    debug!("card_seid = {:02x?}", card_seid);
                    debug!("card_id = {:02x?}", card_id);
                    remove_dkey(card_seid, card_id);
                    session::remove_session_key();
                    debug!("[current dkey] = {:?}", get_dkey(card_seid, card_id));
                }
            },
            _ => {
                todo!()
            }
        }
        Ok(())
    }
}

impl Display for Notification {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_operation(), self.get_object())
    }
}

impl Serde for Notification {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![u8::from(self.operation), u8::from(self.object)];
        if let Some(data) = self.get_data() {
            buffer.append(&mut data.to_vec());
        }
        Ok(buffer)
    }

    fn deserialize(buffer: &[u8]) -> Result<Self::Output> {
        if buffer.len() < NOTIFICATION_LENGTH {
            return Err(ErrorKind::DKeyError(format!("origin data length less than {}", NOTIFICATION_LENGTH)).into());
        }
        let operation = Operations::try_from(buffer[0])?;
        let object = Objects::try_from(buffer[1])?;
        let data = if buffer.len() > NOTIFICATION_LENGTH {
            let data_length = u16::from_be_bytes((&buffer[NOTIFICATION_LENGTH..NOTIFICATION_LENGTH+2]).try_into().unwrap());
            Some(buffer[NOTIFICATION_LENGTH+2..NOTIFICATION_LENGTH + 2 + data_length as usize].to_vec())
        } else {
            None
        };
        Ok(Notification::new(
            operation,
            object,
            data,
        ))
    }
}

pub async fn tsp_handler() {
    let uri = Uri::try_from(format!("ws://{}:{}/ws", TSP_SERVER_ADDRESS, TSP_SERVER_PORT).as_str()).unwrap();
    let (mut client, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    while let Some(Ok(msg)) = client.next().await {
        if msg.is_binary() {
            let notification_cmd = Notification::deserialize(msg.as_payload().to_vec().as_ref()).unwrap();
            info!("Notification is {}", notification_cmd);
            match notification_cmd.operate() {
                Ok(_) => {
                    client.send(Message::text(String::from("OK"))).await.unwrap();
                }
                Err(_) => {
                    client.send(Message::text(String::from("Failed"))).await.unwrap();
                }
            }
        }
    }
}
