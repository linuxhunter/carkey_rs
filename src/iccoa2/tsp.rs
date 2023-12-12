use std::fmt::{Display, Formatter};
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::iccoa2::{certificate, Serde};
use crate::iccoa2::errors::*;
use crate::iccoa2::key_management;

const NOTIFICATION_LENGTH: usize = 0x02;
const TSP_SERVER_ADDRESS: &str = "169.254.101.250";
const TSP_SERVER_PORT: u16 = 12345;
const TSP_DATA_BUFFER_LENGTH: usize = 0x800;

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
    fn change_object_to_key_type(&self) -> Result<key_management::KeyType> {
        if self.get_object() == Objects::Owner {
            Ok(key_management::KeyType::Owner)
        } else if self.get_object() == Objects::Friend {
            Ok(key_management::KeyType::Friend)
        } else {
            Err(ErrorKind::TspError(format!("Operation {} does not support {}", self.get_operation(), self.get_object())).into())
        }
    }
    pub fn operate(&self) -> Result<()> {
        match self.operation {
            Operations::Delete => {
                let key_type = self.change_object_to_key_type()?;
                let key_id = key_management::km_find_key(key_type).ok_or(format!("key type {} is not valid", self.object))?;
                key_management::km_remove_key(&key_id);
            }
            Operations::Disable => {
                let key_type = self.change_object_to_key_type()?;
                let key_id = key_management::km_find_key(key_type).ok_or(format!("key type {} is not valid", self.object))?;
                if key_management::km_disable_key(&key_id) {
                    info!("disable {} key Success", self.object);
                } else {
                    info!("disable {} key Failed", self.object);
                }
            }
            Operations::Enable => {
                let key_type = self.change_object_to_key_type()?;
                let key_id = key_management::km_find_key(key_type).ok_or(format!("key type {} is not valid", self.object))?;
                if key_management::km_enable_key(&key_id) {
                    info!("enable {} key Success", self.object);
                } else {
                    info!("enable {} key Failed", self.object);
                }
            }
            Operations::IssueCertificate => {
                certificate::write_certificate(
                    self.get_object().to_string(),
                    self.get_data().ok_or("certificate data is null".to_string())?
                )?;
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

    fn serialize(&self) -> crate::iccoa2::errors::Result<Vec<u8>> {
        let mut buffer = vec![u8::from(self.operation), u8::from(self.object)];
        if let Some(data) = self.get_data() {
            buffer.append(&mut data.to_vec());
        }
        Ok(buffer)
    }

    fn deserialize(buffer: &[u8]) -> crate::iccoa2::errors::Result<Self::Output> {
        if buffer.len() < NOTIFICATION_LENGTH {
            return Err(ErrorKind::TspError(format!("origin data length less than {}", NOTIFICATION_LENGTH)).into());
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
    let mut tsp_server = loop {
        let tsp_server_socket_addr = format!("{}:{}", TSP_SERVER_ADDRESS, TSP_SERVER_PORT);
        match tokio::net::TcpStream::connect(tsp_server_socket_addr).await {
            Ok(server) => {
                break server
            },
            Err(_) => {
                continue
            }
        }
    };
    let mut tsp_data = vec![0; TSP_DATA_BUFFER_LENGTH];
    loop {
        let _ = tsp_server.read(&mut tsp_data).await.unwrap();
        let notification_cmd = Notification::deserialize(&tsp_data).unwrap();
        info!("Notification is {}", notification_cmd);
        match notification_cmd.operate() {
            Ok(_) => {
                let _ = tsp_server.write("Ok".as_bytes()).await.unwrap();
            }
            Err(_) => {
                let _ = tsp_server.write("Failed".as_bytes()).await.unwrap();
            }
        }
    }
}
