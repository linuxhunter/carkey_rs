use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::sync::Mutex;
use crate::iccoa2::certificate::get_certificate_extension;
use crate::iccoa2::identifier::KeyId;
use crate::iccoa2::{instructions, Serde};
use crate::iccoa2::errors::*;

lazy_static! {
    static ref KEY_MANAGER: Mutex<KeyManagement> = Mutex::new(KeyManagement::new());
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum KeyType {
    #[default]
    Owner = 0x00,
    Friend = 0x01,
}

impl TryFrom<u8> for KeyType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(KeyType::Owner),
            0x01 => Ok(KeyType::Friend),
            _ => Err(format!("Unsupported Key Type value: {}", value))
        }
    }
}

impl From<KeyType> for u8 {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Owner => 0x00,
            KeyType::Friend => 0x01,
        }
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Owner => write!(f, "Owner"),
            KeyType::Friend => write!(f, "Friend"),
        }
    }
}

#[derive(Debug, Default, Clone, PartialOrd, PartialEq)]
pub struct Key {
    key: KeyId,
    key_type: KeyType,
    status: instructions::list_dk::KeyIdStatus,
    certificate: Option<PathBuf>,
    description: Option<String>,
}

#[allow(dead_code)]
impl Key {
    pub fn new(key: KeyId, key_type: KeyType, status: instructions::list_dk::KeyIdStatus, certificate: Option<PathBuf>, description: Option<String>) -> Self {
        Key {
            key,
            key_type,
            status,
            certificate,
            description,
        }
    }
    pub fn from_cert_and_oid(path: PathBuf, oid_str: &str, key_type: KeyType, status: instructions::list_dk::KeyIdStatus, description: Option<String>) -> Result<Self> {
        let raw_key_id = get_certificate_extension(path.clone(), oid_str)?;
        let key_id = KeyId::deserialize(raw_key_id.as_ref())?;
        Ok(Key::new(
            key_id.clone(),
            key_type,
            status,
            Some(path),
            description,
        ))
    }
    pub fn get_key(&self) -> &KeyId {
        &self.key
    }
    pub fn set_key(&mut self, key: KeyId) {
        self.key = key;
    }
    pub fn get_key_type(&self) -> KeyType {
        self.key_type
    }
    pub fn set_key_type(&mut self, key_type: KeyType) {
        self.key_type = key_type;
    }
    pub fn get_status(&self) -> instructions::list_dk::KeyIdStatus{
        self.status
    }
    pub fn set_status(&mut self, status: instructions::list_dk::KeyIdStatus) {
        self.status = status;
    }
    pub fn get_certificate(&self) -> Option<&PathBuf> {
        if let Some(ref path) = self.certificate {
            Some(path)
        } else {
            None
        }
    }
    pub fn set_certificate(&mut self, certificate: Option<PathBuf>) {
        self.certificate = certificate;
    }
    pub fn get_description(&self) -> Option<&str> {
        if let Some(ref description) = self.description {
            Some(description)
        } else {
            None
        }
    }
    pub fn set_description(&mut self, description: String) {
        self.description = Some(description);
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[Key]: ")?;
        write!(f, "\tID: {}", self.get_key())?;
        write!(f, "\tType: {}", self.get_key_type())?;
        write!(f, "\tStatus: {}", self.get_status())?;
        write!(f, "\tCertificate: {:?}", self.get_certificate())?;
        write!(f, "\tDescription: {:?}", self.get_description())
    }
}

#[derive(Debug, Default)]
pub struct KeyManagement {
    keys: Vec<Key>,
    current_key: Option<KeyId>,
}

#[allow(dead_code)]
impl KeyManagement {
    pub fn new() -> Self {
        KeyManagement {
            keys: vec![],
            current_key: None,
        }
    }
    pub fn add_key(&mut self, key: Key) {
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
    }
    pub fn remove_key(&mut self, key: &KeyId) {
        if let Some(index) = self.keys.iter().position(|e| e.get_key().eq(key)) {
            self.keys.remove(index);
            self.set_current_key(None);
        }
    }
    pub fn find_key(&self, key_id: &KeyId) -> Result<&Key> {
        if let Some(index) = self.keys.iter().position(|e| e.key == *key_id) {
            Ok(&self.keys[index])
        } else {
            Err(ErrorKind::KeyManagementsError(format!("key id {} is not exist", key_id)).into())
        }
    }
    pub fn enable_key(&mut self, key: &KeyId) -> bool {
        if let Some(index) = self.keys.iter().position(|e| e.get_key().eq(key)) {
            if self.keys[index].get_certificate().is_some() {
                self.keys[index].set_status(instructions::list_dk::KeyIdStatus::Activated);
                self.set_current_key(Some(self.keys[index].key.clone()));
                true
            } else {
                false
            }
        } else {
            false
        }
    }
    pub fn disable_key(&mut self, key: &KeyId) -> bool {
        if let Some(index) = self.keys.iter().position(|e| e.get_key().eq(key)) {
            self.keys[index].status = instructions::list_dk::KeyIdStatus::Delivered;
            if self.get_current_key().is_some() &&
                self.keys[index].get_key().eq(self.get_current_key().unwrap()) {
                self.set_current_key(None);
            }
            true
        } else {
            false
        }
    }
    pub fn get_current_key(&self) -> Option<&KeyId> {
        if let Some(ref key) = self.current_key {
            Some(key)
        } else {
            None
        }
    }
    pub fn set_current_key(&mut self, key: Option<KeyId>) {
        self.current_key = key;
    }
}

#[allow(dead_code)]
pub fn km_add_key(key: Key) {
    let mut key_manager = KEY_MANAGER.lock().unwrap();
    key_manager.add_key(key);
}

#[allow(dead_code)]
pub fn km_remove_key(key: &KeyId) {
    let mut key_manager = KEY_MANAGER.lock().unwrap();
    key_manager.remove_key(key);
}

#[allow(dead_code)]
pub fn km_enable_key(key: &KeyId) -> bool {
    let mut key_manager = KEY_MANAGER.lock().unwrap();
    key_manager.enable_key(key)
}

#[allow(dead_code)]
pub fn km_disable_key(key: &KeyId) -> bool{
    let mut key_manager = KEY_MANAGER.lock().unwrap();
    key_manager.disable_key(key)
}

pub fn km_find_key(key_type: KeyType) -> Option<KeyId> {
    let key_manager = KEY_MANAGER.lock().unwrap();
    for key in key_manager.keys.iter() {
        if key.get_key_type() == key_type {
            return Some(key.get_key().clone());
        }
    }
    None
}

#[allow(dead_code)]
pub fn km_get_current_key() -> Option<KeyId> {
    let key_manager = KEY_MANAGER.lock().unwrap();
    key_manager.get_current_key().cloned()
}

#[cfg(test)]
mod tests {
    use crate::iccoa2::instructions::list_dk::KeyIdStatus;
    use super::*;

    #[test]
    fn test_create_key_management() {
        let mut key_management = KeyManagement::new();
        let key = Key::new(
            KeyId::new(
                0x0102,
                0x0304,
                &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            ).unwrap(),
            KeyType::Owner,
            KeyIdStatus::Delivered,
            None,
            None,
        );
        key_management.add_key(key);
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x01);
        assert_eq!(key_management.keys[0].get_key_type(), KeyType::Owner);
        assert_eq!(key_management.keys[0].get_status(), KeyIdStatus::Delivered);
        assert!(key_management.keys[0].get_certificate().is_none());
        assert!(key_management.keys[0].get_description().is_none());
    }
    #[test]
    fn test_add_key_management() {
        let mut key_management = KeyManagement::new();
        let key = Key::new(
            KeyId::new(
                0x0102,
                0x0304,
                &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            ).unwrap(),
            KeyType::Owner,
            KeyIdStatus::Delivered,
            None,
            None,
        );
        key_management.add_key(key);
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x01);
        assert_eq!(key_management.keys[0].get_status(), KeyIdStatus::Delivered);
        assert!(key_management.keys[0].get_certificate().is_none());
        assert!(key_management.keys[0].get_description().is_none());
        assert_eq!(key_management.keys[0].get_key(), &KeyId::new(
            0x0102,
            0x0304,
            &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
        ).unwrap())
    }
    #[test]
    fn test_remove_key_management() {
        let mut key_management = KeyManagement::new();
        let key = Key::new(
            KeyId::new(
                0x0102,
                0x0304,
                &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            ).unwrap(),
            KeyType::Owner,
            KeyIdStatus::Delivered,
            Some(PathBuf::from("/etc/certs/iccoa2/owner.pem")),
            None,
        );
        key_management.add_key(key);
        let key2 = Key::new(
            KeyId::new(
                0x0201,
                0x0403,
                &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
            ).unwrap(),
            KeyType::Friend,
            KeyIdStatus::Delivered,
            Some(PathBuf::from("/etc/certs/iccoa2/friend.pem")),
            None,
        );
        key_management.add_key(key2.clone());
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x02);
        key_management.remove_key(key2.get_key());
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x01);
        assert_eq!(key_management.keys[0].get_key(), &KeyId::new(
            0x0102,
            0x0304,
            &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
        ).unwrap());
        assert_eq!(key_management.keys[0].get_key_type(), KeyType::Owner);
        assert_eq!(key_management.keys[0].get_status(), KeyIdStatus::Delivered);
        assert_eq!(key_management.keys[0].get_certificate(), Some(&PathBuf::from("/etc/certs/iccoa2/owner.pem")));
        assert!(key_management.keys[0].get_description().is_none());
    }
    #[test]
    fn test_enable_key_management() {
        let mut key_management = KeyManagement::new();
        let key = Key::new(
            KeyId::new(
                0x0102,
                0x0304,
                &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            ).unwrap(),
            KeyType::Owner,
            KeyIdStatus::Delivered,
            Some(PathBuf::from("/etc/certs/iccoa2/owner.pem")),
            None,
        );
        key_management.add_key(key);
        let key2 = Key::new(
            KeyId::new(
                0x0201,
                0x0403,
                &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
            ).unwrap(),
            KeyType::Friend,
            KeyIdStatus::Delivered,
            Some(PathBuf::from("/etc/certs/iccoa2/friend.pem")),
            None,
        );
        key_management.add_key(key2.clone());
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x02);
        assert_eq!(key_management.enable_key(key2.get_key()), true);
        assert!(key_management.current_key.is_some());
        assert_eq!(key_management.get_current_key(), Some(&KeyId::new(
            0x0201,
            0x0403,
            &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
        ).unwrap()));
    }
    #[test]
    fn test_disable_key_management() {
        let mut key_management = KeyManagement::new();
        let key = Key::new(
            KeyId::new(
                0x0102,
                0x0304,
                &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            ).unwrap(),
            KeyType::Owner,
            KeyIdStatus::Delivered,
            Some(PathBuf::from("/etc/certs/iccoa2/owner.pem")),
            None,
        );
        key_management.add_key(key);
        let key2 = Key::new(
            KeyId::new(
                0x0201,
                0x0403,
                &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
            ).unwrap(),
            KeyType::Friend,
            KeyIdStatus::Delivered,
            Some(PathBuf::from("/etc/certs/iccoa2/friend.pem")),
            None,
        );
        key_management.add_key(key2.clone());
        key_management.enable_key(key2.get_key());
        assert!(key_management.get_current_key().is_some());
        assert_eq!(key_management.get_current_key(), Some(&KeyId::new(
            0x0201,
            0x0403,
            &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
        ).unwrap()));
        key_management.disable_key(key2.get_key());
        assert!(key_management.current_key.is_none());
    }
}
