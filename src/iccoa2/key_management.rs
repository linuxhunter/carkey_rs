use std::fmt::{Display, Formatter};
use crate::iccoa2::identifier::KeyId;

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum KeyStatus {
    #[default]
    Disable = 0x00,
    Enable = 0x01,
}

impl TryFrom<u8> for KeyStatus {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(KeyStatus::Disable),
            0x01 => Ok(KeyStatus::Enable),
            _ => Err(format!("Unsupported Key Status value: {}", value))
        }
    }
}

impl From<KeyStatus> for u8 {
    fn from(value: KeyStatus) -> Self {
        match value {
            KeyStatus::Disable => 0x00,
            KeyStatus::Enable => 0x01,
        }
    }
}

impl Display for KeyStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Disable => write!(f, "Disabled"),
            KeyStatus::Enable => write!(f, "Enabled"),
        }
    }
}

#[derive(Debug, Default, Clone, PartialOrd, PartialEq)]
pub struct Key {
    key: KeyId,
    status: KeyStatus,
    description: Option<String>,
}

#[allow(dead_code)]
impl Key {
    pub fn new(key: KeyId, status: KeyStatus, description: Option<String>) -> Self {
        Key {
            key,
            status,
            description,
        }
    }
    pub fn get_key(&self) -> &KeyId {
        &self.key
    }
    pub fn set_key(&mut self, key: KeyId) {
        self.key = key;
    }
    pub fn get_status(&self) -> KeyStatus {
        self.status
    }
    pub fn set_status(&mut self, status: KeyStatus) {
        self.status = status;
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
        write!(f, "\tStatus: {}", self.get_status())?;
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
    pub fn remove_key(&mut self, key: &Key) {
        if let Some(index) = self.keys.iter().position(|e| *e == *key) {
            self.keys.remove(index);
            self.try_remove_current_key(key.get_key());
        }
    }
    pub fn enable_key(&mut self, key: &Key) -> bool {
        if let Some(index) = self.keys.iter().position(|e| *e == *key) {
            self.keys[index].status = KeyStatus::Enable;
            self.set_current_key(self.keys[index].key.clone());
            true
        } else {
            false
        }
    }
    pub fn disable_key(&mut self, key: &Key) -> bool {
        if let Some(index) = self.keys.iter().position(|e| *e == *key) {
            self.keys[index].status = KeyStatus::Disable;
            self.try_remove_current_key(key.get_key());
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
    pub fn set_current_key(&mut self, key: KeyId) {
        self.current_key = Some(key);
    }
    pub fn try_remove_current_key(&mut self, key: &KeyId) {
        if let Some(ref current_key) = self.current_key {
            if current_key.eq(key) {
                self.current_key = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
            KeyStatus::Disable,
            None,
        );
        key_management.add_key(key);
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x01);
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
            KeyStatus::Disable,
            None,
        );
        key_management.add_key(key);
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x01);
        assert_eq!(key_management.keys[0].get_status(), KeyStatus::Disable);
        assert_eq!(key_management.keys[0].get_description(), None);
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
            KeyStatus::Disable,
            None,
        );
        key_management.add_key(key);
        let key2 = Key::new(
            KeyId::new(
                0x0201,
                0x0403,
                &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
            ).unwrap(),
            KeyStatus::Disable,
            None,
        );
        key_management.add_key(key2.clone());
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x02);
        key_management.remove_key(&key2);
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x01);
        assert_eq!(key_management.keys[0].get_status(), KeyStatus::Disable);
        assert_eq!(key_management.keys[0].get_description(), None);
        assert_eq!(key_management.keys[0].get_key(), &KeyId::new(
            0x0102,
            0x0304,
            &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
        ).unwrap())
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
            KeyStatus::Disable,
            None,
        );
        key_management.add_key(key);
        let key2 = Key::new(
            KeyId::new(
                0x0201,
                0x0403,
                &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
            ).unwrap(),
            KeyStatus::Disable,
            None,
        );
        key_management.add_key(key2.clone());
        assert!(key_management.current_key.is_none());
        assert_eq!(key_management.keys.len(), 0x02);
        key_management.enable_key(&key2);
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
            KeyStatus::Disable,
            None,
        );
        key_management.add_key(key);
        let key2 = Key::new(
            KeyId::new(
                0x0201,
                0x0403,
                &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
            ).unwrap(),
            KeyStatus::Enable,
            None,
        );
        key_management.add_key(key2.clone());
        assert!(key_management.get_current_key().is_some());
        assert_eq!(key_management.get_current_key(), Some(&KeyId::new(
            0x0201,
            0x0403,
            &[0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20],
        ).unwrap()));
        key_management.disable_key(&key2);
        assert!(key_management.current_key.is_none());
    }
}
