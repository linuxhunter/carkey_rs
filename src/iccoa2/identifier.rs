use std::fmt::{Display, Formatter};
use super::errors::*;

const KEY_SERIAL_ID_LENGTH: usize = 12;
const VEHICLE_SERIAL_ID_LENGTH: usize = 14;
const KEY_ID_LENGTH: usize = 16;
const VEHICLE_ID_LENGTH: usize = 16;

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct KeyId {
    device_oem_id: u16,
    vehicle_oem_id: u16,
    key_serial_id: [u8; KEY_SERIAL_ID_LENGTH],
}

impl KeyId {
    pub fn new(device_oem_id: u16, vehicle_oem_id: u16, key_serial_id: &[u8]) -> Result<Self> {
        Ok(KeyId {
            device_oem_id,
            vehicle_oem_id,
            key_serial_id: key_serial_id
                .try_into()
                .map_err(|e| ErrorKind::IdentifierError(format!("key serial id is invalid: {}",e)))?
        })
    }
    pub fn get_device_oem_id(&self) -> u16 {
        self.device_oem_id
    }
    pub fn set_device_oem_id(&mut self, device_oem_id: u16) {
        self.device_oem_id = device_oem_id;
    }
    pub fn get_vehicle_oem_id(&self) -> u16 {
        self.vehicle_oem_id
    }
    pub fn set_vehicle_oem_id(&mut self, vehicle_oem_id: u16) {
        self.vehicle_oem_id = vehicle_oem_id;
    }
    pub fn get_key_serial_id(&self) -> &[u8] {
        &self.key_serial_id
    }
    pub fn set_key_serial_id(&mut self, key_serial_id: &[u8]) -> Result<()> {
        self.key_serial_id = key_serial_id
            .try_into()
            .map_err(|e| ErrorKind::IdentifierError(format!("key serial id error: {}", e)))?;
        Ok(())
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(KEY_SERIAL_ID_LENGTH);
        buffer.append(&mut self.device_oem_id.to_be_bytes().to_vec());
        buffer.append(&mut self.vehicle_oem_id.to_be_bytes().to_vec());
        buffer.append(&mut self.key_serial_id.to_vec());
        Ok(buffer)
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() != KEY_ID_LENGTH {
            return Err(ErrorKind::IdentifierError(format!("key id length wrong")).into());
        }
        let device_oem_id = u16::from_be_bytes(
            (&data[0..2])
                .try_into()
                .map_err(|e| ErrorKind::IdentifierError(format!("deserialize device oem id error: {}", e)))?
        );
        let vehicle_oem_id = u16::from_be_bytes(
            (&data[2..4])
                .try_into()
                .map_err(|e| ErrorKind::IdentifierError(format!("deserialize vehicle oem id error: {}", e)))?
        );
        let key_serial_id = (&data[4..])
            .try_into()
            .map_err(|e| ErrorKind::IdentifierError(format!("deserailize key serial id error: {}", e)))?;
        Ok(KeyId {
            device_oem_id,
            vehicle_oem_id,
            key_serial_id,
        })
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.serialize().unwrap())
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct VehicleId {
    vehicle_oem_id: u16,
    vehicle_serial_id: [u8; VEHICLE_SERIAL_ID_LENGTH],
}

impl VehicleId {
    pub fn new(vehicle_oem_id: u16, vehicle_serial_id: &[u8]) -> Result<Self> {
        Ok(VehicleId {
            vehicle_oem_id,
            vehicle_serial_id: vehicle_serial_id
                .try_into()
                .map_err(|e| ErrorKind::IdentifierError(format!("vehicle id is invalid: {}", e)))?,
        })
    }
    pub fn get_vehicle_oem_id(&self) -> u16 {
        self.vehicle_oem_id
    }
    pub fn set_vehicle_oem_id(&mut self, vehicle_oem_id: u16) {
        self.vehicle_oem_id = vehicle_oem_id;
    }
    pub fn get_vehicle_serial_id(&self) -> &[u8] {
        &self.vehicle_serial_id
    }
    pub fn set_vehicle_serial_id(&mut self, vehicle_serial_id: &[u8]) -> Result<()> {
        self.vehicle_serial_id = vehicle_serial_id
            .try_into()
            .map_err(|e| ErrorKind::IdentifierError(format!("vehicle serial id error: {}", e)))?;
        Ok(())
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(VEHICLE_ID_LENGTH);
        buffer.append(&mut self.vehicle_oem_id.to_be_bytes().to_vec());
        buffer.append(&mut self.vehicle_serial_id.to_vec());
        Ok(buffer)
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() != VEHICLE_ID_LENGTH {
            return Err(ErrorKind::IdentifierError(format!("vehicle id length wrong")).into());
        }
        let vehicle_oem_id = u16::from_be_bytes(
            (&data[0..2])
                .try_into()
                .map_err(|e| ErrorKind::IdentifierError(format!("deserialize vehicle oem id error: {}", e)))?
        );
        let vehicle_serial_id = (&data[2..])
            .try_into()
            .map_err(|e| ErrorKind::IdentifierError(format!("deserialize vehicle serial id error: {}", e)))?;
        Ok(VehicleId {
            vehicle_oem_id,
            vehicle_serial_id,
        })
    }
}

impl Display for VehicleId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X?}", self.serialize().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_key_id() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        assert_eq!(key_id.get_device_oem_id(), 0x0102);
        assert_eq!(key_id.get_vehicle_oem_id(), 0x0304);
        assert_eq!(key_id.get_key_serial_id(), &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    }
    #[test]
    fn test_update_key_id() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let mut key_id = key_id.unwrap();
        let updated_device_oem_id = 0x1112;
        let updated_vehicle_oem_id = 0x1314;
        let updated_key_serial_id = [0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        key_id.set_device_oem_id(updated_device_oem_id);
        key_id.set_vehicle_oem_id(updated_vehicle_oem_id);
        assert!(key_id.set_key_serial_id(&updated_key_serial_id).is_ok());
        assert_eq!(key_id.get_device_oem_id(), updated_device_oem_id);
        assert_eq!(key_id.get_vehicle_oem_id(), updated_vehicle_oem_id);
        assert_eq!(key_id.get_key_serial_id(), &updated_key_serial_id);
    }
    #[test]
    fn test_key_id_serialize() {
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id);
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        let serialized_key_id = key_id.serialize();
        assert!(serialized_key_id.is_ok());
        let serialized_key_id = serialized_key_id.unwrap();
        assert_eq!(serialized_key_id, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    }
    #[test]
    fn test_key_id_deserialize() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = KeyId::deserialize(data.as_ref());
        assert!(key_id.is_ok());
        let key_id = key_id.unwrap();
        assert_eq!(key_id.get_device_oem_id(), 0x0102);
        assert_eq!(key_id.get_vehicle_oem_id(), 0x0304);
        assert_eq!(key_id.get_key_serial_id(), &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    }
    #[test]
    fn test_create_vehicle_id() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = VehicleId::new(vehicle_oem_id, &vehicle_serial_id);
        assert!(vehicle_id.is_ok());
        let vehicle_id = vehicle_id.unwrap();
        assert_eq!(vehicle_id.get_vehicle_oem_id(), 0x0102);
        assert_eq!(vehicle_id.get_vehicle_serial_id(), &[0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    }
    #[test]
    fn test_update_vehicle_id() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = VehicleId::new(vehicle_oem_id, &vehicle_serial_id);
        assert!(vehicle_id.is_ok());
        let mut vehicle_id = vehicle_id.unwrap();
        let updated_vehicle_oem_id = 0x0201;
        let updated_vehicle_serial_id = [0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
        vehicle_id.set_vehicle_oem_id(updated_vehicle_oem_id);
        assert!(vehicle_id.set_vehicle_serial_id(&updated_vehicle_serial_id).is_ok());
        assert_eq!(vehicle_id.get_vehicle_oem_id(), updated_vehicle_oem_id);
        assert_eq!(vehicle_id.get_vehicle_serial_id(), &updated_vehicle_serial_id);
    }
    #[test]
    fn test_vehicle_id_serialize() {
        let vehicle_oem_id = 0x0102;
        let vehicle_serial_id = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = VehicleId::new(vehicle_oem_id, &vehicle_serial_id);
        assert!(vehicle_id.is_ok());
        let vehicle_id = vehicle_id.unwrap();
        let serialized_vehicle_id = vehicle_id.serialize();
        assert!(serialized_vehicle_id.is_ok());
        let serialized_vehicle_id = serialized_vehicle_id.unwrap();
        assert_eq!(serialized_vehicle_id, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    }
    #[test]
    fn test_vehicle_id_deserialize() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let vehicle_id = VehicleId::deserialize(data.as_ref());
        assert!(vehicle_id.is_ok());
        let vehicle_id = vehicle_id.unwrap();
        assert_eq!(vehicle_id.get_vehicle_oem_id(), 0x0102);
        assert_eq!(vehicle_id.get_vehicle_serial_id(), &[0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    }
}