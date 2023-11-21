use crate::iccoa2::{instructions, Serde};
use super::errors::*;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct Apdu {
    inner: Vec<instructions::ApduInstructions>,
}

#[allow(dead_code)]
impl Apdu {
    pub fn new() -> Self {
        Apdu {
            inner: vec![],
        }
    }
    pub fn get_apdu_instructions(&self) -> &[instructions::ApduInstructions] {
        &self.inner
    }
    pub fn add_apdu_instruction(&mut self, apdu: instructions::ApduInstructions) {
        self.inner.push(apdu);
    }
}

impl Serde for Apdu {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        for apdu in self.inner.iter() {
            let mut serialized_apdu = apdu.serialize()?;
            buffer.push(serialized_apdu.len() as u8);
            buffer.append(&mut serialized_apdu);
        }
        Ok(buffer)
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        let total_length = data.len();
        let mut index = 0x00;
        let mut apdu = Apdu::new();
        loop {
            let length = data[index];
            if index + length as usize > total_length {
                return Err(ErrorKind::ApduError("Apdu structure error".to_string()).into());
            }
            let instruction = instructions::ApduInstructions::deserialize(&data[index+1..index+1+length as usize])?;
            apdu.inner.push(instruction);
            index += 1 + length as usize;
            if index == total_length {
                break;
            }
        }
        Ok(apdu)
    }
}

#[cfg(test)]
mod tests {
    use crate::iccoa2::identifier;
    use super::*;

    #[test]
    fn test_apdu_select_request_serialize() {
        let aid = vec![0x10, 0x20, 0x30, 0x40];
        let request = instructions::select::CommandApduSelect::new(aid.as_ref());
        let mut apdu = Apdu::new();
        apdu.add_apdu_instruction(instructions::ApduInstructions::CommandSelect(request));
        let serialized_apdu = apdu.serialize();
        assert!(serialized_apdu.is_ok());
        let serialized_apdu = serialized_apdu.unwrap();
        assert_eq!(
            serialized_apdu,
            vec![
                0x0B,
                0x01,
                0x00, 0xA4, 0x04, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40, 0x00,
            ],
        );
    }
    #[test]
    fn test_apdu_request_serialize() {
        let aid = vec![0x10, 0x20, 0x30, 0x40];
        let select = instructions::select::CommandApduSelect::new(aid.as_ref());
        let cla = 0x00;
        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let random = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let rke_command = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let rke = instructions::rke::CommandApduRke::new(
            cla,
            key_id,
            random.as_ref(),
            rke_command.as_ref(),
        );
        let mut apdu = Apdu::new();
        apdu.add_apdu_instruction(instructions::ApduInstructions::CommandSelect(select));
        apdu.add_apdu_instruction(instructions::ApduInstructions::CommandRke(rke));
        let serialized_apdu = apdu.serialize();
        assert!(serialized_apdu.is_ok());
        let serialized_apdu = serialized_apdu.unwrap();
        assert_eq!(
            serialized_apdu,
            vec![
                0x0B,
                0x01,
                0x00, 0xA4, 0x04, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40, 0x00,
                0x33,
                0x0D,
                0x00, 0x66, 0x00, 0x00,
                0x2C,
                0x89, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x55, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x57, 0x06,
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                0x00,
            ],
        );
    }
    #[test]
    fn test_apdu_select_request_deserialize() {
        let data = vec![
            0x0B,
            0x01,
            0x00, 0xA4, 0x04, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40, 0x00,
        ];
        let apdu = Apdu::deserialize(data.as_ref());
        assert!(apdu.is_ok());
        let apdu = apdu.unwrap();
        assert_eq!(apdu.get_apdu_instructions().len(), 1);
        for apdu_unit in apdu.get_apdu_instructions() {
            match apdu_unit {
                instructions::ApduInstructions::CommandSelect(select) => {
                    assert_eq!(select.get_aid(), &vec![0x10, 0x20, 0x30, 0x40]);
                },
                _ => {
                    assert!(false);
                }
            }
        }
    }
    #[test]
    fn test_apdu_request_deserialize() {
        let data = vec![
            0x0B,
            0x01,
            0x00, 0xA4, 0x04, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40, 0x00,
            0x33,
            0x0D,
            0x00, 0x66, 0x00, 0x00,
            0x2C,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x55, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x57, 0x06,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00,
        ];
        let apdu = Apdu::deserialize(data.as_ref());
        assert!(apdu.is_ok());
        let apdu = apdu.unwrap();
        assert_eq!(apdu.get_apdu_instructions().len(), 2);
        for apdu_unit in apdu.get_apdu_instructions() {
            match apdu_unit {
                instructions::ApduInstructions::CommandSelect(select) => {
                    assert_eq!(select.get_aid(), &vec![0x10, 0x20, 0x30, 0x40]);
                },
                instructions::ApduInstructions::CommandRke(rke) => {
                    let device_oem_id = 0x0102;
                    let vehicle_oem_id = 0x0304;
                    let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
                    assert_eq!(rke.get_cla(), 0x00);
                    assert_eq!(rke.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
                    assert_eq!(
                        rke.get_random(),
                        vec![
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                        ],
                    );
                    assert_eq!(rke.get_command(), vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
                },
                _ => {
                    assert!(false);
                }
            }
        }
    }
    #[test]
    fn test_apdu_select_response_serialize() {
        let version = 0x1010;
        let sw1 = 0x90;
        let sw2 = 0x00;
        let status = instructions::common::ResponseApduTrailer::new(sw1, sw2);
        let response = instructions::select::ResponseApduSelect::new(version, status);
        let mut apdu = Apdu::new();
        apdu.add_apdu_instruction(instructions::ApduInstructions::ResponseSelect(response));
        let serialized_apdu = apdu.serialize();
        assert!(serialized_apdu.is_ok());
        let serialized_apdu = serialized_apdu.unwrap();
        assert_eq!(
            serialized_apdu,
            vec![
                0x07,
                0x02,
                0x5A, 0x02,
                0x10, 0x10,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_apdu_response_serialize() {
        let version = 0x1010;
        let sw1 = 0x90;
        let sw2 = 0x00;
        let status = instructions::common::ResponseApduTrailer::new(sw1, sw2);
        let select = instructions::select::ResponseApduSelect::new(version, status);

        let device_oem_id = 0x0102;
        let vehicle_oem_id = 0x0304;
        let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let key_id = identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap();
        let signature = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let status = instructions::common::ResponseApduTrailer::new(0x90, 0x00);
        let rke = instructions::rke::ResponseApduRke::new(
            key_id,
            signature.as_ref(),
            status,
        );
        let mut apdu = Apdu::new();
        apdu.add_apdu_instruction(instructions::ApduInstructions::ResponseSelect(select));
        apdu.add_apdu_instruction(instructions::ApduInstructions::ResponseRke(rke));
        let serialized_apdu = apdu.serialize();
        assert!(serialized_apdu.is_ok());
        let serialized_apdu = serialized_apdu.unwrap();
        assert_eq!(
            serialized_apdu,
            vec![
                0x07,
                0x02,
                0x5A, 0x02,
                0x10, 0x10,
                0x90, 0x00,
                0x57,
                0x0E,
                0x89, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x8F, 0x40,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x90, 0x00,
            ],
        );
    }
    #[test]
    fn test_apdu_select_response_deserialize() {
        let data = vec![
            0x07,
            0x02,
            0x5A, 0x02,
            0x10, 0x10,
            0x90, 0x00,
        ];
        let apdu = Apdu::deserialize(data.as_ref());
        assert!(apdu.is_ok());
        let apdu = apdu.unwrap();
        assert_eq!(apdu.get_apdu_instructions().len(), 1);
        for apdu_unit in apdu.get_apdu_instructions() {
            match apdu_unit {
                instructions::ApduInstructions::ResponseSelect(select) => {
                    assert_eq!(select.get_version(), 0x1010);
                    assert_eq!(select.get_status(), &instructions::common::ResponseApduTrailer::new(0x90, 0x00));
                },
                _ => {
                    assert!(false);
                }
            }
        }
    }
    #[test]
    fn test_apdu_response_deserialize() {
        let data = vec![
            0x07,
            0x02,
            0x5A, 0x02,
            0x10, 0x10,
            0x90, 0x00,
            0x57,
            0x0E,
            0x89, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x8F, 0x40,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x90, 0x00,
        ];
        let apdu = Apdu::deserialize(data.as_ref());
        assert!(apdu.is_ok());
        let apdu = apdu.unwrap();
        assert_eq!(apdu.get_apdu_instructions().len(), 2);
        for apdu_unit in apdu.get_apdu_instructions() {
            match apdu_unit {
                instructions::ApduInstructions::ResponseSelect(select) => {
                    assert_eq!(select.get_version(), 0x1010);
                    assert_eq!(select.get_status(), &instructions::common::ResponseApduTrailer::new(0x90, 0x00));
                },
                instructions::ApduInstructions::ResponseRke(rke) => {
                    let device_oem_id = 0x0102;
                    let vehicle_oem_id = 0x0304;
                    let key_serial_id = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
                    assert_eq!(rke.get_key_id(), &identifier::KeyId::new(device_oem_id, vehicle_oem_id, &key_serial_id).unwrap());
                    assert_eq!(
                        rke.get_signature(),
                        vec![
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        ],
                    );
                    assert_eq!(rke.get_status(), &instructions::common::ResponseApduTrailer::new(0x90, 0x00));
                },
                _ => {
                    assert!(false);
                }
            }
        }
    }
}
