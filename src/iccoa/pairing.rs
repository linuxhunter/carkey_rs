use super::objects::{ICCOA, Header, Mark, Body, MessageData, create_iccoa_header, create_iccoa_body_message_data, create_iccoa_body, create_iccoa};
use super::errors::*;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Scrypt {
    salt: [u8; 16],
    nscrypt: [u8; 4],
    r: [u8; 2],
    p: [u8; 2],
}

impl Scrypt {
    pub fn new() -> Self {
        Scrypt {
            ..Default::default()
        }
    }
    pub fn set_salt(&mut self, salt: &[u8]) -> Result<()> {
        if salt.len() != 16 {
            return Err(ErrorKind::ICCOAPairingError("salt length error".to_string()).into());
        }
        self.salt = salt.try_into().map_err(|_| String::from("get salt value error"))?;
        Ok(())
    }
    pub fn get_salt(&self) -> &[u8] {
        &self.salt
    }
    pub fn set_nscrypt(&mut self, nscrypt: &[u8]) -> Result<()> {
        if nscrypt.len() != 4 {
            return Err(ErrorKind::ICCOAPairingError("nscrypt length error".to_string()).into());
        }
        self.nscrypt = nscrypt.try_into().map_err(|_| ErrorKind::ICCOAPairingError("get nscrypt value error".to_string()))?;
        Ok(())
    }
    pub fn get_nscrypt(&self) -> &[u8] {
        &self.nscrypt
    }
    pub fn set_r(&mut self, r: &[u8]) -> Result<()> {
        if r.len() != 2 {
            return Err(ErrorKind::ICCOAPairingError("r length error".to_string()).into());
        }
        self.r = r.try_into().map_err(|_| ErrorKind::ICCOAPairingError("get r value error".to_string()))?;
        Ok(())
    }
    pub fn get_r(&self) -> &[u8] {
        &self.r
    }
    pub fn set_p(&mut self, p: &[u8]) -> Result<()> {
        if p.len() != 2 {
            return Err(ErrorKind::ICCOAPairingError("p length error".to_string()).into());
        }
        self.p = p.try_into().map_err(|_| ErrorKind::ICCOAPairingError("get p value error".to_string()))?;
        Ok(())
    }
    pub fn get_p(&self) -> &[u8] {
        &self.p
    }
}

pub fn calculate_pB() -> [u8; 65] {
    [0x00; 65]
}

pub fn calculate_pA() -> [u8; 65] {
    [0x00; 65]
}

pub fn calculate_cB() -> [u8; 18] {
    [0x00; 18]
}

pub fn calculate_cA() -> [u8; 18] {
    [0x00; 18]
}

pub fn get_vehicle_certificate() -> Vec<u8> {
    [0x01; 1024].to_vec()
}

pub fn get_mobile_device_certificate() -> Vec<u8> {
    [0x02; 1024].to_vec()
}

pub fn create_iccoa_pairing_data_request(transaction_id: u16, scrypt: &Scrypt, p_b: &[u8]) -> Result<ICCOA> {
    if p_b.len() != 0x41 {
        return Err(ErrorKind::ICCOAPairingError("pB length is not correct!".to_string()).into());
    }
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+102,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut spake2_plus_data = Vec::new();
    spake2_plus_data.push(0x51);
    spake2_plus_data.push(0x41);
    spake2_plus_data.append(&mut p_b.to_vec());
    spake2_plus_data.push(0xC0);
    spake2_plus_data.push(0x10);
    spake2_plus_data.append(&mut scrypt.get_salt().to_vec());
    spake2_plus_data.push(0xC1);
    spake2_plus_data.push(0x04);
    spake2_plus_data.append(&mut scrypt.get_nscrypt().to_vec());
    spake2_plus_data.push(0xC2);
    spake2_plus_data.push(0x02);
    spake2_plus_data.append(&mut scrypt.get_r().to_vec());
    spake2_plus_data.push(0xC3);
    spake2_plus_data.push(0x02);
    spake2_plus_data.append(&mut scrypt.get_p().to_vec());
    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x02,
        &spake2_plus_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_data_response(transaction_id: u16, status: u16, p_a: &[u8]) -> Result<ICCOA> {
    if p_a.len() != 0x41 {
        return Err(ErrorKind::ICCOAPairingError("pA length is not correct!".to_string()).into());
    }
    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+73,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let mut spack2_plus_data = Vec::new();
    spack2_plus_data.push(0x52);
    spack2_plus_data.push(0x41);
    spack2_plus_data.append(&mut p_a.to_vec());
    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x02,
        &spack2_plus_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_paring_auth_request(transaction_id: u16, c_b: &[u8]) -> Result<ICCOA> {
    if c_b.len() != 0x12 {
        return Err(ErrorKind::ICCOAPairingError("cB length is not correct!".to_string()).into());
    }
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+21,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x03,
        c_b,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_auth_response(transaction_id: u16, status: u16, c_a: &[u8]) -> Result<ICCOA> {
    if c_a.len() != 0x12 {
        return Err(ErrorKind::ICCOAPairingError("cA length is not correct!".to_string()).into());
    }
    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+23,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x03,
        c_a,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_certificate_write_request(transaction_id: u16, vehicle_pub_cert: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+vehicle_pub_cert.len() as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x04,
        vehicle_pub_cert,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_certificate_write_response(transaction_id: u16, status: u16) -> Result<ICCOA> {
    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+5,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x04,
        &[],
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_certificate_read_request(transaction_id: u16, cert_type_list: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+cert_type_list.len() as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        false,
        0x0000,
        0x05,
        cert_type_list,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_certificate_read_response(transaction_id: u16, status: u16, cert: &[u8]) -> Result<ICCOA> {
    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+5+cert.len() as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        0x05,
        cert,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spake2_plus_data_request() {
        let transaction_id = 0x0001;
        let mut scrypt = Scrypt::new();
        scrypt.set_nscrypt(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        scrypt.set_salt(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]).unwrap();
        scrypt.set_r(&[0x01, 0x02]).unwrap();
        scrypt.set_p(&[0x02, 0x01]).unwrap();
        let p_b = calculate_pB();
        let iccoa = create_iccoa_pairing_data_request(transaction_id, &scrypt, &p_b).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0001,
                pdu_length: 12+1+102+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![
                        81, 65, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 192, 16, 0, 1, 2,
                        3, 4, 5, 6, 7, 8, 9, 10,
                        11, 12, 13, 14, 15, 193, 4, 1,
                        2, 3, 4, 194, 2, 1, 2, 195, 2,
                        2, 1],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_data_response() {
        let transaction_id = 0x0002;
        let status = 0x0000;
        let p_a = calculate_pA();
        let iccoa = create_iccoa_pairing_data_response(transaction_id, status, &p_a).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0002,
                pdu_length: 12+1+73+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: 0x0000,
                    tag: 0x02,
                    value: vec![
                        82, 65, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0
                    ]
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_auth_request() {
        let transaction_id = 0x0002;
        let c_b = calculate_cB();
        let iccoa = create_iccoa_paring_auth_request(transaction_id, &c_b).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0002,
                pdu_length: 12+1+21+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment:false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x03,
                    value: [0x00; 18].to_vec(),
                    ..Default::default()
                }

            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_auth_response() {
        let transaction_id= 0x0003;
        let c_a = calculate_cA();
        let status = 0x0000;
        let iccoa = create_iccoa_pairing_auth_response(transaction_id, status, &c_a).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0003,
                pdu_length: 12+1+23+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: 0x0000,
                    tag: 0x03,
                    value: [0x00; 18].to_vec(),
                },
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_spake2_plus_certificate_write_request() {
        let transaction_id = 0x0004;
        let vehicle_certificate = get_vehicle_certificate();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &vehicle_certificate).unwrap(); 
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+1027+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x04,
                    value: [0x01; 1024].to_vec(),
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        })       
    }
    #[test]
    fn test_spake2_plus_certificate_write_response() {
        let transaction_id = 0x0004;
        let status = 0x0000;
        let iccoa = create_iccoa_pairing_certificate_write_response(transaction_id, status).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0004,
                pdu_length: 12+1+5+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: 0x0000,
                    tag: 0x04,
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_spake2_plus_certificate_read_request() {
        let transaction_id = 0x0005;
        let cert_type_list = [0x01, 0x02, 0x03];
        let iccoa = create_iccoa_pairing_certificate_read_request(transaction_id, &cert_type_list).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+6+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x05,
                    value: [0x01, 0x02, 0x03].to_vec(),
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_certificate_read_response() {
        let transaction_id = 0x0005;
        let status = 0x0000;
        let mobile_device_certificate = get_mobile_device_certificate();
        let iccoa = create_iccoa_pairing_certificate_read_response(transaction_id, status, &mobile_device_certificate).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0005,
                pdu_length: 12+1+1029+8,
                mark: Mark {
                    encrypt_type: crate::iccoa::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: crate::iccoa::objects::MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: 0x0000,
                    tag: 0x05,
                    value: [0x02; 1024].to_vec(),
                },
            },
            mac: [0x00; 8],
        })
    }
}