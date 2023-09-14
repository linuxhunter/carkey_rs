use std::io::{Read, Write};
use std::sync::Mutex;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use rand::Rng;

use crate::iccoa::utils::CipherKey;

use super::objects::{ICCOA, Mark, create_iccoa_header, create_iccoa_body_message_data, create_iccoa_body, create_iccoa};
use super::{errors::*, TLVPayload, TLVPayloadBuilder, auth, utils};
use super::status::{StatusBuilder, Status, StatusTag};

const SALT: &str = "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4";
const SCRYPT_N: u32 = 32768;
const SCRYPT_R: u16 = 1;
const SCRYPT_P: u16 = 8;

lazy_static! {
    static ref W0: BigNum = BigNum::from_hex_str("1DDA099ADFB7464CB073503FCDFFBBEED9499646A37E3FA53271976AB407361C").unwrap();
    static ref L: BigNum = BigNum::from_hex_str("1F2131221F850910EA2EBD8E744F3B1320B423310B49CAADE1A9338D829D29D963D910E6C41F6AEFA5EDCDEA7E12D52AEA2581D07D34C861C0776CE111DBE000").unwrap();
    static ref M: BigNum = BigNum::from_hex_str("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f").unwrap();
    static ref N: BigNum = BigNum::from_hex_str("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49").unwrap();
    static ref P: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref RANDOM_Y: Mutex<u32> = Mutex::new(0);
    static ref PAIRING_PAYLOAD_LENGTH_MINIMUM: usize = 0x02;
    static ref PAIRING_KEY: Mutex<CipherKey> = Mutex::new(CipherKey::new());
    static ref PAIRING_PA: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref PAIRING_PB: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref PAIRING_Z: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref PAIRING_V: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref PAIRING_CA: Mutex<Vec<u8>> = Mutex::new(vec![]);
}

pub fn calculate_p_b() -> BigNum {
    let nid = Nid::X9_62_PRIME256V1;
    let group = EcGroup::from_curve_name(nid).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    //calculate base point P
    let base_point = group.generator();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    base_point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx).unwrap();
    let mut p = P.lock().unwrap();
    *p = x;

    //calculate random u32 y
    let mut rng = rand::thread_rng();
    let y = rng.gen::<u32>();
    let mut random_y = RANDOM_Y.lock().unwrap();
    *random_y = y;

    //calculate p_b
    let mut tmp_y = BigNum::new().unwrap();
    tmp_y.checked_mul(&*p, &BigNum::from_u32(y).unwrap(), &mut ctx).unwrap();

    let mut tmp_n = BigNum::new().unwrap();
    tmp_n.checked_mul(&N, &W0, &mut ctx).unwrap();

    let mut p_b = BigNum::new().unwrap();
    p_b.checked_add(&tmp_y, &tmp_n).unwrap();
    p_b
}

pub fn verify_p_a() {
    let h = 1;
    let y = *RANDOM_Y.lock().unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let mut tmp_m = BigNum::new().unwrap();
    tmp_m.checked_mul(&W0, &M, &mut ctx).unwrap();

    let p_a = PAIRING_PA.lock().unwrap();
    let mut tmp_z = BigNum::new().unwrap();
    tmp_z.checked_sub(&*p_a, &tmp_m).unwrap();

    let mut ec_z = BigNum::new().unwrap();
    ec_z.checked_mul(&BigNum::from_u32(h*y).unwrap(), &tmp_z, &mut ctx).unwrap();
    let mut ec_v = BigNum::new().unwrap();
    ec_v.checked_mul(&L, &BigNum::from_u32(h*y).unwrap(), &mut ctx).unwrap();

    let mut pairing_z = PAIRING_Z.lock().unwrap();
    *pairing_z = ec_z;
    let mut paring_v = PAIRING_V.lock().unwrap();
    *paring_v = ec_v;
}

pub fn calculate_p_a() -> [u8; 65] {
    [0x00; 65]
}

pub fn set_pairing_key_mac(key: &[u8]) {
    let mut pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.set_key_mac(key);
}

pub fn set_pairing_key_enc(key: &[u8]) {
    let mut pairing_Key = PAIRING_KEY.lock().unwrap();
    pairing_Key.set_key_enc(key);
}

pub fn get_pairing_key_mac() -> Vec<u8> {
    let pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.get_key_mac()
}

pub fn get_pairing_key_enc() -> Vec<u8> {
    let pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.get_key_enc()
}

pub fn calculate_length_element_tt(element: &[u8]) -> Vec<u8> {
    let mut tt_elements = Vec::new();
    let length_u64 = element.len() as u64;
    tt_elements.append(&mut length_u64.to_le_bytes().to_vec());
    tt_elements.append(&mut element.to_vec());
    tt_elements
}

pub fn calculate_tt() -> Vec<u8> {
    let mut tt = Vec::new();
    tt.append(&mut calculate_length_element_tt(M.to_vec().as_slice()));
    tt.append(&mut calculate_length_element_tt(N.to_vec().as_slice()));
    tt.append(&mut calculate_length_element_tt(PAIRING_PA.lock().unwrap().to_vec().as_slice()));
    tt.append(&mut calculate_length_element_tt(PAIRING_PB.lock().unwrap().to_vec().as_slice()));
    tt.append(&mut calculate_length_element_tt(PAIRING_Z.lock().unwrap().to_vec().as_slice()));
    tt.append(&mut calculate_length_element_tt(PAIRING_V.lock().unwrap().to_vec().as_slice()));
    tt.append(&mut calculate_length_element_tt(W0.to_vec().as_slice()));
    tt
}

pub fn calculate_c_b() -> [u8; 16] {
    let tt = calculate_tt();
    let hash_tt = utils::calculate_sha256(&tt);
    let k_a = &hash_tt[0..16];
    let _k_b = &hash_tt[16..32];
    let derived_key = utils::calculate_derive_key(None, k_a, "ConfirmationKeys".as_bytes(), 32);
    let k_ca = &derived_key[0..16];
    let k_cb = &derived_key[16..32];
    let p_a = PAIRING_PA.lock().unwrap();
    let p_b = PAIRING_PB.lock().unwrap();
    let c_a = utils::calculate_cmac(k_ca, &p_b.to_vec()).unwrap();
    let c_b = utils::calculate_cmac(k_cb, &p_a.to_vec()).unwrap();
    let mut pairing_c_a = PAIRING_CA.lock().unwrap();
    *pairing_c_a = c_a.clone();
    c_b.try_into().unwrap()
}

pub fn calculate_c_a() -> [u8; 16] {
    [0x00; 16]
}

pub fn get_vehicle_certificate() -> Vec<u8> {
    let mut cert = Vec::new();
    if let Ok(mut file) = std::fs::File::open("/etc/certs/vehicle_public.crt") {
        let metadata = std::fs::metadata("/etc/certs/vehicle_public.crt").unwrap();
        cert = vec![0; metadata.len() as usize];
        file.read(&mut cert).unwrap();
    } else {
        cert = [0x01; 16].to_vec();
    }
    cert
}

pub fn get_mobile_device_server_ca_certificate() -> Vec<u8> {
    let mut cert = Vec::new();
    if let Ok(mut file) = std::fs::File::open("/etc/certs/mobile_server_ca.crt") {
        file.read(&mut cert).unwrap();
    } else {
        cert = [0x02; 16].to_vec();
    }
    cert
}

pub fn get_mobile_device_tee_ca_certificate() -> Vec<u8> {
    let mut cert = Vec::new();
    if let Ok(mut file) = std::fs::File::open("/etc/certs/mobile_tee_ca.crt") {
        file.read(&mut cert).unwrap();
    } else {
        cert = [0x03; 16].to_vec();
    }
    cert
}

pub fn get_carkey_certificate() -> Vec<u8> {
    [0x04; 16].to_vec()
}

pub fn create_iccoa_pairing_data_request_package() -> Result<Vec<u8>> {
    let transaction_id = 0x0000;
    let p_b = calculate_p_b();
    let p_b_payload = TLVPayloadBuilder::new().set_tag(0x51).set_value(&p_b.to_vec()).build();
    let mut pb = PAIRING_PB.lock().unwrap();
    *pb = p_b;
    let salt_payload = TLVPayloadBuilder::new().set_tag(0xC0).set_value(SALT.as_bytes()).build();
    let nscrypt_payload = TLVPayloadBuilder::new().set_tag(0xC1).set_value(&SCRYPT_N.to_le_bytes()).build();
    let r_payload = TLVPayloadBuilder::new().set_tag(0xC2).set_value(&SCRYPT_R.to_le_bytes()).build();
    let p_payload = TLVPayloadBuilder::new().set_tag(0xC3).set_value(&SCRYPT_P.to_le_bytes()).build();
    let iccoa = create_iccoa_pairing_data_request(
        transaction_id,
        &[p_b_payload, salt_payload, nscrypt_payload, r_payload, p_payload])?;
    Ok(iccoa.serialize())
}

fn create_iccoa_pairing_request(transaction_id: u16, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += p.get_total_length();
        payload_data.append(&mut p.serialize());
    });

    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+payload_length as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

fn create_iccoa_pairing_response(transaction_id: u16, status: Status, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += p.get_total_length();
        payload_data.append(&mut p.serialize());
    });

    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+payload_length as u16,
        Mark {
            encrypt_type: super::objects::EncryptType::ENCRYPT_BEFORE_AUTH,
            more_fragment: false,
            fragment_offset: 0x0000,
        }
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::VEHICLE_PAIRING,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

pub fn create_iccoa_pairing_data_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x02, payloads)
}

pub fn create_iccoa_pairing_data_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x02, payloads)
}

pub fn create_iccoa_paring_auth_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x03, payloads)
}

pub fn create_iccoa_pairing_auth_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x03, payloads)
}

pub fn create_iccoa_pairing_certificate_write_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x04, payloads)
}

pub fn create_iccoa_pairing_certificate_write_response(transaction_id: u16, status: Status) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x04, &[])
}

pub fn create_iccoa_pairing_certificate_read_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_request(transaction_id, 0x05, payloads)
}

pub fn create_iccoa_pairing_certificate_read_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    return create_iccoa_pairing_response(transaction_id, status, 0x05, payloads)
}


pub fn handle_iccoa_pairing_p_a_payload(iccoa: &ICCOA) -> Result<()> {
    //handle pA
    let payload = iccoa.get_body().get_message_data().get_value();
    let p_a_tlv_payload = TLVPayload::deserialize(payload)?;
    if p_a_tlv_payload.get_tag() != 0x52 {
        return Err(ErrorKind::ICCOAPairingError("handle pairing pA payload error".to_string()).into());
    }
    let mut pairing_p_a = PAIRING_PA.lock().unwrap();
    *pairing_p_a = BigNum::from_slice(&p_a_tlv_payload.value).unwrap();
    Ok(())
}

pub fn handle_iccoa_pairing_c_a_payload(iccoa: &ICCOA) -> Result<()> {
    let payload = iccoa.get_body().get_message_data().get_value();
    let c_a_tlv_payload = TLVPayload::deserialize(payload)?;
    if c_a_tlv_payload.get_tag() != 0x53 {
        return Err(ErrorKind::ICCOAPairingError("handle pairing cA payload error".to_string()).into());
    }
    let mobile_c_a = c_a_tlv_payload.value.as_slice();
    if PAIRING_CA.lock().unwrap().eq(mobile_c_a) {
        println!("C_A OK!!!!!!");
    } else {
        println!("C_A Failed!!!!!!");
        return Err(ErrorKind::ICCOAPairingError("cA calculate error".to_string()).into());
    }

    let tt = calculate_tt();
    let hash_tt = utils::calculate_sha256(&tt);
    let _k_a = &hash_tt[0..16];
    let k_b = &hash_tt[16..32];
    let derived_key = utils::calculate_derive_key(None, k_b, "ConfirmationKeys".as_bytes(), 32);
    let k_enc= &derived_key[0..16];
    let k_mac= &derived_key[16..32];
    set_pairing_key_enc(k_enc);
    set_pairing_key_mac(k_mac);
    Ok(())
}

pub fn handle_iccoa_pairing_read_response_payload(iccoa: &ICCOA) -> Result<()> {
    //handle read response payload
    let message_data = iccoa.get_body().get_message_data();
    if message_data.get_status().get_tag() == StatusTag::SUCCESS {
        let cert_payload = TLVPayload::deserialize(&message_data.get_value()).unwrap();
        let dec_key = PAIRING_KEY.lock().unwrap().get_key_enc();
        let iv = utils::get_default_iv();
        let plain_text = utils::decrypt_aes_128_cbc(&dec_key, &cert_payload.value, &iv)?;
        match cert_payload.get_tag() {
            0x01 => {
                let mut file = std::fs::File::create("/etc/certs/mobile_server_ca.crt")
                    .map_err(|_| ErrorKind::ICCOAPairingError("create mobile server ca cert file error".to_string()))
                    .unwrap();
                file.write_all(&plain_text)
                    .map_err(|_| ErrorKind::ICCOAPairingError("write cert data to mobile server ca cert file error".to_string()))
                    .unwrap();
            },
            0x02 => {
                let mut file = std::fs::File::create("/etc/certs/mobile_tee_ca.crt")
                    .map_err(|_| ErrorKind::ICCOAPairingError("create mobile tee ca cert file error".to_string()))
                    .unwrap();
                file.write_all(&plain_text)
                    .map_err(|_| ErrorKind::ICCOAPairingError("write cert data to moile tee ca cert file error".to_string()))
                    .unwrap();
            },
            0x03 => {
                let mut file = std::fs::File::create("/etc/certs/carkey_public.crt")
                    .map_err(|_| ErrorKind::ICCOAPairingError("create carkey public cert file error".to_string()))
                    .unwrap();
                file.write_all(&plain_text)
                    .map_err(|_| ErrorKind::ICCOAPairingError("write cert data to carkey public cert file error".to_string()))
                    .unwrap();
            },
            _ => {},
        }
        Ok(())
    } else {
        return Err(ErrorKind::ICCOAPairingError("pairing read response error".to_string()).into());
    }
}

pub fn handle_iccoa_pairing_response_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    let transaction_id = 0x00000;
    let message_data = &iccoa.body.message_data;
    match message_data.get_tag() {
        0x01 => {
            return Err(ErrorKind::ICCOAPairingError("getting paired password is not implemented".to_string()).into());
        },
        0x02 => {   //get pA
            //handle pA
            handle_iccoa_pairing_p_a_payload(iccoa)?;
            verify_p_a();
            //create spake2+ auth request cB
            let c_b = calculate_c_b();
            let c_b_payload = TLVPayloadBuilder::new().set_tag(0x53).set_value(&c_b).build();
            let response = create_iccoa_paring_auth_request(transaction_id, &[c_b_payload])?;
            return Ok(response)
        },
        0x03 => {   //get cA
            //handle cA
            handle_iccoa_pairing_c_a_payload(iccoa)?;
            //create spake2+ pairing certificate write request
            let vehicle_pubkey_cert = get_vehicle_certificate();
            let enc_key = PAIRING_KEY.lock().unwrap().get_key_enc();
            let iv = utils::get_default_iv();
            let cipher_text= utils::encrypt_aes_128_cbc(&enc_key, &vehicle_pubkey_cert, &iv)?;
            let vehicle_pubkey_cert_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&cipher_text).build();
            let response = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_pubkey_cert_payload])?;
            Ok(response)
        },
        0x04 => {   //get write command status
            //handle write command status
            //create spake2+ pairing certificate read request
            let device_ca_cert_payload = TLVPayloadBuilder::new().set_tag(0x01).build();
            let response = create_iccoa_pairing_certificate_read_request(transaction_id, &[device_ca_cert_payload])?;
            Ok(response)
        },
        0x05 => {   //get read command data(TLV)
            //handle read command data
            handle_iccoa_pairing_read_response_payload(iccoa)?;
            //create spake2+ pairing certificate read request
            let payload = TLVPayload::deserialize(message_data.get_value())?;
            let response = match payload.get_tag() {
                0x01 => {
                    let mobile_tee_cert_payload = TLVPayloadBuilder::new().set_tag(0x02).build();
                    create_iccoa_pairing_certificate_read_request(transaction_id, &[mobile_tee_cert_payload])?
                },
                0x02 => {
                    let carkey_pubkey_cert_payload= TLVPayloadBuilder::new().set_tag(0x03).build();
                    create_iccoa_pairing_certificate_read_request(transaction_id, &[carkey_pubkey_cert_payload])?
                },
                _ => {
                    //test create standard auth request
                    auth::create_iccoa_standard_auth_pubkey_exchange_request_package()?
                    //return Err(ErrorKind::ICCOAPairingError("Pairing Completed".to_string()).into());
                }
            };
            Ok(response)
        },
        0x07 => {
            return Err(ErrorKind::ICCOAPairingError("Tag 0x07 is not implemented".to_string()).into());
        },
        0xC0 => {
            return Err(ErrorKind::ICCOAPairingError("Tag 0xC0 is not implemented".to_string()).into());
        },
        _ => {      //RFU
            return Err(ErrorKind::ICCOAPairingError("RFU is not implemented".to_string()).into());
        },
    }
}


#[cfg(test)]
mod tests {
    use crate::iccoa::{objects::{Header, Body, MessageData}, TLVPayloadBuilder};

    use super::*;

    #[test]
    fn test_little_size_pairing_payload() {
        let transaction_id = 0x0004;
        let vehicle_certificate = [0x01; 16];
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap();
        println!("seialized iccoa = {:02X?}", iccoa.serialize());
        let deserialized_iccoa = ICCOA::deserialize(&iccoa.serialize()).unwrap();
        assert_eq!(iccoa, deserialized_iccoa);
    }
    #[test]
    fn test_middle_size_pairing_payload() {
        let transaction_id = 0x0004;
        let vehicle_certificate = [0x01; 250];
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap();
        println!("seialized iccoa = {:02X?}", iccoa.serialize());
        let deserialized_iccoa = ICCOA::deserialize(&iccoa.serialize()).unwrap();
        assert_eq!(iccoa, deserialized_iccoa);
    }
    #[test]
    fn test_large_size_pairing_payload() {
        let transaction_id = 0x0004;
        let vehicle_certificate = [0x01; 1024];
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap();
        println!("seialized iccoa = {:02X?}", iccoa.serialize());
        let deserialized_iccoa = ICCOA::deserialize(&iccoa.serialize()).unwrap();
        assert_eq!(iccoa, deserialized_iccoa);
    }
    #[test]
    fn test_spake2_plus_data_request() {
        let transaction_id = 0x0001;
        let p_b = calculate_p_b();
        let p_b_payload = TLVPayloadBuilder::new().set_tag(0x51).set_value(&p_b.to_vec()).build();
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let salt_payload = TLVPayloadBuilder::new().set_tag(0xC0).set_value(&salt).build();
        let nscrypt = [0x01, 0x02, 0x03, 0x04];
        let nscrypt_payload = TLVPayloadBuilder::new().set_tag(0xC1).set_value(&nscrypt).build();
        let r = [0x01, 0x02];
        let r_payload = TLVPayloadBuilder::new().set_tag(0xC2).set_value(&r).build();
        let p = [0x02, 0x01];
        let p_payload = TLVPayloadBuilder::new().set_tag(0xC3).set_value(&p).build();
        let iccoa = create_iccoa_pairing_data_request(transaction_id, &[p_b_payload, salt_payload, nscrypt_payload, r_payload, p_payload]).unwrap();
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
        let status = StatusBuilder::new().success().build();
        let p_a = calculate_p_a();
        let p_a_payload = TLVPayloadBuilder::new().set_tag(0x52).set_value(&p_a).build();
        let iccoa = create_iccoa_pairing_data_response(transaction_id, status, &[p_a_payload]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0002,
                pdu_length: 12+73+8,
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
                    status: StatusBuilder::new().success().build(),
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
        calculate_p_a();
        let c_b = calculate_c_b();
        let c_b_payload = TLVPayloadBuilder::new().set_tag(0x53).set_value(&c_b).build();
        let iccoa = create_iccoa_paring_auth_request(transaction_id, &[c_b_payload]).unwrap();
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
                    value: vec![
                        0x53, 0x10,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ],
                    ..Default::default()
                }

            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_auth_response() {
        let transaction_id= 0x0003;
        let status = StatusBuilder::new().success().build();
        let c_a = calculate_c_a();
        let c_a_payload = TLVPayloadBuilder::new().set_tag(0x54).set_value(&c_a).build();
        let iccoa = create_iccoa_pairing_auth_response(transaction_id, status, &[c_a_payload]).unwrap();
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
                    status: StatusBuilder::new().success().build(),
                    tag: 0x03,
                    value: vec![
                        0x54, 0x10,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ],
                },
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_spake2_plus_certificate_write_request() {
        let transaction_id = 0x0004;
        let vehicle_certificate = get_vehicle_certificate();
        let vehicle_certificate_payload = TLVPayloadBuilder::new().set_tag(0x55).set_value(&vehicle_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_write_request(transaction_id, &[vehicle_certificate_payload]).unwrap(); 
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0004,
                pdu_length: 12+1+21+8,
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
                    value: vec![
                        0x55, 0x10,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        })       
    }
    #[test]
    fn test_spake2_plus_certificate_write_response() {
        let transaction_id = 0x0004;
        let status = StatusBuilder::new().success().build();
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
                    status: StatusBuilder::new().success().build(),
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
        let cert_type_payload1 = TLVPayloadBuilder::new().set_tag(0x01).build();
        let cert_type_payload2 = TLVPayloadBuilder::new().set_tag(0x02).build();
        let cert_type_payload3 = TLVPayloadBuilder::new().set_tag(0x03).build();
        let iccoa = create_iccoa_pairing_certificate_read_request(transaction_id, &[cert_type_payload1, cert_type_payload2, cert_type_payload3]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REQUEST_PACKET,
                dest_transaction_id: 0x0005,
                pdu_length: 12+1+3+6+8,
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
                    value: vec![
                        0x01, 0x00,
                        0x02, 0x00,
                        0x03, 0x00
                    ],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_spake2_plus_certificate_read_response() {
        let transaction_id = 0x0005;
        let status = StatusBuilder::new().success().build();
        let mobile_device_certificate = get_mobile_device_server_ca_certificate();
        let mobile_tee_certificate = get_mobile_device_tee_ca_certificate();
        let carkey_certificate = get_carkey_certificate();
        let payload1 = TLVPayloadBuilder::new().set_tag(0x01).set_value(&mobile_device_certificate).build();
        let payload2 = TLVPayloadBuilder::new().set_tag(0x02).set_value(&mobile_tee_certificate).build();
        let payload3 = TLVPayloadBuilder::new().set_tag(0x03).set_value(&carkey_certificate).build();
        let iccoa = create_iccoa_pairing_certificate_read_response(transaction_id, status, &[payload1, payload2, payload3]).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                packet_type: crate::iccoa::objects::PacketType::REPLY_PACKET,
                source_transaction_id: 0x0005,
                pdu_length: 12+1+2+3+18*3+8,
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
                    status: StatusBuilder::new().success().build(),
                    tag: 0x05,
                    value: vec![
                        0x01, 0x10,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x02, 0x10,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                        0x03, 0x10,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
                    ],
                },
            },
            mac: [0x00; 8],
        })
    }
}