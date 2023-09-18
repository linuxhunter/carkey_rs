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
const W0: &str = "1DDA099A5FB7464CD1FFD2E91C006F558BE0E1A2AB6FC79BB44004C2B407361C";
const L: &str = "1F2131221F850910EA2EBD8E744F3B1320B423310B49CAADE1A9338D829D29D963D910E6C41F6AEFA5EDCDEA7E12D52AEA2581D07D34C861C0776CE111DBE000";
const M: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
const SCRYPT_N: u32 = 32768;
const SCRYPT_R: u16 = 1;
const SCRYPT_P: u16 = 8;

lazy_static! {
    static ref PAIRING_KEY: Mutex<CipherKey> = Mutex::new(CipherKey::new());
    static ref SPAKE2_PLUS_OBJECT: Mutex<Spake2Plus> = Mutex::new(Spake2Plus::new(W0, L, M, N));
}

#[derive(Debug, PartialEq)]
pub struct Spake2Plus {
    w0: BigNum,
    l: BigNum,
    m: BigNum,
    n: BigNum,
    p: BigNum,
    h: u32,
    random_y: u32,
    pa: BigNum,
    pb: BigNum,
    z: BigNum,
    v: BigNum,
    ca: Vec<u8>,
    cb: Vec<u8>,
}

impl Spake2Plus {
    pub fn new(w0: &str, l: &str, m: &str, n: &str) -> Self {
        Spake2Plus {
            w0: BigNum::from_hex_str(w0).unwrap(),
            l: BigNum::from_hex_str(l).unwrap(),
            m: BigNum::from_hex_str(m).unwrap(),
            n: BigNum::from_hex_str(n).unwrap(),
            p: BigNum::new().unwrap(),
            h: 0x01,
            random_y: rand::thread_rng().gen::<u32>(),
            pa: BigNum::new().unwrap(),
            pb: BigNum::new().unwrap(),
            z: BigNum::new().unwrap(),
            v: BigNum::new().unwrap(),
            ca: vec![],
            cb: vec![],
        }
    }
    pub fn calculate_pb(&mut self) -> Result<()> {
        let nid = Nid::X9_62_PRIME256V1;
        let group = EcGroup::from_curve_name(nid).map_err(|_| ErrorKind::ICCOAPairingError("create prime 256 v1 ec group error".to_string()))?;
        let mut ctx = BigNumContext::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num context error".to_string()))?;

        //calculate base point P
        let base_point = group.generator();
        let mut x = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("crate big number x error".to_string()))?;
        let mut y = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create big number y error".to_string()))?;
        base_point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx).map_err(|_| ErrorKind::ICCOAPairingError("get affine coorderinate prime on ec group error".to_string()))?;
        self.p = x;
 
        //calculate p_b
        let mut tmp_y = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num error".to_string()))?;
        tmp_y.checked_mul(&self.p, &BigNum::from_u32(self.random_y).unwrap(), &mut ctx).map_err(|_| ErrorKind::ICCOAPairingError("multipy big number y with P error".to_string()))?;

        let mut tmp_n = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num error".to_string()))?;
        tmp_n.checked_mul(&self.n, &self.w0, &mut ctx).map_err(|_| ErrorKind::ICCOAPairingError("multipy N with W0 error".to_string()))?;

        let mut p_b = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num error".to_string()))?;
        p_b.checked_add(&tmp_y, &tmp_n).map_err(|_| ErrorKind::ICCOAPairingError("add big number y*P and N*W0 error".to_string()))?;
        self.pb = p_b;
        Ok(())
    }
    pub fn set_pa(&mut self, pa: BigNum) {
        self.pa = pa;
    }
    pub fn calculate_z_v(&mut self) -> Result<()> {
        let mut ctx = BigNumContext::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num context error".to_string()))?;

        let mut tmp_m = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num error".to_string()))?;
        tmp_m.checked_mul(&self.w0, &self.m, &mut ctx).map_err(|_| ErrorKind::ICCOAPairingError("multipy big number W0 and M error".to_string()))?;

        let mut tmp_z = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num error".to_string()))?;
        tmp_z.checked_sub(&self.pa, &tmp_m).map_err(|_| ErrorKind::ICCOAPairingError("substract PA with W0*M error".to_string()))?;

        let mut ec_z = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num error".to_string()))?;
        ec_z.checked_mul(&BigNum::from_u32(self.h*self.random_y).unwrap(), &tmp_z, &mut ctx).map_err(|_| ErrorKind::ICCOAPairingError("multipy h*y with z error".to_string()))?;
        let mut ec_v = BigNum::new().map_err(|_| ErrorKind::ICCOAPairingError("create openssl big num error".to_string()))?;
        ec_v.checked_mul(&self.l, &BigNum::from_u32(self.h*self.random_y).unwrap(), &mut ctx).map_err(|_| ErrorKind::ICCOAPairingError("multipy L with h*y error".to_string()))?;

        self.z = ec_z;
        self.v = ec_v;
        Ok(())
    }
    fn calculate_tt(&self) -> Result<Vec<u8>> {
        let calculate_length_element_tt = |elem: &[u8]| {
            let mut tt_elements = Vec::new();
            let length_u64 = elem.len() as u64;
            tt_elements.append(&mut length_u64.to_le_bytes().to_vec());
            tt_elements.append(&mut elem.to_vec());
            tt_elements
        };
        let mut tt = Vec::new();
        tt.append(&mut calculate_length_element_tt(self.m.to_vec().as_slice()));
        tt.append(&mut calculate_length_element_tt(self.n.to_vec().as_slice()));
        tt.append(&mut calculate_length_element_tt(self.pa.to_vec().as_slice()));
        tt.append(&mut calculate_length_element_tt(self.pb.to_vec().as_slice()));
        tt.append(&mut calculate_length_element_tt(self.z.to_vec().as_slice()));
        tt.append(&mut calculate_length_element_tt(self.v.to_vec().as_slice()));
        tt.append(&mut calculate_length_element_tt(self.w0.to_vec().as_slice()));
        Ok(tt)
    }
    pub fn calculate_ca_cb(&mut self) -> Result<()> {
        let tt = self.calculate_tt()?;
        let hash_tt = utils::calculate_sha256(&tt);
        let k_a = &hash_tt[0..16];
        let _k_b = &hash_tt[16..32];
        let derived_key = utils::calculate_derive_key(None, k_a, "ConfirmationKeys".as_bytes(), 32);
        let k_ca = &derived_key[0..16];
        let k_cb = &derived_key[16..32];
        let c_a = utils::calculate_cmac(k_ca, &self.pb.to_vec()).map_err(|_| ErrorKind::ICCOAPairingError("calculate cmac on PB with k_ca error".to_string()))?;
        let c_b = utils::calculate_cmac(k_cb, &self.pa.to_vec()).map_err(|_| ErrorKind::ICCOAPairingError("calculate cmakc on PA with k_cb error".to_string()))?;
        self.ca = c_a;
        self.cb = c_b;
        Ok(())
    }
}

pub fn set_pairing_key_mac(key: &[u8]) {
    let mut pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.set_key_mac(key);
}

pub fn set_pairing_key_enc(key: &[u8]) {
    let mut pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.set_key_enc(key);
}

pub fn get_pairing_key_mac() -> Vec<u8> {
    let pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.get_key_mac()
}

pub fn get_pairing_key_enc() -> Vec<u8> {
    let pairing_key = PAIRING_KEY.lock().unwrap();
    pairing_key.get_key_enc()
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
    let mut spake2_plus_object = SPAKE2_PLUS_OBJECT.lock().unwrap();
    spake2_plus_object.calculate_pb()?;
    let p_b_payload = TLVPayloadBuilder::new().set_tag(0x51).set_value(&spake2_plus_object.pb.to_vec()).build();
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


pub fn handle_iccoa_pairing_p_a_payload(iccoa: &ICCOA, spake2_plus_object: &mut Spake2Plus) -> Result<()> {
    //handle pA
    let payload = iccoa.get_body().get_message_data().get_value();
    let p_a_tlv_payload = TLVPayload::deserialize(payload)?;
    if p_a_tlv_payload.get_tag() != 0x52 {
        return Err(ErrorKind::ICCOAPairingError("handle pairing pA payload error".to_string()).into());
    }

    spake2_plus_object.set_pa(BigNum::from_slice(&p_a_tlv_payload.value).map_err(|_| ErrorKind::ICCOAPairingError("create Big Number from mobild PA TLV payload error".to_string()))?);
    spake2_plus_object.calculate_z_v()
}

pub fn handle_iccoa_pairing_c_a_payload(iccoa: &ICCOA, spake2_plus_object: &Spake2Plus) -> Result<()> {
    let payload = iccoa.get_body().get_message_data().get_value();
    let c_a_tlv_payload = TLVPayload::deserialize(payload)?;
    if c_a_tlv_payload.get_tag() != 0x53 {
        return Err(ErrorKind::ICCOAPairingError("handle pairing cA payload error".to_string()).into());
    }
    let mobile_c_a = c_a_tlv_payload.value.as_slice();
    if spake2_plus_object.ca.eq(mobile_c_a) {
        println!("C_A OK!!!!!!");
    } else {
        println!("C_A Failed!!!!!!");
        return Err(ErrorKind::ICCOAPairingError("cA calculate error".to_string()).into());
    }

    let tt = spake2_plus_object.calculate_tt()?;
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
    let mut spake2_plus_object = SPAKE2_PLUS_OBJECT.lock().unwrap();
    match message_data.get_tag() {
        0x01 => {
            return Err(ErrorKind::ICCOAPairingError("getting paired password is not implemented".to_string()).into());
        },
        0x02 => {   //get pA
            //handle pA
            handle_iccoa_pairing_p_a_payload(iccoa, &mut spake2_plus_object)?;
            //create spake2+ auth request cB
            spake2_plus_object.calculate_ca_cb()?;
            let c_b_payload = TLVPayloadBuilder::new().set_tag(0x53).set_value(&spake2_plus_object.cb).build();
            let response = create_iccoa_paring_auth_request(transaction_id, &[c_b_payload])?;
            return Ok(response)
        },
        0x03 => {   //get cA
            //handle cA
            handle_iccoa_pairing_c_a_payload(iccoa, &spake2_plus_object)?;
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
        let mut spake2_plus_object = SPAKE2_PLUS_OBJECT.lock().unwrap();
        spake2_plus_object.calculate_pb().unwrap();
        let p_b_payload = TLVPayloadBuilder::new().set_tag(0x51).set_value(&spake2_plus_object.pb.to_vec()).build();
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
                pdu_length: 12+1+101+8,
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
                    value: iccoa.get_body().message_data.get_value().to_vec(),
                    ..Default::default()
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_spake2_plus_data_response() {
        let transaction_id = 0x0002;
        let status = StatusBuilder::new().success().build();
        let p_a = [0x00; 65];
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
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_spake2_plus_auth_request() {
        let transaction_id = 0x0002;
        let mut spake2_plus_object = SPAKE2_PLUS_OBJECT.lock().unwrap();
        spake2_plus_object.set_pa(BigNum::from_slice(&[0x00; 65]).unwrap());
        spake2_plus_object.calculate_ca_cb().unwrap();
        let c_b_payload = TLVPayloadBuilder::new().set_tag(0x53).set_value(&spake2_plus_object.cb).build();
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
                    value: iccoa.get_body().get_message_data().get_value().to_vec(),
                    ..Default::default()
                }

            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        });
    }
    #[test]
    fn test_spake2_plus_auth_response() {
        let transaction_id= 0x0003;
        let status = StatusBuilder::new().success().build();
        let spake2_plus_object = SPAKE2_PLUS_OBJECT.lock().unwrap();
        let c_a_payload = TLVPayloadBuilder::new().set_tag(0x54).set_value(&spake2_plus_object.ca).build();
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
                        176, 48, 166, 194, 104, 114, 227, 104, 41, 107, 52, 134, 118, 72, 14, 16
                    ],
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
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
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
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
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
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
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
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
                pdu_length: 12+1+2+3+22+8,
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
                        0x01, 0x00,
                        0x02, 0x00,
                        0x03, 0x10,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
                    ],
                },
            },
            mac: iccoa.get_mac().to_vec().try_into().unwrap(),
        })
    }
}