use std::sync::Mutex;
use crate::iccoa::objects;

use crate::iccoa::utils::{KeyDeriveMaterial, CipherKey};

use super::objects::{ICCOA, Mark, create_iccoa_header, create_iccoa_body_message_data, create_iccoa_body, create_iccoa};
use super::utils::KeyMaterialOperation;
use super::{errors::*, TLVPayload, TLVPayloadBuilder};
use super::status::{StatusBuilder, Status};

lazy_static! {
    static ref AUTH_SIGN_OBJECT: Mutex<KeyDeriveMaterial> = Mutex::new(KeyDeriveMaterial::new());
    static ref AUTH_KEY_PERSISTENT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static ref AUTH_KEY: Mutex<CipherKey> = Mutex::new(CipherKey::new());
}

pub fn get_auth_key_mac() -> Vec<u8> {
    let auth_key = AUTH_KEY.lock().unwrap();
    auth_key.get_key_mac()
}

pub fn get_auth_key_enc() -> Vec<u8> {
    let auth_key = AUTH_KEY.lock().unwrap();
    auth_key.get_key_enc()
}

fn create_iccoa_auth_request(transaction_id: u16, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += p.get_total_length();
        payload_data.append(&mut p.serialize());
    });

    let mut mark = Mark::new();
    mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
    mark.set_more_fragment(false);
    mark.set_fragment_offset(0x0000);
    let header = create_iccoa_header(
        super::objects::PacketType::REQUEST_PACKET,
        transaction_id,
        1+3+payload_length as u16,
        mark
    );

    let message_data = create_iccoa_body_message_data(
        false,
        StatusBuilder::new().success().build(),
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}

fn create_iccoa_auth_response(transaction_id: u16, status: Status, tag: u8, payloads: &[TLVPayload]) -> Result<ICCOA> {
    let mut payload_data= Vec::new();
    let mut payload_length = 0x00;
    payloads.iter().for_each(|p| {
        payload_length += p.get_total_length();
        payload_data.append(&mut p.serialize());
    });

    let mut mark = Mark::new();
    mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
    mark.set_more_fragment(false);
    mark.set_fragment_offset(0x0000);
    let header = create_iccoa_header(
        super::objects::PacketType::REPLY_PACKET,
        transaction_id,
        1+2+3+payload_length as u16,
        mark
    );

    let message_data = create_iccoa_body_message_data(
        true,
        status,
        tag,
        &payload_data,
    );
    let body = create_iccoa_body(
        super::objects::MessageType::AUTH,
        message_data,
    );

    Ok(create_iccoa(header, body))
}


pub fn create_iccoa_standard_auth_pubkey_exchange_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_request(transaction_id, 0x01, payloads)
}

pub fn create_iccoa_standard_auth_pubkey_exchange_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_response(transaction_id, status, 0x01, payloads)
}

pub fn create_iccoa_standard_auth_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_request(transaction_id, 0x02, payloads)
}

pub fn create_iccoa_standard_auth_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_response(transaction_id, status, 0x02, payloads)
}

pub fn create_iccoa_standard_auth_friend_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_request(transaction_id, 0x03, payloads)
}

pub fn create_iccoa_standard_auth_friend_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_response(transaction_id, status, 0x03, payloads)
}

pub fn create_iccoa_standard_auth_write_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_request(transaction_id, 0x04, payloads)
}

pub fn create_iccoa_standard_auth_write_response(transaction_id: u16, status: Status) -> Result<ICCOA> {
    create_iccoa_auth_response(transaction_id, status, 0x04, &[])
}

pub fn create_iccoa_standard_auth_read_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_request(transaction_id, 0x05, payloads)
}

pub fn create_iccoa_standard_auth_read_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_response(transaction_id, status, 0x05, payloads)
}

pub fn create_iccoa_fast_auth_pubkey_exchange_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_request(transaction_id, 0xC1, payloads)
}

pub fn create_iccoa_fast_auth_pubkey_exchange_response(transaction_id: u16, status: Status, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_response(transaction_id, status, 0xC1, payloads)
}

pub fn create_iccoa_fast_auth_request(transaction_id: u16, payloads: &[TLVPayload]) -> Result<ICCOA> {
    create_iccoa_auth_request(transaction_id, 0xC2, payloads)
}

pub fn create_iccoa_fast_auth_response(transaction_id: u16, status: Status) -> Result<ICCOA> {
    create_iccoa_auth_response(transaction_id, status, 0xC2, &[])
}

pub fn create_iccoa_standard_auth_pubkey_exchange_request_package() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let mut auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    auth_sign_object.create_vehicle_temp_keypair("ec")?;
    let vehicle_temp_pubkey = auth_sign_object.get_vehicle_temp_public_key_pem()?;
    let vehicle_id = auth_sign_object.get_vehicle_id()?;
    let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
    let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
    let iccoa = create_iccoa_standard_auth_pubkey_exchange_request(
        transaction_id,
        &[vehicle_temp_pubkey_payload, vehicle_id_payload])?;
    Ok(iccoa)
}

pub fn create_iccoa_fast_auth_pubkey_exchange_request_package() -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let mut auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    auth_sign_object.create_vehicle_temp_keypair("ec")?;
    let vehicle_temp_pubkey = auth_sign_object.get_vehicle_temp_public_key_pem()?;
    let vehicle_id = auth_sign_object.get_vehicle_id()?;
    let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
    let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
    let iccoa = create_iccoa_fast_auth_pubkey_exchange_request(
        transaction_id,
        &[vehicle_temp_pubkey_payload, vehicle_id_payload])?;
    Ok(iccoa)
}

pub fn handle_iccoa_standard_auth_data_exchange_response_payload(iccoa: &ICCOA) -> Result<Vec<u8>> {
    //handle standard auth data exchange payload
    let message_data = iccoa.get_body().get_message_data();
    if message_data.get_status() != StatusBuilder::new().success().build() {
        return Err(ErrorKind::ICCOAAuthError("standard auth data exchnage response error".to_string()).into());
    }
    if message_data.get_tag() != 0x01 {
        return Err(ErrorKind::ICCOAAuthError("standard auth data exchange response tag error".to_string()).into());
    }
    let total_payload = message_data.get_value();
    let total_length = total_payload.len();
    let mut index = 0x00;
    let mut carkey_temp_pubkey = Vec::new();
    let mut carkey_id = Vec::new();
    while index < total_length {
        let payload = TLVPayload::deserialize(&total_payload[index..]).unwrap();
        if payload.get_tag() == 0x84 {
            carkey_temp_pubkey.append(&mut payload.value.to_vec());
        } else if payload.get_tag() == 0x89 {
            carkey_id.append(&mut payload.value.to_vec());
        }
        index += payload.get_total_length();
    }
    let mut auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    auth_sign_object.set_mobile_temp_public_key_pem(&carkey_temp_pubkey)?;
    auth_sign_object.set_mobile_id(&carkey_id);
    auth_sign_object.signature()
}

pub fn handle_iccoa_standard_auth_response_payload(iccoa: &ICCOA) -> Result<()> {
    //handle standard auth response payload
    let message_data = iccoa.get_body().get_message_data();
    if message_data.get_status() != StatusBuilder::new().success().build() {
        return Err(ErrorKind::ICCOAAuthError("standard auth response error".to_string()).into());
    }
    if message_data.get_tag() != 0x02 {
        return Err(ErrorKind::ICCOAAuthError("standard auth response tag error".to_string()).into());
    }
    let total_payload = message_data.get_value();
    let total_length = total_payload.len();
    let mut index = 0x00;
    let mut mobile_auth_info = Vec::new();
    while index < total_length {
        let payload = TLVPayload::deserialize(&total_payload[index..]).unwrap();
        if payload.get_tag() == 0x87 {
            mobile_auth_info.append(&mut payload.value.to_vec());
        }
        index += payload.get_total_length();
    }
    let mut auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    match auth_sign_object.verify(&mobile_auth_info)  {
        Ok(result) => {
            if result {
                let cipher_key = auth_sign_object.derive_key(None, "ECDH".as_bytes(), 32)?;
                let mut auth_key = AUTH_KEY.lock().unwrap();
                auth_key.set_key_enc(&cipher_key[0..16]);
                auth_key.set_key_mac(&cipher_key[16..32]);
                let persistent = auth_sign_object.derive_key(None, "Persistent".as_bytes(), 32)?;
                let mut auth_key_persistent = AUTH_KEY_PERSISTENT.lock().unwrap();
                auth_key_persistent.append(&mut persistent.to_vec());
                println!("OK");
                Ok(())
            } else {
                println!("Failed");
                Err(ErrorKind::ICCOAAuthError("mobile auth info signature verify error".to_string()).into())
            }
        },
        Err(_) => {
            Err(ErrorKind::ICCOAAuthError("mobile auth info signature verify error".to_string()).into())
        }
    }
}

pub fn handle_iccoa_fast_auth_data_exchange_response_payload(iccoa: &ICCOA) -> Result<Vec<u8>> {
    let message_data = iccoa.get_body().get_message_data();
    if message_data.get_status() != StatusBuilder::new().success().build() {
        return Err(ErrorKind::ICCOAAuthError("standard auth data exchnage response error".to_string()).into());
    }
    if message_data.get_tag() != 0xC1 {
        return Err(ErrorKind::ICCOAAuthError("standard auth data exchange response tag error".to_string()).into());
    }
    let total_payload = message_data.get_value();
    let total_length = total_payload.len();
    let mut index = 0x00;
    let mut carkey_temp_pubkey = Vec::new();
    let mut carkey_id = Vec::new();
    let mut cryptogram = Vec::new();
    while index < total_length {
        let payload = TLVPayload::deserialize(&total_payload[index..]).unwrap();
        if payload.get_tag() == 0x84 {
            carkey_temp_pubkey.append(&mut payload.value.to_vec());
        } else if payload.get_tag() == 0x85 {
            cryptogram.append(&mut payload.value.to_vec());
        } else if payload.get_tag() == 0x89 {
            carkey_id.append(&mut payload.value.to_vec());
        }
        index += payload.get_total_length();
    }
    let mut auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    auth_sign_object.set_mobile_temp_public_key_pem(&carkey_temp_pubkey)?;
    auth_sign_object.set_mobile_id(&carkey_id);
    let key_persistent = AUTH_KEY_PERSISTENT.lock().unwrap();
    let fast_cipher_key = auth_sign_object.derive_key(Some(&key_persistent), "FastAuth".as_bytes(), 64)?;
    let mut auth_key = AUTH_KEY.lock().unwrap();
    auth_key.set_kv_mac(&fast_cipher_key[0..16]);
    auth_key.set_kd_mac(&fast_cipher_key[16..32]);
    auth_key.set_key_enc(&fast_cipher_key[32..48]);
    auth_key.set_key_mac(&fast_cipher_key[48..64]);
    let calculated_cmac = auth_sign_object.calculate_cryptogram(&auth_key.get_kd_mac(), "mobile")?;
    if calculated_cmac.eq(&cryptogram) {
        println!("-------------- Fast Auth OK-------------------");
        auth_sign_object.calculate_cryptogram(&auth_key.get_kv_mac(), "vehicle")
    } else {
        println!("-------------- Fast Auth Failed-------------------");
        Err(ErrorKind::ICCOAAuthError("fast auth verify cryptogram error".to_string()).into())
    }
}

pub fn handle_iccoa_fast_auth_response_payload(iccoa: &ICCOA) -> Result<()> {
    //handle fast auth response payload
    let message_data = iccoa.get_body().get_message_data();
    if message_data.get_status() != StatusBuilder::new().success().build() {
        return Err(ErrorKind::ICCOAAuthError("standard auth response error".to_string()).into());
    }
    if message_data.get_tag() != 0xC2 {
        return Err(ErrorKind::ICCOAAuthError("standard auth response tag error".to_string()).into());
    }
    let total_payload = message_data.get_value();
    let total_length = total_payload.len();
    let mut index = 0x00;
    let mut mobile_auth_info = Vec::new();
    while index < total_length {
        let payload = TLVPayload::deserialize(&total_payload[index..]).unwrap();
        if payload.get_tag() == 0x87 {
            mobile_auth_info.append(&mut payload.value.to_vec());
        }
        index += payload.get_total_length();
    }
    let auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    match auth_sign_object.verify(&mobile_auth_info)  {
        Ok(result) => {
            if result {
                println!("OK");
                Ok(())
            } else {
                println!("Failed");
                Err(ErrorKind::ICCOAAuthError("mobile auth info signature verify error".to_string()).into())
            }
        },
        Err(_) => {
            Err(ErrorKind::ICCOAAuthError("mobile auth info signature verify error".to_string()).into())
        }
    }
}

pub fn handle_iccoa_auth_response_from_mobile(iccoa: &ICCOA) -> Result<ICCOA> {
    let transaction_id = 0x0000;
    let message_data = iccoa.get_body().get_message_data();
    match message_data.get_tag() {
        0x01 => {
            //handle standard auth vehicle temp pubkey response
            let vehicle_signature = handle_iccoa_standard_auth_data_exchange_response_payload(iccoa)?;
            //create standard auth request
            let vehicle_signature_payload = TLVPayloadBuilder::new().set_tag(0x86).set_value(&vehicle_signature).build();
            let response = create_iccoa_standard_auth_request(transaction_id, &[vehicle_signature_payload])?;
            Ok(response)
        },
        0x02 => {
            //handle standard auth response
            handle_iccoa_standard_auth_response_payload(iccoa)?;
            Err(ErrorKind::ICCOAAuthError("standard auth completed".to_string()).into())
        },
        0xC1 => {
            //handle fast auth vehicle temp pubkey response
            let vehicle_fast_auth_data = handle_iccoa_fast_auth_data_exchange_response_payload(iccoa)?;
            //create fast auth request
            let vehicle_fast_auth_data_payload = TLVPayloadBuilder::new().set_tag(0x88).set_value(&vehicle_fast_auth_data).build();
            let response = create_iccoa_fast_auth_request(transaction_id, &[vehicle_fast_auth_data_payload]).unwrap();
            Ok(response)
        },
        0xC2 => {
            //handle fast auth response
            let _status = handle_iccoa_fast_auth_response_payload(iccoa);
            Err(ErrorKind::ICCOAAuthError("fast auth completed".to_string()).into())
        },
        _ => {
            Err(ErrorKind::ICCOAPairingError("RFU is not implemented".to_string()).into())
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::iccoa::{objects::{Header, Body, MessageData, PacketType, EncryptType, MessageType}, TLVPayloadBuilder};
    use super::*;

    #[test]
    fn test_standard_auth_data_exchange_request() {
        let transaction_id = 0x0001;
        let vehicle_temp_pubkey = [0x01; 65];
        let vehicle_id = [0x10; 16];
        let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
        let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
        let iccoa = create_iccoa_standard_auth_pubkey_exchange_request(transaction_id, &[vehicle_temp_pubkey_payload, vehicle_id_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0001,
            1+88,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x01,
            vec![
                0x81, 0x41,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01,
                0x83, 0x10,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_standard_auth_data_exchange_response() {
        let transaction_id = 0x0001;
        let status = StatusBuilder::new().success().build();
        let mobile_temp_pubkey = [0x02; 65];
        let mobile_id = [0x20; 16];
        let mobile_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x84).set_value(&mobile_temp_pubkey).build();
        let mobile_id_payload = TLVPayloadBuilder::new().set_tag(0x89).set_value(&mobile_id).build();
        let iccoa = create_iccoa_standard_auth_pubkey_exchange_response(transaction_id, status, &[mobile_temp_pubkey_payload, mobile_id_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0001,
            1+2+88,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0x01,
           vec![
                0x84, 0x41,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02,
                0x89, 0x10,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_standard_auth_request() {
        let transaction_id = 0x0002;
        let vehicle_signature = [0x03; 64];
        let vehicle_signature_payload = TLVPayloadBuilder::new().set_tag(0x86).set_value(&vehicle_signature).build();
        let iccoa = create_iccoa_standard_auth_request(transaction_id, &[vehicle_signature_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0002,
            1+69,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x02,
           vec![
                0x86, 0x40,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_standard_auth_response() {
        let transaction_id = 0x0002;
        let status = StatusBuilder::new().success().build();
        let mobile_signature = [0x30; 64];
        let mobile_signature_payload = TLVPayloadBuilder::new().set_tag(0x87).set_value(&mobile_signature).build();
        let iccoa = create_iccoa_standard_auth_response(transaction_id, status, &[mobile_signature_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0002,
            1+2+69,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0x02,
            vec![
                0x87, 0x40,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_friend_key_data_request() {
        let transaction_id = 0x0003;
        let friend_key_data = [0x04; 64];
        let friend_key_data_payload = TLVPayloadBuilder::new().set_tag(0x71).set_value(&friend_key_data).build();
        let iccoa = create_iccoa_standard_auth_friend_request(transaction_id, &[friend_key_data_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0003,
            1+3+2+friend_key_data.len() as u16,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x03,
            vec![
                0x71, 0x40,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_friend_key_data_response() {
        let transaction_id = 0x0003;
        let status = StatusBuilder::new().success().build();
        let friend_key_shared_info = [0x40; 64];
        let friend_key_shared_info_payload = TLVPayloadBuilder::new().set_tag(0x71).set_value(&friend_key_shared_info).build();
        let iccoa = create_iccoa_standard_auth_friend_response(transaction_id, status, &[friend_key_shared_info_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0003,
            1+2+3+2+friend_key_shared_info.len() as u16,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0x03,
           vec![
                0x71, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_write_request() {
        let transaction_id = 0x0004;
        let write_data = [0x05; 32];
        let write_data_payload = TLVPayloadBuilder::new().set_tag(0x72).set_value(&write_data).build();
        let iccoa = create_iccoa_standard_auth_write_request(transaction_id, &[write_data_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0004,
            1+3+2+write_data.len() as u16,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x04,
           vec![
                0x72, 0x20,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_write_response() {
        let transaction_id = 0x0004;
        let status = StatusBuilder::new().success().build();
        let iccoa = create_iccoa_standard_auth_write_response(transaction_id, status).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0004,
            1+2+3,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0x04,
            vec![].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_read_request() {
        let transaction_id = 0x0005;
        let read_list = vec![0x01, 0x02, 0x03];
        let payload1 = TLVPayloadBuilder::new().set_tag(0x01).build();
        let payload2 = TLVPayloadBuilder::new().set_tag(0x02).build();
        let payload3 = TLVPayloadBuilder::new().set_tag(0x03).build();
        let iccoa = create_iccoa_standard_auth_read_request(transaction_id, &[payload1, payload2, payload3]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0005,
            1+3+2*3,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0x05,
           vec![
                0x01, 0x00,
                0x02, 0x00,
                0x03, 0x00
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_read_response() {
        let transaction_id = 0x0005;
        let status = StatusBuilder::new().success().build();
        let data1 = [0x50; 16];
        let data2 = [0x60; 16];
        let data3 = [0x70; 16];
        let payload1 = TLVPayloadBuilder::new().set_tag(0x01).set_value(&data1).build();
        let payload2 = TLVPayloadBuilder::new().set_tag(0x02).set_value(&data2).build();
        let payload3 = TLVPayloadBuilder::new().set_tag(0x03).set_value(&data3).build();
        let iccoa = create_iccoa_standard_auth_read_response(transaction_id, status, &[payload1, payload2, payload3]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0005,
            1+2+3+18*3,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0x05,
           vec![
                0x01, 0x10,
                0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
                0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50,
                0x02, 0x10,
                0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
                0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
                0x03, 0x10,
                0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70,
                0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_fast_auth_data_exchange_request() {
        let transaction_id = 0x0006;
        let vehicle_temp_pubkey = [0x06; 65];
        let vehicle_id = [0x60; 16];
        let vehicle_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x81).set_value(&vehicle_temp_pubkey).build();
        let vehicle_id_payload = TLVPayloadBuilder::new().set_tag(0x83).set_value(&vehicle_id).build();
        let iccoa = create_iccoa_fast_auth_pubkey_exchange_request(transaction_id, &[vehicle_temp_pubkey_payload, vehicle_id_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0006,
            1+3+67+18,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0xC1,
           vec![
                0x81, 0x41,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06,
                0x83, 0x10,
                0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
                0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_fast_auth_data_exchange_response() {
        let transaction_id = 0x0006;
        let status = StatusBuilder::new().success().build();
        let mobile_temp_pubkey = [0x07; 65];
        let mobile_id = [0x70; 16];
        let mobile_temp_pubkey_payload = TLVPayloadBuilder::new().set_tag(0x84).set_value(&mobile_temp_pubkey).build();
        let mobile_id_payload = TLVPayloadBuilder::new().set_tag(0x89).set_value(&mobile_id).build();
        let iccoa = create_iccoa_fast_auth_pubkey_exchange_response(transaction_id, status, &[mobile_temp_pubkey_payload, mobile_id_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0006,
            1+2+3+67+18,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0xC1,
           vec![
                0x84, 0x41,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07,
                0x89, 0x10,
                0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70,
                0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_fast_auth_request() {
        let transaction_id = 0x0007;
        let vehicle_fast_auth_data = [0x08; 16];
        let vehicle_fast_auth_data_payload = TLVPayloadBuilder::new().set_tag(0x88).set_value(&vehicle_fast_auth_data).build();
        let iccoa = create_iccoa_fast_auth_request(transaction_id, &[vehicle_fast_auth_data_payload]).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0007,
            1+3+18,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            false,
            StatusBuilder::new().success().build(),
            0xC2,
            vec![
                0x88, 0x10,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08
            ].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
    #[test]
    fn test_fast_auth_response() {
        let transaction_id = 0x0007;
        let status = StatusBuilder::new().success().build();
        let iccoa = create_iccoa_fast_auth_response(transaction_id, status).unwrap();
        let mut mark = Mark::new();
        mark.set_encrypt_type(objects::EncryptType::ENCRYPT_BEFORE_AUTH);
        mark.set_more_fragment(false);
        mark.set_fragment_offset(0x0000);
        let header = objects::create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0007,
            1+2+3,
            mark
        );
        let message_data = objects::create_iccoa_body_message_data(
            true,
            StatusBuilder::new().success().build(),
            0xC2,
            vec![].as_slice()
        );
        let body = objects::create_iccoa_body(
            MessageType::AUTH,
            message_data
        );
        let standard_iccoa = objects::create_iccoa(header, body);
        assert_eq!(iccoa, standard_iccoa);
    }
}