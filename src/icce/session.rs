use std::sync::Mutex;
use openssl::symm::{Cipher, decrypt, encrypt};
use crate::icce::errors::ErrorKind;

lazy_static! {
    static ref SESSION_KEY: Mutex<[u8; 16]> = Mutex::new([0; 16]);
    static ref SESSION_IV: Mutex<[u8; 16]> = Mutex::new([0; 16]);
}

pub fn is_session_key_valid() -> bool {
    let session_key = SESSION_KEY.lock().unwrap().to_vec();
    session_key.ne(&[0u8; 16])
}

pub fn update_session_key(key: &[u8]) {
    let mut session_key = SESSION_KEY.lock().unwrap();
    session_key.copy_from_slice(key);
}

pub fn update_session_iv(iv: &[u8]) {
    let mut session_iv = SESSION_IV.lock().unwrap();
    session_iv.copy_from_slice(iv);
}

pub fn get_session_key() -> Vec<u8> {
    SESSION_KEY.lock().unwrap().to_vec()
}

pub fn get_session_iv() -> Vec<u8> {
    SESSION_IV.lock().unwrap().to_vec()
}

//calculate Sessin IV with ReaderRnd || CardRnd
pub fn calculate_session_iv(reader_rnd: &[u8], card_rnd: &[u8]) -> Vec<u8> {
    let mut session_iv = Vec::with_capacity(16);
    session_iv.append(&mut reader_rnd.to_vec());
    session_iv.append(&mut card_rnd.to_vec());
    if session_iv.len() > 16 {
        session_iv[session_iv.len() - 16..].to_vec()
    } else {
        session_iv
    }
}

//calculate Session Key with DKey and CardIV and it's payload of Session IV || ReaderKeyParameter
pub fn calculate_session_key(dkey: &[u8], card_iv: &[u8], session_iv: &[u8], reader_key_parameter: &[u8]) -> crate::icce::errors::Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.append(&mut session_iv.to_vec());
    payload.append(&mut reader_key_parameter.to_vec());

    let session_key = encrypt_with_session_key(dkey, card_iv, &payload)?;
    if session_key.len() > 16 {
        Ok(session_key[0..16].to_vec())
    } else {
        Ok(session_key)
    }
}

//decrypt encrypted text with Session Key and Session IV
pub fn decrypt_with_session_key(session_key: &[u8], session_iv: &[u8], encrypted_text: &[u8]) -> crate::icce::errors::Result<Vec<u8>> {
    let cipher = Cipher::aes_128_cbc();
    let plain_text = decrypt(cipher, session_key, Some(session_iv), encrypted_text)
        .map_err(|e| ErrorKind::EncryptDecryptError(format!("decrypt error: {:?}", e)))?;
    Ok(plain_text)
}

//encrypt plain text with Session Key and Session IV
pub fn encrypt_with_session_key(session_key: &[u8], session_iv: &[u8], plain_text: &[u8]) -> crate::icce::errors::Result<Vec<u8>> {
    let cipher = Cipher::aes_128_cbc();
    let encrypted_text = encrypt(cipher, session_key, Some(session_iv), plain_text)
        .map_err(|e| ErrorKind::EncryptDecryptError(format!("encrypt error: {:?}", e)))?;
    Ok(encrypted_text)
}
