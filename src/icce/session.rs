use std::sync::Mutex;
use openssl::symm::{Cipher, decrypt, encrypt};
use crate::icce::errors::ErrorKind;

const SESSION_KEY_LENGTH: usize = 0x10;
const SESSION_IV_LENGTH: usize = 0x10;

lazy_static! {
    static ref SESSION: Mutex<Session> = Mutex::new(Session::default());
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
struct Session {
    key: Vec<u8>,
    iv: Vec<u8>,
}

#[allow(dead_code)]
impl Session {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        Session {
            key: key.to_vec(),
            iv: iv.to_vec(),
        }
    }
    pub fn set_key(&mut self, key: &[u8]) {
        self.key = key.to_vec();
    }
    pub fn get_key(&self) -> &[u8] {
        self.key.as_ref()
    }
    pub fn is_key_valid(&self) -> bool {
        self.key.ne(&vec![0x00])
    }
    pub fn set_iv(&mut self, iv: &[u8]) {
        self.iv = iv.to_vec();
    }
    pub fn get_iv(&self) -> &[u8] {
        self.iv.as_ref()
    }
}

pub fn is_session_key_valid() -> bool {
    let session = SESSION.lock().unwrap();
    session.is_key_valid()
}

pub fn remove_session_key() {
    let mut session = SESSION.lock().unwrap();
    session.set_key(&vec![0x00]);
}

#[allow(dead_code)]
pub fn get_session_key() -> Vec<u8> {
    let session = SESSION.lock().unwrap();
    return session.get_key().to_vec()
}

#[allow(dead_code)]
pub fn get_session_iv() -> Vec<u8> {
    let session = SESSION.lock().unwrap();
    return session.get_iv().to_vec()
}

//calculate Sessin IV with ReaderRnd || CardRnd
pub fn calculate_session_iv(reader_rnd: &[u8], card_rnd: &[u8]) {
    let mut session = SESSION.lock().unwrap();
    let mut session_iv = Vec::with_capacity(SESSION_IV_LENGTH);
    session_iv.append(&mut reader_rnd.to_vec());
    session_iv.append(&mut card_rnd.to_vec());
    let iv = if session_iv.len() > SESSION_IV_LENGTH {
        session_iv[session_iv.len() - SESSION_IV_LENGTH..].to_vec()
    } else {
        session_iv
    };
    session.set_iv(iv.as_ref());
}

//calculate Session Key with DKey and CardIV and it's payload of Session IV || ReaderKeyParameter
pub fn calculate_session_key(dkey: &[u8], card_iv: &[u8], reader_key_parameter: &[u8]) -> crate::icce::errors::Result<()> {
    let mut session = SESSION.lock().unwrap();
    let mut payload = Vec::new();
    payload.append(&mut session.get_iv().to_vec());
    payload.append(&mut reader_key_parameter.to_vec());

    let cipher = Cipher::aes_128_cbc();
    let session_key = encrypt(cipher, dkey, Some(card_iv), &payload)
        .map_err(|e| ErrorKind::EncryptDecryptError(format!("calculate session key: {:?}", e)))?;
    let key = if session_key.len() > SESSION_KEY_LENGTH {
        session_key[0..SESSION_KEY_LENGTH].to_vec()
    } else {
        session_key
    };
    session.set_key(key.as_ref());
    Ok(())
}

//decrypt encrypted text with Session Key and Session IV
pub fn decrypt_with_session_key(encrypted_text: &[u8]) -> crate::icce::errors::Result<Vec<u8>> {
    let session = SESSION.lock().unwrap();
    let cipher = Cipher::aes_128_cbc();
    let plain_text = decrypt(cipher, session.get_key(), Some(session.get_iv()), encrypted_text)
        .map_err(|e| ErrorKind::EncryptDecryptError(format!("decrypt error: {:?}", e)))?;
    Ok(plain_text)
}

//encrypt plain text with Session Key and Session IV
pub fn encrypt_with_session_key(plain_text: &[u8]) -> crate::icce::errors::Result<Vec<u8>> {
    let session = SESSION.lock().unwrap();
    let cipher = Cipher::aes_128_cbc();
    let encrypted_text = encrypt(cipher, session.get_key(), Some(session.get_iv()), plain_text)
        .map_err(|e| ErrorKind::EncryptDecryptError(format!("encrypt error: {:?}", e)))?;
    Ok(encrypted_text)
}
