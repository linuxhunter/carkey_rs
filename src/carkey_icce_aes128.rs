use aes::cipher::{KeyIvInit, BlockEncryptMut, block_padding::Pkcs7, BlockDecryptMut};

type Result<T> = std::result::Result<T, String>;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn get_card_seid() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

pub fn get_card_id() -> Vec<u8> {
    vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]
}

pub fn get_card_rnd() -> Vec<u8> {
    vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
}

pub fn get_card_info1() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
}

pub fn get_card_atc() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04]
}

pub fn get_card_auth_parameter() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

pub fn get_reader_type() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
}

pub fn get_reader_id() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xe, 0x0f, 0x00]
}

pub fn get_reader_rnd() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

pub fn get_reader_key_parameter() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

pub fn get_reader_auth_parameter() -> Vec<u8> {
    vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
}

pub fn calculate_dkey(_card_seid: &[u8], _card_id: &[u8]) -> Vec<u8> {
    //根据card_seid查找到相应的认证根密钥
    //用card_id分散因子计算认证密钥DKey
    vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
}

pub fn get_card_iv() -> Vec<u8> {
    vec![0x00; 16]
}

pub fn calculate_session_iv(reader_rnd: &[u8], card_rnd: &[u8]) -> Vec<u8> {
    let mut session_iv = Vec::with_capacity(16);
    session_iv.append(&mut reader_rnd.clone().to_vec());
    session_iv.append(&mut card_rnd.clone().to_vec());
    if session_iv.len() > 16 {
        session_iv[session_iv.len() - 16..].to_vec()
    } else {
        session_iv
    }
}

pub fn calculate_session_key(dkey: &[u8], card_iv: &[u8], session_iv: &[u8], reader_key_parameter: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.append(&mut session_iv.clone().to_vec());
    payload.append(&mut reader_key_parameter.clone().to_vec());

    let mut buf = [0u8; 48];
    let pt_len = payload.len();
    buf[..pt_len].copy_from_slice(&payload);

    let session_key = Aes128CbcEnc::new(dkey.into(), card_iv.into()).encrypt_padded_b2b_mut::<Pkcs7>(&payload, &mut buf).unwrap();
    if session_key.len() > 16 {
        Ok(session_key[session_key.len() - 16..].to_vec())
    } else {
        Ok(session_key.to_vec())
    }
}

pub fn encrypt_with_session_key(session_key: &[u8], session_iv: &[u8], plain_text: &[u8]) -> Result<Vec<u8>> {
    let mut buf = [0u8; 48];
    let pt_len = plain_text.len();
    buf[..pt_len].copy_from_slice(&plain_text);

    let encrypted_text = Aes128CbcEnc::new(session_key.into(), session_iv.into()).encrypt_padded_b2b_mut::<Pkcs7>(plain_text, &mut buf).unwrap();
    Ok(encrypted_text.to_vec())
}

pub fn decrypt_with_session_key(session_key: &[u8], session_iv: &[u8], encrypted_text: &[u8]) -> Result<Vec<u8>> {
    let cipher_len = encrypted_text.len();
    let mut buf = [0u8; 48];
    buf[..cipher_len].copy_from_slice(encrypted_text);

    let plain_text = Aes128CbcDec::new(session_key.into(), session_iv.into()).decrypt_padded_b2b_mut::<Pkcs7>(encrypted_text, &mut buf).unwrap();
    Ok(plain_text.to_vec())
}
