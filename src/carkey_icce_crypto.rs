use libaes::{AES_128_KEY_LEN, Cipher};

type Result<T> = std::result::Result<T, String>;

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

pub fn calculate_sesion_key(dkey: &[u8], card_iv: &[u8], session_iv: &[u8], reader_key_parameter: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.append(&mut session_iv.clone().to_vec());
    payload.append(&mut reader_key_parameter.clone().to_vec());
    let key = dkey[0..AES_128_KEY_LEN].try_into().map_err(|e| "Invalid dkey".to_string())?;
    let cipher = Cipher::new_128(key);
    let session_key = cipher.cbc_encrypt(card_iv, &payload);
    if session_key.len() > 16 {
        Ok(session_key[session_key.len() - 16..].to_vec())
    } else {
        Ok(session_key)
    }
}

pub fn encrypt_with_session_key(session_key: &[u8], session_iv: &[u8], plain_text: &[u8]) -> Result<Vec<u8>> {
    let key = session_key[0..AES_128_KEY_LEN].try_into().map_err(|e| "Invalid session key".to_string())?;
    let cipher = Cipher::new_128(key);
    Ok(cipher.cbc_encrypt(session_iv, plain_text))
}

pub fn decrypt_with_session_key(session_key: &[u8], session_iv: &[u8], encrypted_text: &[u8]) -> Result<Vec<u8>> {
    let key = session_key[0..AES_128_KEY_LEN].try_into().map_err(|e| "Invalid session key".to_string())?;
    let cipher = Cipher::new_128(key);
    Ok(cipher.cbc_decrypt(session_iv, encrypted_text))
}
