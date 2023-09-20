use openssl::symm::{encrypt, decrypt, Cipher};

type Result<T> = std::result::Result<T, String>;

//CardSEID rule is 车钥匙应用卡片唯一标识，根据CardSEID查找到响应的认证根密钥，长度8字节
pub fn get_card_seid() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

//CardID rule is 车钥匙应用数字Key ID唯一标识，用CardID分散因子计算认证密钥DKey，长度16字节
pub fn get_card_id() -> Vec<u8> {
    vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]
}

//CardRnd rule is 车钥匙应用卡片随机数，长度8字节
pub fn get_card_rnd() -> Vec<u8> {
    vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
}

//CardInfo1 rule is 车钥匙应用自定义数据，车钥匙非敏感的明文数据
pub fn get_card_info1() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
}

//CardATC rule is 车钥匙应用卡片计数器，长度4字节
pub fn get_card_atc() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04]
}

//CardAuthParameter rule is 车钥匙自定义认证数据
pub fn get_card_auth_parameter() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

//ReaderType rule is VIN前2字节||1字节自定义||2字节车型代码||1字节自定义
pub fn get_reader_type() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
}

//ReaderID rule is 长度8-20字节
pub fn get_reader_id() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xe, 0x0f, 0x00]
}

//ReaderRnd rule is 车侧随机数，长度8字节
pub fn get_reader_rnd() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

//ReaderKeyParameter rule is 车侧会话密钥分散因子，参与进行会话密钥分散
pub fn get_reader_key_parameter() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

//ReaderAuthParameter rule is 车侧自定义认证数据，用于挑战车钥匙
pub fn get_reader_auth_parameter() -> Vec<u8> {
    vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
}

//DKey is calculated by CardSEID and CardID, which length is 16Bytes
pub fn calculate_dkey(_card_seid: &[u8], _card_id: &[u8]) -> Vec<u8> {
    //根据card_seid查找到相应的认证根密钥
    //用card_id分散因子计算认证密钥DKey
    vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
}

//CardIV is initialized vector, which length is 16Bytes. Default CardIV is all zero.
pub fn get_card_iv() -> Vec<u8> {
    vec![0x00; 16]
}

//calculate Sessin IV with ReaderRnd || CardRnd
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

//calculate Session Key with DKey and CardIV and it's payload of Session IV || ReaderKeyParameter
pub fn calculate_session_key(dkey: &[u8], card_iv: &[u8], session_iv: &[u8], reader_key_parameter: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.append(&mut session_iv.clone().to_vec());
    payload.append(&mut reader_key_parameter.clone().to_vec());

    let session_key = encrypt_with_session_key(dkey, card_iv, &payload)?;
    if session_key.len() > 16 {
        Ok(session_key[0..16].to_vec())
    } else {
        Ok(session_key)
    }
}

//decrypt encrypted text with Session Key and Session IV
pub fn decrypt_with_session_key(session_key: &[u8], session_iv: &[u8], encrypted_text: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_cbc();
    let plain_text = decrypt(cipher, session_key, Some(session_iv), encrypted_text)
        .map_err(|e| format!("decrypt error: {:?}", e))?;
    Ok(plain_text)
}

//encrypt plain text with Session Key and Session IV
pub fn encrypt_with_session_key(session_key: &[u8], session_iv: &[u8], plain_text: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_cbc();
    let encrypted_text = encrypt(cipher, session_key, Some(session_iv), plain_text)
        .map_err(|e| format!("encrypt error: {:?}", e))?;
    Ok(encrypted_text)
}
