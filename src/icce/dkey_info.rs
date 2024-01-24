//DKey is calculated by CardSEID and CardID, which length is 16Bytes

use std::collections::HashMap;
use std::sync::Mutex;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;

lazy_static! {
    static ref DKEY: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
}

pub fn save_dkey(card_seid: &[u8], card_id: &[u8], card_dkey: &[u8]) {
    let mut key = Vec::new();
    key.append(&mut card_seid.to_vec());
    key.append(&mut card_id.to_vec());
    let base64_key = BASE64_STANDARD.encode(key);
    let mut dkey = DKEY.lock().unwrap();
    dkey.insert(base64_key, card_dkey.to_vec());
}

pub fn remove_dkey(card_seid: &[u8], card_id: &[u8]) {
    let mut key = Vec::new();
    key.append(&mut card_seid.to_vec());
    key.append(&mut card_id.to_vec());
    let base64_key = BASE64_STANDARD.encode(key);
    let mut dkey = DKEY.lock().unwrap();
    dkey.remove(&base64_key);
}

pub fn get_dkey(card_seid: &[u8], card_id: &[u8]) -> Option<Vec<u8>> {
    let mut key = Vec::new();
    key.append(&mut card_seid.to_vec());
    key.append(&mut card_id.to_vec());
    let base64_key = BASE64_STANDARD.encode(key);
    let dkey = DKEY.lock().unwrap();
    dkey.get(&base64_key).map(|key| key.to_vec())
}

pub fn calculate_dkey(card_seid: &[u8], card_id: &[u8]) -> Vec<u8> {
    //根据card_seid查找到相应的认证根密钥
    //用card_id分散因子计算认证密钥DKey
    let mut key = Vec::new();
    key.append(&mut card_seid.to_vec());
    key.append(&mut card_id.to_vec());
    let base64_key = BASE64_STANDARD.encode(key);
    let dkey = DKEY.lock().unwrap();
    let dkey_value = dkey.get(&base64_key);
    match dkey_value {
        Some(value) => {
            value.to_vec()
        },
        None => {
            vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        }
    }
}
