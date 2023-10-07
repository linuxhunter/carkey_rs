use super::{aes128, objects::{self, Body}};

type Result<T> = std::result::Result<T, String>;

pub fn create_auth_get_process_data_payload(reader_type: &[u8], reader_id: &[u8], reader_rnd: &[u8], reader_key_parameter: &[u8]) -> Vec<u8> {
    let mut payload= Vec::new();

    payload.push(0x80);     //CLA
    payload.push(0xCA);     //INS
    payload.push(0x00);     //P1
    payload.push(0x00);     //P2
    let lc = 3 + reader_type.len() + 3 + reader_id.len() + 3 + reader_rnd.len() + 3 + reader_key_parameter.len();
    payload.push(lc as u8); //Lc

    payload.push(0x9F);
    payload.push(0x35);
    payload.push(reader_type.len() as u8);
    payload.append(&mut reader_type.to_vec());
    payload.push(0x9F);
    payload.push(0x1E);
    payload.push(reader_id.len() as u8);
    payload.append(&mut reader_id.to_vec());
    payload.push(0x9F);
    payload.push(0x37);
    payload.push(reader_rnd.len() as u8);
    payload.append(&mut reader_rnd.to_vec());
    payload.push(0x9F);
    payload.push(0x0C);
    payload.push(reader_key_parameter.len() as u8);
    payload.append(&mut reader_key_parameter.to_vec());
    payload.push(0x00);     //Le

    payload
}

pub fn handle_auth_get_process_data_response_payload(payload: &[u8], reader_rnd: &[u8], reader_key_parameter: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let sw1 = payload[payload.len()-2];
    let sw2 = payload[payload.len()-1];
    let mut card_seid = Vec::with_capacity(8);
    let mut card_id = Vec::with_capacity(16);
    let mut card_rnd = Vec::with_capacity(8);
    let mut card_info1 = Vec::new();
    let mut encrypted_text = Vec::new();

    if sw1 == 0x90 && sw2 == 0x00 {
        let mut index = 0x00;
        if payload[index] == 0x77 {
            index += 1;
            while index < payload.len() -2 {
                if payload[index] == 0x5A {
                    index += 1;
                    let length = payload[index] as usize;
                    index += 1;
                    let value = &payload[index..index+length];
                    index += length;
                    card_seid.append(&mut value.to_vec());
                } else if payload[index] == 0x9F && payload[index+1] == 0x3B {
                    index += 2;
                    let length = payload[index] as usize;
                    index += 1;
                    let value = &payload[index..index+length];
                    index += length;
                    card_id.append(&mut value.to_vec());
                } else if payload[index] == 0x9F && payload[index+1] == 0x3E {
                    index += 2;
                    let length = payload[index] as usize;
                    index += 1;
                    let value = &payload[index..index+length];
                    index += length;
                    card_rnd.append(&mut value.to_vec());
                } else if payload[index] == 0x9F && payload[index+1] == 0x05 {
                    index += 2;
                    let length = payload[index] as usize;
                    index += 1;
                    let value = &payload[index..index+length];
                    index += length;
                    card_info1.append(&mut value.to_vec());
                } else if payload[index] == 0x73 {
                    index += 1;
                    let value = &payload[index..payload.len()-2];
                    index = payload.len() - 2;
                    encrypted_text.append(&mut value.to_vec());
                }
            }
            if card_rnd.is_empty() || reader_rnd.is_empty() || card_seid.is_empty() || card_id.is_empty() {
                println!("Cannot calculate session IV and session Key");
                return Err("Cannot calculate session IV or session Key".to_string());
            }
            let mut card_atc = Vec::new();
            let session_iv = aes128::calculate_session_iv(reader_rnd, &card_rnd);
            let dkey = aes128::calculate_dkey(&card_seid, &card_id);
            let card_iv = aes128::get_card_iv();
            let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, reader_key_parameter)?;
            let decrypted_text = aes128::decrypt_with_session_key(&session_key, &session_iv, &encrypted_text)?;
            index = 0;
            while index < decrypted_text.len() {
                if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x36 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let value = &decrypted_text[index..index+length];
                    index += length;
                    card_atc.append(&mut value.to_vec());
                } else if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x37 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let _value = &decrypted_text[index..index+length];
                    index += length;
                }
            }
            Ok((session_key, session_iv, card_atc, card_rnd))
        } else {
            Err("Invalid Payload Label".to_string())
        }
    } else {
        Err("Response is not correct".to_string())
    }
}

pub fn create_auth_auth_payload(card_atc: &[u8], reader_auth_parameter: &[u8], card_rnd: &[u8], session_key: &[u8], session_iv: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();

    payload.push(0x80);     //CLA
    payload.push(0x80);     //INS
    payload.push(0x00);     //P1
    payload.push(0x00);     //P2

    let mut data_domain = Vec::new();
    data_domain.push(0x9F);
    data_domain.push(0x36);
    data_domain.push(card_atc.len() as u8);
    data_domain.append(&mut card_atc.to_vec());
    data_domain.push(0x9F);
    data_domain.push(0x0A);
    data_domain.push(reader_auth_parameter.len() as u8);
    data_domain.append(&mut reader_auth_parameter.to_vec());
    data_domain.push(0x9F);
    data_domain.push(0x3E);
    data_domain.push(card_rnd.len() as u8);
    data_domain.append(&mut card_rnd.to_vec());
    let encrypt_data = aes128::encrypt_with_session_key(session_key, session_iv, &data_domain)?;

    payload.push(1 + encrypt_data.len() as u8);      //Lc
    payload.push(0x77);
    payload.append(&mut encrypt_data.clone());
    payload.push(0x00);     //Le

    Ok(payload)
}

pub fn handle_auth_auth_response_payload(payload: &[u8], _reader_rnd: &[u8], session_key: &[u8], session_iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let sw1 = payload[payload.len()-2];
    let sw2 = payload[payload.len()-1];
    let mut card_auth_parameter = Vec::new();
    let mut reader_auth_parameter = Vec::new();
    if sw1 == 0x90 && sw2 == 0x00 {
        if payload[0] == 0x77 {
            let decrypted_text = aes128::decrypt_with_session_key(session_key, session_iv, &payload[1..payload.len()-2])?;
            let mut index = 0;
            while index < decrypted_text.len() {
                if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x31 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let value = &decrypted_text[index..index+length];
                    index += length;
                    card_auth_parameter.append(&mut value.to_vec());
                } else if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x0A {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let value = &decrypted_text[index..index+length];
                    index += length;
                    reader_auth_parameter.append(&mut value.to_vec());
                } else if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x37 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let _value = &decrypted_text[index..index+length];
                    index += length;
                }
            }
            Ok((card_auth_parameter, reader_auth_parameter))
        } else {
            Err("Invalid Payload Label".to_string())
        }
    } else {
        Err("Response is not correct".to_string())
    }
}

pub fn create_icce_auth_request(apdu: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+apdu.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(0x01, apdu);
    let body = objects::create_icce_body(0x01, 0x01, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_auth_get_process_data_request() -> objects::ICCE {
    let reader_type = aes128::get_reader_type();
    let reader_id = aes128::get_reader_id();
    let reader_rnd = aes128::get_reader_rnd();
    let reader_key_parameter = aes128::get_reader_key_parameter();
    let get_process_data_apdu = create_auth_get_process_data_payload(&reader_type, &reader_id, &reader_rnd, &reader_key_parameter);
    create_icce_auth_request(&get_process_data_apdu)
}

pub fn create_icce_auth_response(status: u8, apdu: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+apdu.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let apdu_payload = objects::create_icce_body_payload(0x01, apdu);
    let body = objects::create_icce_body(0x01, 0x01, &[status_payload, apdu_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn handle_icce_auth_response(body: &Body) -> Result<Vec<u8>> {
    let reader_rnd = aes128::get_reader_rnd();
    let reader_key_parameter = aes128::get_reader_key_parameter();
    let reader_auth_parameter = aes128::get_reader_auth_parameter();
    let mut response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err("ICCE Auth Response Status Error".to_string());
            }
        } else if payload.get_payload_type() == 0x01 {
            let value = payload.get_payload_value();
            if value[0] == 0x77 && value[1] == 0x5A && value[2] == 0x08 {
                //sending auth get process data response
                if let Ok((session_key, session_iv, card_atc, card_rnd)) = handle_auth_get_process_data_response_payload(value, &reader_rnd, &reader_key_parameter) {
                    objects::update_session_key(&session_key);
                    objects::update_session_iv(&session_iv);
                    objects::update_card_atc(&card_atc);
                    let auth_request_payload = create_auth_auth_payload(&card_atc, &reader_auth_parameter, &card_rnd, &session_key, &session_iv)?;
                    println!("Sending Auth Request......");
                    response.append(&mut create_icce_auth_request(&auth_request_payload).serialize());
                    return Ok(response)
                } else {
                    return Err("ICCE Auth Response Status Error".to_string());
                }
            } else {
                //sending auth auth response
                let session_key = objects::get_session_key();
                let session_iv = objects::get_session_iv();
                if let Ok((card_auth_parameter, reader_auth_parameter)) = handle_auth_auth_response_payload(value, &reader_rnd, &session_key, &session_iv) {
                    println!("card_auth_parameter = {:02X?}", card_auth_parameter);
                    println!("reader_auth_parameter = {:02X?}", reader_auth_parameter);
                    return Ok(response)
                } else {
                    return Err("ICCE Auth Response Status Error".to_string());
                }
            }
        } else {
            return Err("Invalid payload type".to_string());
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::icce::objects::{ICCE, Header, Control, Payload};

    use super::*;

    #[test]
    fn test_create_icce_auth_request() {
        let apdu = vec![0x01, 0x02, 0x03, 0x04];
        let icce = create_icce_auth_request(&apdu);
        let mut target_icce = ICCE::new();
        let mut target_header = Header::new();
        target_header.set_sof(0x5A);
        target_header.set_length(0x0a);
        target_header.set_control(Control::from(0x10));
        target_header.set_fsn(0x00);
        let mut target_body = Body::new();
        target_body.set_message_id(0x01);
        target_body.set_command_id(0x01);
        let mut target_payload = Payload::new();
        target_payload.set_payload_type(0x01);
        target_payload.set_payload_length(0x04);
        target_payload.set_payload_value(&vec![0x01, 0x02, 0x03, 0x04]);
        target_body.set_payload(target_payload);
        target_icce.set_header(target_header);
        target_icce.set_body(target_body);
        target_icce.set_checksum(0x5237);
        assert_eq!(icce, target_icce);
    }
    #[test]
    fn test_create_icce_auth_response() {
        let status = 0x00;
        let apdu = vec![0x01, 0x02, 0x03, 0x04];
        let icce = create_icce_auth_response(status, &apdu);
        let mut target_icce = ICCE::new();
        let mut target_header = Header::new();
        target_header.set_sof(0x5A);
        target_header.set_length(0x0D);
        target_header.set_control(Control::from(0x00));
        target_header.set_fsn(0x00);
        let mut target_body = Body::new();
        target_body.set_message_id(0x01);
        target_body.set_command_id(0x01);
        let mut target_payload = Payload::new();
        target_payload.set_payload_type(0x00);
        target_payload.set_payload_length(0x01);
        target_payload.set_payload_value(&vec![0x00]);
        target_body.set_payload(target_payload);
        let mut target_payload2 = Payload::new();
        target_payload2.set_payload_type(0x01);
        target_payload2.set_payload_length(0x04);
        target_payload2.set_payload_value(&vec![0x01, 0x02, 0x03, 0x04]);
        target_body.set_payload(target_payload2);
        target_icce.set_header(target_header);
        target_icce.set_body(target_body);
        target_icce.set_checksum(0xB7B5);
        assert_eq!(icce, target_icce);
    }
    #[test]
    fn test_auth_get_process_data_payload() {
        let reader_type = aes128::get_reader_type();
        let reader_id = aes128::get_reader_id();
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();

        let auth_get_process_data_payload = create_auth_get_process_data_payload(&reader_type, &reader_id, &reader_rnd, &reader_key_parameter);

        assert_eq!(auth_get_process_data_payload,
            vec![128, 202, 0, 0, 50, 159, 53, 6, 1, 2, 3, 4, 5, 6, 159, 30, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0,
            159, 55, 8, 1, 2, 3, 4, 5, 6, 7, 8, 159, 12, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
    }
    #[test]
    fn test_auth_handle_get_process_data_reponse_payload() {
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let card_rnd = aes128::get_card_rnd();
        let card_info1 = aes128::get_card_info1();
        let card_atc = aes128::get_card_atc();
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();
        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);
        payload.push(0x5A);
        payload.push(card_seid.len() as u8);
        payload.append(&mut card_seid.clone().to_vec());
        payload.push(0x9F);
        payload.push(0x3B);
        payload.push(card_id.len() as u8);
        payload.append(&mut card_id.clone().to_vec());
        payload.push(0x9F);
        payload.push(0x3E);
        payload.push(card_rnd.len() as u8);
        payload.append(&mut card_rnd.clone().to_vec());
        payload.push(0x9F);
        payload.push(0x05);
        payload.push(card_info1.len() as u8);
        payload.append(&mut card_info1.clone().to_vec());
        payload.push(0x73);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x36);
        plain_text.push(card_atc.len() as u8);
        plain_text.append(&mut card_atc.clone().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.len() as u8);
        plain_text.append(&mut reader_rnd.clone().to_vec());
        let encrypted_text = aes128::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        match handle_auth_get_process_data_response_payload(&payload, &reader_rnd, &reader_key_parameter) {
            Ok((sess_key, sess_iv, atc, card_rnd1)) => {
                assert_eq!(sess_key, sess_key);
                assert_eq!(sess_iv, sess_iv);
                assert_eq!(atc, card_atc);
                assert_eq!(card_rnd1, card_rnd);
            },
            Err(err) => {
                println!("Error is {}", err);
                assert!(false);
            }
        }
    }
    #[test]
    fn test_auth_auth_payload() {
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();
        let reader_auth_parameter = aes128::get_reader_auth_parameter();
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let card_rnd = aes128::get_card_rnd();
        let card_atc = aes128::get_card_atc();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();
        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let _payload = create_auth_auth_payload(&card_atc, &reader_auth_parameter, &card_rnd, &session_key, &session_iv).unwrap();
    }
    #[test]
    fn test_auth_auth_response_payload() {
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let card_rnd = aes128::get_card_rnd();
        let card_auth_parameter = aes128::get_card_auth_parameter();
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();
        let reader_auth_parameter = aes128::get_reader_auth_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();
        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x31);
        plain_text.push(card_auth_parameter.len() as u8);
        plain_text.append(&mut card_auth_parameter.clone().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x0A);
        plain_text.push(reader_auth_parameter.len() as u8);
        plain_text.append(&mut &mut reader_auth_parameter.clone().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.len() as u8);
        plain_text.append(&mut reader_rnd.clone().to_vec());
        let encrypted_text = aes128::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        match handle_auth_auth_response_payload(&payload, &reader_rnd, &session_key, &session_iv) {
            Ok((card_auth, reader_auth)) => {
                assert_eq!(card_auth, card_auth_parameter);
                assert_eq!(reader_auth, reader_auth_parameter);
            },
            Err(error) => {
                println!("Error is {}", error);
                assert!(false);
            }
        }
    }
    #[test]
    fn test_create_auth_get_process_data_response_payload() {
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let card_rnd = aes128::get_card_rnd();
        let card_info1 = aes128::get_card_info1();
        let card_atc = aes128::get_card_atc();
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();
        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);
        payload.push(0x5A);
        payload.push(card_seid.len() as u8);
        payload.append(&mut card_seid.clone().to_vec());
        payload.push(0x9F);
        payload.push(0x3B);
        payload.push(card_id.len() as u8);
        payload.append(&mut card_id.clone().to_vec());
        payload.push(0x9F);
        payload.push(0x3E);
        payload.push(card_rnd.len() as u8);
        payload.append(&mut card_rnd.clone().to_vec());
        payload.push(0x9F);
        payload.push(0x05);
        payload.push(card_info1.len() as u8);
        payload.append(&mut card_info1.clone().to_vec());
        payload.push(0x73);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x36);
        plain_text.push(card_atc.len() as u8);
        plain_text.append(&mut card_atc.clone().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.len() as u8);
        plain_text.append(&mut reader_rnd.clone().to_vec());
        let encrypted_text = aes128::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        let icce = create_icce_auth_response(0x00, &payload);
    }
    #[test]
    fn test_create_auth_auth_response_payload() {
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let card_rnd = aes128::get_card_rnd();
        let card_auth_parameter = aes128::get_card_auth_parameter();
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();
        let reader_auth_parameter = aes128::get_reader_auth_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();
        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x31);
        plain_text.push(card_auth_parameter.len() as u8);
        plain_text.append(&mut card_auth_parameter.clone().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x0A);
        plain_text.push(reader_auth_parameter.len() as u8);
        plain_text.append(&mut &mut reader_auth_parameter.clone().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.len() as u8);
        plain_text.append(&mut reader_rnd.clone().to_vec());
        let encrypted_text = aes128::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        let icce = create_icce_auth_response(0x00, &payload);
    }

}