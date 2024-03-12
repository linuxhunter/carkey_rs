use log::debug;
use crate::icce::card_info::{CardATC, CardId, CardInfo1, CardRnd, CardSeId};
use super::{card_info, dkey_info, objects::{self, Body}, Serde, session, vehicle_info};
use crate::icce::errors::*;

pub fn create_auth_get_process_data_payload(reader_type: &[u8], reader_id: &[u8], reader_rnd: &[u8], reader_key_parameter: &[u8]) -> Vec<u8> {
    let mut payload= vec![0x80, 0xCA, 0x00, 0x00];

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

#[derive(Debug, PartialOrd, PartialEq)]
pub struct IcceAuthResponseInfo {
    card_atc: Vec<u8>,
    card_rnd: Vec<u8>,
}

impl IcceAuthResponseInfo {
    pub fn new(card_atc: &[u8], card_rnd: &[u8]) -> Self {
        IcceAuthResponseInfo {
            card_atc: card_atc.to_vec(),
            card_rnd: card_rnd.to_vec(),
        }
    }
    pub fn get_card_atc(&self) -> &[u8] {
        self.card_atc.as_ref()
    }
    pub fn get_card_rnd(&self) -> &[u8] {
        self.card_rnd.as_ref()
    }
}

pub fn handle_auth_get_process_data_response_payload(payload: &[u8], reader_rnd: &[u8], reader_key_parameter: &[u8]) -> Result<IcceAuthResponseInfo> {
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
                return Err(ErrorKind::AuthError("Cannot calculate session IV or session Key".to_string()).into());
            }
            card_info::set_card_se_id(&CardSeId::new(card_seid.as_ref()));
            card_info::set_card_id(&CardId::new(card_id.as_ref()));
            card_info::set_card_rnd(&CardRnd::new(card_rnd.as_ref()));
            card_info::set_card_info1(&CardInfo1::new(card_info1.as_ref()));

            session::calculate_session_iv(reader_rnd, &card_rnd);
            let dkey = dkey_info::calculate_dkey(&card_seid, &card_id);
            session::calculate_session_key(&dkey, reader_key_parameter)?;
            let decrypted_text = session::decrypt_with_session_key(&encrypted_text)?;
            index = 0;
            while index < decrypted_text.len() {
                if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x36 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let value = &decrypted_text[index..index+length];
                    index += length;
                    card_info::set_card_atc(&CardATC::new(value));
                } else if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x37 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let _value = &decrypted_text[index..index+length];
                    index += length;
                }
            }
            Ok(IcceAuthResponseInfo::new(card_info::get_card_atc().get_card_atc(), card_rnd.as_ref()))
        } else {
            Err(ErrorKind::AuthError("Invalid Payload Label".to_string()).into())
        }
    } else {
        Err(ErrorKind::AuthError("Response is not correct".to_string()).into())
    }
}

pub fn create_auth_auth_payload(card_atc: &[u8], reader_auth_parameter: &[u8], card_rnd: &[u8]) -> Result<Vec<u8>> {
    let mut payload = vec![0x80, 0x80, 0x00, 0x00];

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
    let encrypt_data = session::encrypt_with_session_key(&data_domain)?;

    payload.push(1 + encrypt_data.len() as u8);      //Lc
    payload.push(0x77);
    payload.append(&mut encrypt_data.clone());
    payload.push(0x00);     //Le

    Ok(payload)
}

pub fn handle_auth_auth_response_payload(payload: &[u8], _reader_rnd: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let sw1 = payload[payload.len()-2];
    let sw2 = payload[payload.len()-1];
    let mut card_auth_parameter = Vec::new();
    let mut reader_auth_parameter = Vec::new();
    if sw1 == 0x90 && sw2 == 0x00 {
        if payload[0] == 0x77 {
            let decrypted_text = session::decrypt_with_session_key(&payload[1..payload.len()-2])?;
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
            Err(ErrorKind::AuthError("Invalid Payload Label".to_string()).into())
        }
    } else {
        Err(ErrorKind::AuthError("Response is not correct".to_string()).into())
    }
}

pub fn create_icce_auth_request(apdu: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+apdu.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(0x01, apdu);
    let body = objects::create_icce_body(0x01, 0x01, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_auth_get_process_data_request() -> Result<objects::Icce> {
    let reader_type = vehicle_info::get_vehicle_reader_type();
    let reader_id = vehicle_info::get_vehicle_reader_id();
    let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
    let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();
    let get_process_data_apdu = create_auth_get_process_data_payload(
        reader_type.serialize()?.as_ref(),
        reader_id.serialize()?.as_ref(),
        reader_rnd.serialize()?.as_ref(),
        reader_key_parameter.serialize()?.as_ref()
    );
    Ok(create_icce_auth_request(&get_process_data_apdu))
}

#[allow(dead_code)]
pub fn create_icce_auth_response(status: u8, apdu: &[u8]) -> objects::Icce {
    let mut icce = objects::Icce::new();

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
    let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
    let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();
    let reader_auth_parameter = vehicle_info::get_vehicle_reader_auth_parameter();
    let mut response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err(ErrorKind::AuthError("Icce Auth Response Status Error".to_string()).into());
            }
        } else if payload.get_payload_type() == 0x01 {
            let value = payload.get_payload_value();
            return if value[0] == 0x77 && value[1] == 0x5A && value[2] == 0x08 {
                //sending auth get process data response
                if let Ok(icce_auth_response) = handle_auth_get_process_data_response_payload(value, reader_rnd.serialize()?.as_ref(), reader_key_parameter.serialize()?.as_ref()) {
                    let auth_request_payload = create_auth_auth_payload(
                        icce_auth_response.get_card_atc(),
                        reader_auth_parameter.serialize()?.as_ref(),
                        icce_auth_response.get_card_rnd(),
                    )?;
                    debug!("Sending Auth Request......");
                    response.append(&mut create_icce_auth_request(&auth_request_payload).serialize());
                    Ok(response)
                } else {
                    Err(ErrorKind::AuthError("Icce Auth Response Status Error".to_string()).into())
                }
            } else {
                //sending auth auth response
                if let Ok((card_auth_parameter, reader_auth_parameter)) = handle_auth_auth_response_payload(value, reader_rnd.serialize()?.as_ref()) {
                    debug!("card_auth_parameter = {:02X?}", card_auth_parameter);
                    debug!("reader_auth_parameter = {:02X?}", reader_auth_parameter);
                    Ok(response)
                } else {
                    Err(ErrorKind::AuthError("Icce Auth Response Status Error".to_string()).into())
                }
            }
        } else {
            return Err(ErrorKind::AuthError("Invalid payload type".to_string()).into());
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::icce::objects::{Icce, Header, Control, Payload};

    use super::*;

    #[test]
    fn test_create_icce_auth_request() {
        let apdu = vec![0x01, 0x02, 0x03, 0x04];
        let icce = create_icce_auth_request(&apdu);
        let mut target_icce = Icce::new();
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
        let mut target_icce = Icce::new();
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
        let reader_type = vehicle_info::get_vehicle_reader_type();
        let reader_id = vehicle_info::get_vehicle_reader_id();
        let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
        let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();

        let auth_get_process_data_payload = create_auth_get_process_data_payload(
            reader_type.serialize().unwrap().as_ref(),
            reader_id.serialize().unwrap().as_ref(),
            reader_rnd.serialize().unwrap().as_ref(),
            reader_key_parameter.serialize().unwrap().as_ref());

        println!("auth_get_process_data_payload = {:02X?}", auth_get_process_data_payload);
    }
    #[test]
    fn test_auth_handle_get_process_data_reponse_payload() {
        let card_seid = card_info::get_card_se_id();
        let card_id = card_info::get_card_id();
        let card_rnd = card_info::get_card_rnd();
        let card_info1 = card_info::get_card_info1();
        let card_atc = card_info::get_card_atc();
        let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
        let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();

        session::calculate_session_iv(reader_rnd.get_reader_rnd(), card_rnd.get_card_rnd());
        let dkey = dkey_info::calculate_dkey(card_seid.get_card_se_id(), card_id.get_card_id());
        let card_iv = card_info::get_card_iv();
        session::calculate_session_key(&dkey, reader_key_parameter.get_reader_key_parameter()).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);
        payload.push(0x5A);
        payload.push(card_seid.get_card_se_id().len() as u8);
        payload.append(&mut card_seid.get_card_se_id().to_vec());
        payload.push(0x9F);
        payload.push(0x3B);
        payload.push(card_id.get_card_id().len() as u8);
        payload.append(&mut card_id.get_card_id().to_vec());
        payload.push(0x9F);
        payload.push(0x3E);
        payload.push(card_rnd.get_card_rnd().len() as u8);
        payload.append(&mut card_rnd.get_card_rnd().to_vec());
        payload.push(0x9F);
        payload.push(0x05);
        payload.push(card_info1.get_card_info1().len() as u8);
        payload.append(&mut card_info1.get_card_info1().to_vec());
        payload.push(0x73);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x36);
        plain_text.push(card_atc.get_card_atc().len() as u8);
        plain_text.append(&mut card_atc.get_card_atc().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.get_reader_rnd().len() as u8);
        plain_text.append(&mut reader_rnd.get_reader_rnd().to_vec());
        let encrypted_text = session::encrypt_with_session_key(&plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        match handle_auth_get_process_data_response_payload(&payload, reader_rnd.get_reader_rnd(), reader_key_parameter.get_reader_key_parameter()) {
            Ok(icce_auth_response) => {
                assert_eq!(icce_auth_response.get_card_atc().to_vec(), card_atc.get_card_atc());
                assert_eq!(icce_auth_response.get_card_rnd().to_vec(), card_rnd.get_card_rnd());
            },
            Err(err) => {
                println!("Error is {}", err);
                assert!(false);
            }
        }
    }
    #[test]
    fn test_auth_auth_payload() {
        let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
        let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();
        let reader_auth_parameter = vehicle_info::get_vehicle_reader_auth_parameter();
        let card_seid = card_info::get_card_se_id();
        let card_id = card_info::get_card_id();
        let card_rnd = card_info::get_card_rnd();
        let card_atc = card_info::get_card_atc();

        session::calculate_session_iv(reader_rnd.get_reader_rnd(), card_rnd.get_card_rnd());
        let dkey = dkey_info::calculate_dkey(card_seid.get_card_se_id(), card_id.get_card_id());
        let card_iv = card_info::get_card_iv();
        session::calculate_session_key(&dkey, reader_key_parameter.get_reader_key_parameter()).unwrap();

        let _payload = create_auth_auth_payload(card_atc.get_card_atc(), reader_auth_parameter.get_reader_auth_parameter(), card_rnd.get_card_rnd()).unwrap();
    }
    #[test]
    fn test_auth_auth_response_payload() {
        let card_seid = card_info::get_card_se_id();
        let card_id = card_info::get_card_id();
        let card_rnd = card_info::get_card_rnd();
        let card_auth_parameter = card_info::get_card_auth_parameter();
        let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
        let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();
        let reader_auth_parameter = vehicle_info::get_vehicle_reader_auth_parameter();

        session::calculate_session_iv(reader_rnd.get_reader_rnd(), card_rnd.get_card_rnd());
        let dkey = dkey_info::calculate_dkey(card_seid.get_card_se_id(), card_id.get_card_id());
        let card_iv = card_info::get_card_iv();
        session::calculate_session_key(&dkey, reader_key_parameter.get_reader_key_parameter()).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x31);
        plain_text.push(card_auth_parameter.get_card_auth_parameter().len() as u8);
        plain_text.append(&mut card_auth_parameter.get_card_auth_parameter().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x0A);
        plain_text.push(reader_auth_parameter.get_reader_auth_parameter().len() as u8);
        plain_text.append(&mut &mut reader_auth_parameter.get_reader_auth_parameter().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.get_reader_rnd().len() as u8);
        plain_text.append(&mut reader_rnd.get_reader_rnd().to_vec());
        let encrypted_text = session::encrypt_with_session_key(&plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        match handle_auth_auth_response_payload(&payload, reader_rnd.get_reader_rnd()) {
            Ok((card_auth, reader_auth)) => {
                assert_eq!(card_auth, card_auth_parameter.get_card_auth_parameter().to_vec());
                assert_eq!(reader_auth, reader_auth_parameter.get_reader_auth_parameter().to_vec());
            },
            Err(error) => {
                println!("Error is {}", error);
                assert!(false);
            }
        }
    }
    #[test]
    fn test_create_auth_get_process_data_response_payload() {
        let card_seid = card_info::get_card_se_id();
        let card_id = card_info::get_card_id();
        let card_rnd = card_info::get_card_rnd();
        let card_info1 = card_info::get_card_info1();
        let card_atc = card_info::get_card_atc();
        let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
        let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();

        session::calculate_session_iv(reader_rnd.get_reader_rnd(), card_rnd.get_card_rnd());
        let dkey = dkey_info::calculate_dkey(card_seid.get_card_se_id(), card_id.get_card_id());
        let card_iv = card_info::get_card_iv();
        session::calculate_session_key(&dkey, reader_key_parameter.get_reader_key_parameter()).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);
        payload.push(0x5A);
        payload.push(card_seid.get_card_se_id().len() as u8);
        payload.append(&mut card_seid.get_card_se_id().to_vec());
        payload.push(0x9F);
        payload.push(0x3B);
        payload.push(card_id.get_card_id().len() as u8);
        payload.append(&mut card_id.get_card_id().to_vec());
        payload.push(0x9F);
        payload.push(0x3E);
        payload.push(card_rnd.get_card_rnd().len() as u8);
        payload.append(&mut card_rnd.get_card_rnd().to_vec());
        payload.push(0x9F);
        payload.push(0x05);
        payload.push(card_info1.get_card_info1().len() as u8);
        payload.append(&mut card_info1.get_card_info1().to_vec());
        payload.push(0x73);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x36);
        plain_text.push(card_atc.get_card_atc().len() as u8);
        plain_text.append(&mut card_atc.get_card_atc().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.get_reader_rnd().len() as u8);
        plain_text.append(&mut reader_rnd.get_reader_rnd().to_vec());
        let encrypted_text = session::encrypt_with_session_key(&plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        let _icce = create_icce_auth_response(0x00, &payload);
    }
    #[test]
    fn test_create_auth_auth_response_payload() {
        let card_seid = card_info::get_card_se_id();
        let card_id = card_info::get_card_id();
        let card_rnd = card_info::get_card_rnd();
        let card_auth_parameter = card_info::get_card_auth_parameter();
        let reader_rnd = vehicle_info::get_vehicle_reader_rnd();
        let reader_key_parameter = vehicle_info::get_vehicle_reader_key_parameter();
        let reader_auth_parameter = vehicle_info::get_vehicle_reader_auth_parameter();

        session::calculate_session_iv(reader_rnd.get_reader_rnd(), card_rnd.get_card_rnd());
        let dkey = dkey_info::calculate_dkey(card_seid.get_card_se_id(), card_id.get_card_id());
        let card_iv = card_info::get_card_iv();
        session::calculate_session_key(&dkey, reader_key_parameter.get_reader_key_parameter()).unwrap();

        let mut payload = Vec::new();
        payload.push(0x77);

        let mut plain_text = Vec::new();
        plain_text.push(0x9F);
        plain_text.push(0x31);
        plain_text.push(card_auth_parameter.get_card_auth_parameter().len() as u8);
        plain_text.append(&mut card_auth_parameter.get_card_auth_parameter().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x0A);
        plain_text.push(reader_auth_parameter.get_reader_auth_parameter().len() as u8);
        plain_text.append(&mut &mut reader_auth_parameter.get_reader_auth_parameter().to_vec());
        plain_text.push(0x9F);
        plain_text.push(0x37);
        plain_text.push(reader_rnd.get_reader_rnd().len() as u8);
        plain_text.append(&mut reader_rnd.get_reader_rnd().to_vec());
        let encrypted_text = session::encrypt_with_session_key(&plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        let _icce = create_icce_auth_response(0x00, &payload);
    }

}
