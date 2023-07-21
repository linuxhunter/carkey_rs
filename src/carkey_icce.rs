use std::sync::Mutex;

use crc16::CCITT_FALSE;

use crate::carkey_icce_crypto;

type Result<T> = std::result::Result<T, String>;

lazy_static! {
    static ref SESSION_KEY: Mutex<[u8; 16]> = Mutex::new([0; 16]);
    static ref SESSION_IV: Mutex<[u8; 16]> = Mutex::new([0; 16]);
    static ref CARD_ATC: Mutex<[u8; 4]> = Mutex::new([0; 4]);
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Control(u8);

impl Control {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn clear(&mut self) {
        self.0 = 0x00;
    }
    pub fn set_request(&mut self) {
        self.0 |= 0b00010000;
    }
    pub fn set_response(&mut self) {
        self.0 &= 0b11101111;
    }
    pub fn set_crypto(&mut self) {
        self.0 |= 0b00001000;
    }
    pub fn set_no_crypto(&mut self) {
        self.0 &= 0b11110111;
    }
    pub fn set_async(&mut self) {
        self.0 |= 0b00000100;
    }
    pub fn set_sync(&mut self) {
        self.0 &= 0b11111011;
    }
    pub fn set_no_frag(&mut self) {
        self.0 &= 0b11111100;
    }
    pub fn set_first_frag(&mut self) {
        self.0 |= 0b00000001;
        self.0 &= 0b11111101;
    }
    pub fn set_conti_frag(&mut self) {
        self.0 &= 0b11111110;
        self.0 |= 0b00000010;
    }
    pub fn set_last_frag(&mut self) {
        self.0 |= 0b00000011;
    }
    pub fn is_request(&self) -> bool {
        if self.0 & 0b00010000 == 0 {
            false
        } else {
            true
        }
    }
    pub fn is_crypto(&self) -> bool {
        if self.0 & 0b00001000 == 0 {
            false
        } else {
            true
        }
    }
    pub fn is_async(&self) -> bool {
        if self.0 & 0b00000100 == 0 {
            false
        } else {
            true
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        serialized_data.push(self.0);
        serialized_data
    }
    pub fn deserialize(byte_stream: &[u8]) -> Result<Self> {
        if byte_stream.len() < 1 {
            return Err("Invalid byte stream length".to_string());
        }
        let mut control = Control::new();
        control.0 = byte_stream[0];
        Ok(control)
    }
}

impl From<u8> for Control {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Control> for u8 {
    fn from(value: Control) -> Self {
        value.0
    }
}

impl std::fmt::Display for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Header {
    sof: u8,
    length: u16,
    control: Control,
    fsn: u8,    
}

impl Header {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_sof(&mut self, sof: u8) {
        self.sof = sof;
    }
    pub fn set_length(&mut self, length: u16) {
        self.length = length;
    }
    pub fn set_control(&mut self, control: Control) {
        self.control = control;
    }
    pub fn set_fsn(&mut self, fsn: u8) {
        self.fsn = fsn;
    }
    pub fn get_length(&self) -> u16 {
        self.length
    }
    pub fn get_control(&self) -> Control {
        self.control
    }
    pub fn get_fsn(&self) -> u8 {
        self.fsn
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        serialized_data.push(self.sof);
        serialized_data.append(&mut self.length.to_le_bytes().to_vec());
        serialized_data.append(&mut self.control.serialize().to_vec());
        serialized_data.push(self.fsn);

        serialized_data
    }
    pub fn deserialize(byte_stream: &[u8]) -> Result<Self> {
        if byte_stream.len() < 5 {
            return Err("Invalid byte stream length".to_string());
        }
        let mut header = Header::new();
        header.set_sof(byte_stream[0]);
        let length_bytes: [u8; 2] = [byte_stream[1], byte_stream[2]];
        header.set_length(u16::from_le_bytes(length_bytes));
        header.set_control(Control::from(byte_stream[3]));
        header.set_fsn(byte_stream[4]);

        Ok(header)
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Payload {
    payload_type: u8,
    payload_length: u8,
    payload_value: Vec<u8>,
}

impl Payload {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_payload_type(&mut self, payload_type: u8) {
        self.payload_type = payload_type;
    }
    pub fn set_payload_length(&mut self, payload_length: u8) {
        self.payload_length = payload_length;
    }
    pub fn set_payload_value(&mut self, payload_value: &[u8]) {
        self.payload_value = payload_value.to_vec();
    }
    pub fn get_payload_type(&self) -> u8 {
        self.payload_type
    }
    pub fn get_payload_length(&self) -> u8 {
        self.payload_length
    }
    pub fn get_payload_value(&self) -> &[u8] {
        &self.payload_value
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        serialized_data.push(self.payload_type);
        serialized_data.push(self.payload_length);
        serialized_data.append(&mut self.payload_value.to_vec());

        serialized_data
    }
    pub fn deserialize(byte_stream: &[u8]) -> Result<Self> {
        if byte_stream.len() < 2 || byte_stream.len() < 2 + byte_stream[1] as usize {
            return Err("Invalid byte stream length".to_string());
        }
        let mut payload = Payload::new();
        payload.set_payload_type(byte_stream[0]);
        payload.set_payload_length(byte_stream[1]);
        payload.set_payload_value(&byte_stream[2..2+byte_stream[1] as usize]);

        Ok(payload)
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Body {
    message_id: u8,
    command_id: u8,
    payloads: Vec<Payload>,
}

impl Body {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_message_id(&mut self, message_id: u8) {
        self.message_id = message_id;
    }
    pub fn set_command_id(&mut self, command_id: u8) {
        self.command_id = command_id;
    }
    pub fn set_payload(&mut self, payload: Payload) {
        self.payloads.push(payload);
    }
    pub fn get_message_id(&self) -> u8 {
        self.message_id
    }
    pub fn get_command_id(&self) -> u8 {
        self.command_id
    }
    pub fn get_payloads(&self) -> &[Payload] {
        &self.payloads
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        serialized_data.push(self.message_id);
        serialized_data.push(self.command_id);
        self.payloads.iter().for_each(|payload| {
            serialized_data.append(&mut payload.serialize().to_vec());
        });

        serialized_data
    }
    pub fn deserialize(byte_stream: &[u8]) -> Result<Self> {
        if byte_stream.len() < 2 {
            return Err("Invalid byte stream length".to_string());
        }
        let mut body = Body::new();
        body.set_message_id(byte_stream[0]);
        body.set_command_id(byte_stream[1]);
        let mut index = 2;
        while index < byte_stream.len() {
            let payload = Payload::deserialize(&byte_stream[index..])?;
            index = index + 2 + payload.payload_length as usize;
            body.set_payload(payload);
        }

        Ok(body)
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct ICCE {
    pub header: Header,
    pub body: Body,
    pub checksum: u16,
}

impl ICCE {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_header(&mut self, header: Header) {
        self.header = header;
    }
    pub fn set_body(&mut self, body: Body) {
        self.body = body;
    }
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum;
    }
    pub fn get_header(&self) -> &Header {
        &self.header
    }
    pub fn get_body(&self) -> &Body {
        &self.body
    }
    pub fn get_checksum(&self) -> u16 {
        self.checksum
    }
    pub fn calculate_checksum(&mut self) {
        let crc16_header= self.header.serialize();
        let crc16_body = self.body.serialize();
        let mut crc16_ccitt = crc16::State::<CCITT_FALSE>::new();
        crc16_ccitt.update(&crc16_header);
        crc16_ccitt.update(&crc16_body);
        self.checksum = crc16_ccitt.get();
    }
    pub fn calculate_bytearray_checksum(payload: &[u8]) -> u16 {
        let mut crc16_ccitt = crc16::State::<CCITT_FALSE>::new();
        crc16_ccitt.update(payload);
        crc16_ccitt.get()
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data = Vec::new();
        if self.get_header().get_control().is_crypto() == false {
            serialized_data.append(&mut self.header.serialize());
            serialized_data.append(&mut self.body.serialize());
            serialized_data.append(&mut self.checksum.to_le_bytes().to_vec());
        } else {
            //handle body encrypt
            let mut plain_text = Vec::new();
            plain_text.append(&mut self.body.serialize());
            let encrypted_text = carkey_icce_crypto::encrypt_with_session_key(
                &SESSION_KEY.lock().unwrap().to_vec(),
                &SESSION_IV.lock().unwrap().to_vec(),
                &plain_text).unwrap();
            //create new header object with new length
            let mut new_header = Header::new();
            new_header.set_sof(0x5A);
            new_header.set_length(2 + encrypted_text.len() as u16);
            new_header.set_control(self.get_header().get_control());
            new_header.set_fsn(self.get_header().get_fsn());
            serialized_data.append(&mut new_header.serialize());
            serialized_data.append(&mut encrypted_text.to_vec());
            let new_checksum = ICCE::calculate_bytearray_checksum(&serialized_data);
            serialized_data.append(&mut new_checksum.to_le_bytes().to_vec());
        }

        serialized_data
    }
    pub fn deserialize(byte_stream: &[u8]) -> Result<Self> {
        let mut icce = ICCE::new();
        if byte_stream.len() < 5 {
            return Err("Invalid byte stream length".to_string());
        }
        icce.set_header(Header::deserialize(&byte_stream[0..])?);
        if icce.get_header().get_control().is_crypto() == false {
            icce.set_body(Body::deserialize(&byte_stream[5..byte_stream.len()-2])?);
            let checksum_bytes: [u8; 2] = [byte_stream[byte_stream.len()-2], byte_stream[byte_stream.len()-1]];
            icce.set_checksum(u16::from_le_bytes(checksum_bytes));
        } else {
            let mut new_header = Header::new();
            new_header.set_sof(0x5A);
            new_header.set_control(icce.get_header().get_control());
            new_header.set_fsn(icce.get_header().get_fsn());

            let encrypted_text = &byte_stream[5..byte_stream.len()-2];
            let plain_text = carkey_icce_crypto::decrypt_with_session_key(
                &SESSION_KEY.lock().unwrap().to_vec(),
                &SESSION_IV.lock().unwrap().to_vec(),
                &encrypted_text)?;
            new_header.set_length(2 + plain_text.len() as u16);
            icce.set_header(new_header);

            icce.set_body(Body::deserialize(&plain_text)?);

            let mut checksum_entry = new_header.serialize();
            checksum_entry.append(&mut plain_text.to_vec());
            icce.set_checksum(ICCE::calculate_bytearray_checksum(&checksum_entry));
        }

        Ok(icce)
    }
}

pub fn create_icce_header(request_flag: bool, crypto_flag: bool, async_flag: bool, frag_flag: u8, fsn: u8, length: u16) -> Header {
    let mut control = Control::new();
    if request_flag == true {
        control.set_request();
    } else {
        control.set_response();
    }
    if crypto_flag == true {
        control.set_crypto();
    } else {
        control.set_no_crypto();
    }
    if async_flag == true {
        control.set_async();
    } else {
        control.set_sync();
    }
    if frag_flag == 0x00 {
        control.set_no_frag();
    } else if frag_flag == 0x01 {
        control.set_first_frag();
    } else if frag_flag == 0x02 {
        control.set_conti_frag();
    } else {
        control.set_last_frag();
    }
    let mut header = Header::new();
    header.set_sof(0x5A);
    header.set_control(control);
    header.set_length(length);
    header.set_fsn(fsn);

    header
}

pub fn create_icce_body_payload(payload_type: u8, payload_value: &[u8]) -> Payload {
    let mut payload = Payload::new();
    payload.set_payload_type(payload_type);
    payload.set_payload_length(payload_value.len() as u8);
    payload.set_payload_value(payload_value);
    payload
}

pub fn create_icce_body(message_id: u8, command_id: u8, payloads: &[Payload]) -> Body {
    let mut body = Body::new();
    body.set_message_id(message_id);
    body.set_command_id(command_id);
    for payload in payloads {
        body.set_payload(payload.to_owned());
    }
    body
}

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
    payload.append(&mut reader_type.clone().to_vec());
    payload.push(0x9F);
    payload.push(0x1E);
    payload.push(reader_id.len() as u8);
    payload.append(&mut reader_id.clone().to_vec());
    payload.push(0x9F);
    payload.push(0x37);
    payload.push(reader_rnd.len() as u8);
    payload.append(&mut reader_rnd.clone().to_vec());
    payload.push(0x9F);
    payload.push(0x0C);
    payload.push(reader_key_parameter.len() as u8);
    payload.append(&mut reader_key_parameter.clone().to_vec());
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
    let mut session_iv = Vec::new();
    let mut session_key = Vec::new();
    let mut card_atc = Vec::new();

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
                    card_seid.append(&mut value.clone().to_vec());
                } else if payload[index] == 0x9F && payload[index+1] == 0x3B {
                    index += 2;
                    let length = payload[index] as usize;
                    index += 1;
                    let value = &payload[index..index+length];
                    index += length;
                    card_id.append(&mut value.clone().to_vec());
                } else if payload[index] == 0x9F && payload[index+1] == 0x3E {
                    index += 2;
                    let length = payload[index] as usize;
                    index += 1;
                    let value = &payload[index..index+length];
                    index += length;
                    card_rnd.append(&mut value.clone().to_vec());
                } else if payload[index] == 0x9F && payload[index+1] == 0x05 {
                    index += 2;
                    let length = payload[index] as usize;
                    index += 1;
                    let value = &payload[index..index+length];
                    index += length;
                    card_info1.append(&mut value.clone().to_vec());
                } else if payload[index] == 0x73 {
                    index += 1;
                    let value = &payload[index..payload.len()-2];
                    index = payload.len() - 2;
                    encrypted_text.append(&mut value.clone().to_vec());
                }
            }
            if card_rnd.len() == 0 || reader_rnd.len() == 0 || card_seid.len() == 0 || card_id.len() == 0 {
                println!("Cannot calculate session IV and session Key");
                return Err("Cannot calculate session IV or session Key".to_string());
            }
            session_iv = carkey_icce_crypto::calculate_session_iv(reader_rnd, &card_rnd);
            let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
            let card_iv = carkey_icce_crypto::get_card_iv();
            session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter)?;
            let decrypted_text = carkey_icce_crypto::decrypt_with_session_key(&session_key, &session_iv, &encrypted_text)?;
            index = 0;
            while index < decrypted_text.len() {
                if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x36 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let value = &decrypted_text[index..index+length];
                    index += length;
                    card_atc.append(&mut value.clone().to_vec());
                } else if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x37 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let _value = &decrypted_text[index..index+length];
                    index += length;
                }
            }
            return Ok((session_key, session_iv, card_atc, card_rnd));
        } else {
            return Err("Invalid Payload Label".to_string());
        }
    } else {
        return Err("Response is not correct".to_string());
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
    data_domain.append(&mut card_atc.clone().to_vec());
    data_domain.push(0x9F);
    data_domain.push(0x0A);
    data_domain.push(reader_auth_parameter.len() as u8);
    data_domain.append(&mut reader_auth_parameter.clone().to_vec());
    data_domain.push(0x9F);
    data_domain.push(0x3E);
    data_domain.push(card_rnd.len() as u8);
    data_domain.append(&mut card_rnd.clone().to_vec());
    let encrypt_data = carkey_icce_crypto::encrypt_with_session_key(session_key, session_iv, &data_domain)?;

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
            let decrypted_text = carkey_icce_crypto::decrypt_with_session_key(session_key, session_iv, &payload[1..payload.len()-2])?;
            let mut index = 0;
            while index < decrypted_text.len() {
                if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x31 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let value = &decrypted_text[index..index+length];
                    index += length;
                    card_auth_parameter.append(&mut value.clone().to_vec());
                } else if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x0A {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let value = &decrypted_text[index..index+length];
                    index += length;
                    reader_auth_parameter.append(&mut value.clone().to_vec());
                } else if decrypted_text[index] == 0x9F && decrypted_text[index+1] == 0x37 {
                    index += 2;
                    let length = decrypted_text[index] as usize;
                    index += 1;
                    let _value = &decrypted_text[index..index+length];
                    index += length;
                }
            }
            return Ok((card_auth_parameter, reader_auth_parameter))
        } else {
            return Err("Invalid Payload Label".to_string());
        }
    } else {
        return Err("Response is not correct".to_string());
    }
}

pub fn create_icce_auth_request(apdu: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+2+apdu.len() as u16);
    icce.set_header(header);

    let payload = create_icce_body_payload(0x01, apdu);
    let body = create_icce_body(0x01, 0x01, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_auth_response(status: u8, apdu: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+2+apdu.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let apdu_payload = create_icce_body_payload(0x01, apdu);
    let body = create_icce_body(0x01, 0x01, &[status_payload, apdu_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_measure_request(mesaure_type: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let measure_payload = create_icce_body_payload(0x01, &[mesaure_type]);
    let body = create_icce_body(0x02, 0x01, &[measure_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_measure_response(status: u8, timeout: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+2+timeout.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let timeout_payload = create_icce_body_payload(0x01, timeout);
    let body = create_icce_body(0x02, 0x01, &[status_payload, timeout_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_anti_relay_request(measure_type: u8, vehicle_info: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+3+2+vehicle_info.len() as u16);
    icce.set_header(header);

    let measure_payload = create_icce_body_payload(0x01, &[measure_type]);
    let vehicle_info_payload = create_icce_body_payload(0x02, vehicle_info);
    let body = create_icce_body(0x02, 0x02, &[measure_payload, vehicle_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_anti_relay_response(status: u8, check_result: u8, device_info: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+3+2+device_info.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let check_result_payload = create_icce_body_payload(0x01, &[check_result]);
    let device_info_payload = create_icce_body_payload(0x02, device_info);
    let body = create_icce_body(0x02, 0x02, &[status_payload, check_result_payload, device_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_control_request(rke_type: u8, rke_cmd: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, true, false, 0, 0, 4+2+rke_cmd.len() as u16);
    icce.set_header(header);

    let rke_cmd_payload = create_icce_body_payload(rke_type, rke_cmd);
    let body = create_icce_body(0x02, 0x03, &[rke_cmd_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_control_response(status: u8, rke_result: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, true, false, 0, 0, 4+3+2+rke_result.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let rke_result_payload = create_icce_body_payload(0x01, rke_result);
    let body = create_icce_body(0x02, 0x03, &[status_payload, rke_result_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_challege_request(rke_type: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let rke_type_payload = create_icce_body_payload(0x01, &[rke_type]);
    let body = create_icce_body(0x02, 0x04, &[rke_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_challege_response(status: u8, random_value: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+2+random_value.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let random_value_payload = create_icce_body_payload(0x01, random_value);
    let body = create_icce_body(0x02, 0x04, &[status_payload, random_value_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_vehicle_info_request(request_type: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let request_type_payload = create_icce_body_payload(0x01, &[request_type]);
    let body = create_icce_body(0x02, 0x05, &[request_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_vehicle_info_response(status: u8, vehicle_info: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+2+vehicle_info.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let vehicle_info_payload = create_icce_body_payload(0x01, vehicle_info);
    let body = create_icce_body(0x02, 0x05, &[status_payload, vehicle_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_mobile_info_request(request_type: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let request_type_payload = create_icce_body_payload(0x01, &[request_type]);
    let body = create_icce_body(0x02, 0x06, &[request_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_mobile_info_response(status: u8, mobile_info: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+2+mobile_info.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let mobile_info_payload = create_icce_body_payload(0x01, mobile_info);
    let body = create_icce_body(0x02, 0x06, &[status_payload, mobile_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_calibrate_clock_request() -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4);
    icce.set_header(header);

    let body = create_icce_body(0x02, 0x07, &[]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_calibrate_clock_response(status: u8, clock: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+2+clock.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let clock_payload = create_icce_body_payload(0x01, clock);
    let body = create_icce_body(0x02, 0x07, &[status_payload, clock_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_protocol_request(protocol: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+2+protocol.len() as u16);
    icce.set_header(header);

    let protocol_payload = create_icce_body_payload(0x01, protocol);
    let body = create_icce_body(0x02, 0x08, &[protocol_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_protocol_response(status: u8, protocol: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3+2+protocol.len() as u16);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let protocol_payload = create_icce_body_payload(0x01, protocol);
    let body = create_icce_body(0x02, 0x08, &[status_payload, protocol_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_state_event_request(mobile_event: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let mobile_event_payload = create_icce_body_payload(0x01, &[mobile_event]);
    let body = create_icce_body(0x03, 0x01, &[mobile_event_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_state_event_response(status: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let body = create_icce_body(0x03, 0x01, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_state_event_request(vehicle_event: u8, async_result: &[u8], vehicle_state: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+3+2+async_result.len() as u16 + 2+vehicle_state.len() as u16);
    icce.set_header(header);

    let vehicle_event_payload = create_icce_body_payload(0x01, &[vehicle_event]);
    let async_result_payload = create_icce_body_payload(0x02, async_result);
    let vehicle_state_payload = create_icce_body_payload(0x03, vehicle_state);
    let body = create_icce_body(0x03, 0x02, &[vehicle_event_payload, async_result_payload, vehicle_state_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_state_event_response(status: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let body = create_icce_body(0x03, 0x02, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_app_event_request(data: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = create_icce_body_payload(0x01, data);
    let body = create_icce_body(0x03, 0x03, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_app_event_response(status: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let body = create_icce_body(0x03, 0x03, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_server_event_request(data: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = create_icce_body_payload(0x01, data);
    let body = create_icce_body(0x03, 0x04, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_server_event_response(status: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let body = create_icce_body(0x03, 0x04, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_to_vehicle_event_request(data: &[u8]) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = create_icce_body_payload(0x01, data);
    let body = create_icce_body(0x03, 0x05, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_to_vehicle_event_response(status: u8) -> ICCE {
    let mut icce = ICCE::new();

    let header = create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = create_icce_body_payload(0x00, &[status]);
    let body = create_icce_body(0x03, 0x05, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn handle_icce_mobile_request(icce_object: &ICCE) -> Result<Vec<u8>> {
    let response = Vec::new();

    Ok(response)
}

fn handle_icce_auth_response(body: &Body) -> Result<Vec<u8>> {
    let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let reader_auth_parameter = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
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
                if let Ok((session_key, session_iv, card_atc, card_rnd)) = handle_auth_get_process_data_response_payload(&value, &reader_rnd, &reader_key_parameter) {
                    SESSION_KEY.lock().unwrap().copy_from_slice(&session_key.as_slice());
                    SESSION_IV.lock().unwrap().copy_from_slice(&session_iv.as_slice());
                    CARD_ATC.lock().unwrap().copy_from_slice(&card_atc.as_slice());
                    let auth_request_payload = create_auth_auth_payload(&card_atc, &reader_auth_parameter, &card_rnd, &session_key, &session_iv)?;
                    println!("Sending Auth Request......");
                    response.append(&mut create_icce_auth_request(&auth_request_payload).serialize());
                    return Ok(response)
                } else {
                    return Err("ICCE Auth Response Status Error".to_string());
                }
            } else {
                //sending auth auth response
                if let Ok((card_auth_parameter, reader_auth_parameter)) = handle_auth_auth_response_payload(value, &reader_rnd, &SESSION_KEY.lock().unwrap().to_vec(), &SESSION_IV.lock().unwrap().to_vec()) {
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
pub fn handle_icce_mobile_response(icce_object: &ICCE) -> Result<Vec<u8>> {
    let _header = icce_object.get_header();
    let body = icce_object.get_body();
    match body.get_message_id() {
        0x01 => {
            match body.get_command_id() {
                0x01 => {
                    return handle_icce_auth_response(body);
                },
                _ => {
                    return Err("RFU".to_string());
                }
            }
        },
        0x02 => {
            return Err("RFU".to_string());
        },
        0x03 => {
            return Err("RFU".to_string());
        },
        _ => {
            return Err("RFU".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_default() {
        let control = Control::new();
        assert_eq!(control.0, 0b0000_0000);
    }
    #[test]
    fn test_control_request() {
        let mut control = Control::new();
        control.set_request();
        assert_eq!(control.0, 0b0001_0000);
    }
    #[test]
    fn test_control_response() {
        let mut control = Control::new();
        control.set_response();
        assert_eq!(control.0, 0b0000_0000);
    }
    #[test]
    fn test_control_crypto() {
        let mut control = Control::new();
        control.set_crypto();
        assert_eq!(control.0, 0b0000_1000);
    }
    #[test]
    fn test_control_no_crypto() {
        let mut control = Control::new();
        control.set_no_crypto();
        assert_eq!(control.0, 0b0000_0000);
    }
    #[test]
    fn test_control_async() {
        let mut control = Control::new();
        control.set_async();
        assert_eq!(control.0, 0b0000_0100);
    }
    #[test]
    fn test_control_sync() {
        let mut control = Control::new();
        control.set_sync();
        assert_eq!(control.0, 0b0000_0000);
    }
    #[test]
    fn test_control_no_frag() {
        let mut control = Control::new();
        control.set_no_frag();
        assert_eq!(control.0, 0b0000_0000);
    }
    #[test]
    fn test_control_first_frag() {
        let mut control = Control::new();
        control.set_first_frag();
        assert_eq!(control.0, 0b0000_0001);
    }
    #[test]
    fn test_control_conti_frag() {
        let mut control = Control::new();
        control.set_conti_frag();
        assert_eq!(control.0, 0b0000_0010);
    }
    #[test]
    fn test_control_last_frag() {
        let mut control = Control::new();
        control.set_last_frag();
        assert_eq!(control.0, 0b0000_0011);
    }
    #[test]
    fn test_control_request_and_crypto() {
        let mut control = Control::new();
        control.set_request();
        control.set_crypto();
        assert_eq!(control.0, 0b0001_1000);
    }
    #[test]
    fn test_control_request_and_crypto_and_async() {
        let mut control = Control::new();
        control.set_request();
        control.set_crypto();
        control.set_async();
        assert_eq!(control.0, 0b0001_1100);
    }
    #[test]
    fn test_control_request_and_crypto_and_async_and_first_frag() {
        let mut control = Control::new();
        control.set_request();
        control.set_crypto();
        control.set_async();
        control.set_first_frag();
        assert_eq!(control.0, 0b0001_1101);
    }
    #[test]
    fn test_control_request_and_crypto_and_async_and_conti_frag() {
        let mut control = Control::new();
        control.set_request();
        control.set_crypto();
        control.set_async();
        control.set_conti_frag();
        assert_eq!(control.0, 0b0001_1110);
    }
    #[test]
    fn test_control_request_and_crypto_and_async_and_last_frag() {
        let mut control = Control::new();
        control.set_request();
        control.set_crypto();
        control.set_async();
        control.set_last_frag();
        assert_eq!(control.0, 0b0001_1111);
    }
    #[test]
    fn test_control_bit_encode() {
        let mut control = Control::new();
        control.set_request();
        let encoded = control.serialize();
        assert_eq!(encoded, vec![0x10]);
    }
    #[test]
    fn test_control_bit_decode() {
        let mut control = Control::new();
        control.set_request();
        control.set_crypto();
        let encoded_control = control.serialize();
        let decoded_control = Control::deserialize(&encoded_control).unwrap();
        assert_eq!(decoded_control.0, 0b0001_1000);
    }
    #[test]
    fn test_header_base() {
        let mut header = Header::new();
        header.set_sof(0x5A);
        header.set_length(0x0A);
        let mut control = Control::new();
        control.set_request();
        header.set_control(control);
        header.set_fsn(0x00);
        assert_eq!(header,
        Header {
            sof: 0x5A,
            length: 0x0A,
            control: Control::from(0b0001_0000),
            fsn: 0x00,
        });
    }
    #[test]
    fn test_header_serialaized() {
        let mut header = Header::new();
        header.set_sof(0x5A);
        header.set_length(0x0A);
        let mut control = Control::new();
        control.set_request();
        header.set_control(control);
        header.set_fsn(0x00);
        let serialized_header = header.serialize();
        assert_eq!(serialized_header, vec![0x5A, 0x0A, 0x00, 0x10, 0x00]);
    }
    #[test]
    fn test_header_deserialized() {
        let mut header = Header::new();
        header.set_sof(0x5A);
        header.set_length(0x0A);
        let mut control = Control::new();
        control.set_request();
        header.set_control(control);
        header.set_fsn(0x00);
        let serialized_header = header.serialize();
        let deserialized_header = Header::deserialize(&serialized_header).unwrap();
        assert_eq!(deserialized_header,
        Header {
            sof: 0x5A,
            length: 0x0A,
            control: Control::from(0b0001_0000),
            fsn: 0x00,
        });
    }
    #[test]
    fn test_payload_base() {
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        let value = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        payload.set_payload_value(&value);
        assert_eq!(payload,
        Payload {
            payload_type: 0x01,
            payload_length: 0x06,
            payload_value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        });
    }
    #[test]
    fn test_payload_with_empty_value() {
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        assert_eq!(payload,
        Payload {
            payload_type: 0x01,
            payload_length: 0x06,
            payload_value: vec![],
        });
    }
    #[test]
    fn tset_payload_serialized_and_deserialized() {
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        let value = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        payload.set_payload_value(&value);

        let serialized_payload = payload.serialize();
        let deserialized_payload: Payload = Payload::deserialize(&serialized_payload).unwrap();
        assert_eq!(deserialized_payload, 
        Payload {
            payload_type: 0x01,
            payload_length: 0x06,
            payload_value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        });
    }
    #[test]
    fn test_body_base() {
        let mut body = Body::new();
        body.set_message_id(0x01);
        body.set_command_id(0x02);
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        let value = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        payload.set_payload_value(&value);
        body.set_payload(payload);
        assert_eq!(body,
        Body {
            message_id: 0x01,
            command_id: 0x02,
            payloads: vec![
                Payload {
                    payload_type: 0x01,
                    payload_length: 0x06,
                    payload_value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                }
            ]
        });
    }
    #[test]
    fn test_body_with_two_payloads() {
        let mut body = Body::new();
        body.set_message_id(0x01);
        body.set_command_id(0x02);
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        let value = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        payload.set_payload_value(&value);
        body.set_payload(payload);
        let mut payload2 = Payload::new();
        payload2.set_payload_type(0x02);
        payload2.set_payload_length(0x04);
        let value2 = vec![0x01, 0x02, 0x03, 0x04];
        payload2.set_payload_value(&value2);
        body.set_payload(payload2);
        assert_eq!(body,
        Body {
            message_id: 0x01,
            command_id: 0x02,
            payloads: vec![
                Payload {
                    payload_type: 0x01,
                    payload_length: 0x06,
                    payload_value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                },
                Payload {
                    payload_type: 0x02,
                    payload_length: 0x04,
                    payload_value: vec![0x01, 0x02, 0x03, 0x04],
                }
            ],
        });
    }
    #[test]
    fn test_body_serialized_and_deserialized() {
        let mut body = Body::new();
        body.set_message_id(0x01);
        body.set_command_id(0x02);
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        let value = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        payload.set_payload_value(&value);
        body.set_payload(payload);
        let mut payload2 = Payload::new();
        payload2.set_payload_type(0x02);
        payload2.set_payload_length(0x04);
        let value2 = vec![0x01, 0x02, 0x03, 0x04];
        payload2.set_payload_value(&value2);
        body.set_payload(payload2);
        
        let serialized_body = body.serialize();
        let deserialized_body: Body = Body::deserialize(&serialized_body).unwrap();
        assert_eq!(deserialized_body,
        Body {
            message_id: 0x01,
            command_id: 0x02,
            payloads: vec![
                Payload {
                    payload_type: 0x01,
                    payload_length: 0x06,
                    payload_value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                },
                Payload {
                    payload_type: 0x02,
                    payload_length: 0x04,
                    payload_value: vec![0x01, 0x02, 0x03, 0x04],
                }
            ]
        });
    }
    #[test]
    fn test_icce_base() {
        let mut icce = ICCE::new();
        let mut header = Header::new();
        header.set_sof(0x5A);
        let mut control = Control::new();
        control.set_request();
        header.set_control(control);
        header.set_fsn(0x00);
        header.set_length(2+2+1+1+6);
        let mut body = Body::new();
        body.set_message_id(0x01);
        body.set_command_id(0x02);
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        let value: Vec<u8>= vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        payload.set_payload_value(&value);
        body.set_payload(payload);
        icce.set_header(header);
        icce.set_body(body);
        icce.calculate_checksum();
        assert_eq!(icce,
        ICCE {
            header: Header {
                sof: 0x5A,
                length: 0x0C,
                control: Control::from(0x10),
                fsn: 0x00,
            },
            body: Body {
                message_id: 0x01,
                command_id: 0x02,
                payloads: vec![
                    Payload {
                        payload_type: 0x01,
                        payload_length: 0x06,
                        payload_value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                    }
                ],
            },
            checksum: 0xF79A,
        });
    }
    #[test]
    fn test_icce_serialize_and_deserialize() {
        let mut icce = ICCE::new();
        let mut header = Header::new();
        header.set_sof(0x5A);
        let mut control = Control::new();
        control.set_request();
        header.set_control(control);
        header.set_fsn(0x00);
        header.set_length(2+2+1+1+6);
        let mut body = Body::new();
        body.set_message_id(0x01);
        body.set_command_id(0x02);
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        payload.set_payload_length(0x06);
        let value: Vec<u8>= vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        payload.set_payload_value(&value);
        body.set_payload(payload);
        icce.set_header(header);
        icce.set_body(body);
        icce.calculate_checksum();

        let serialized_icce = icce.serialize();
        let deserialized_icce = ICCE::deserialize(&serialized_icce).unwrap();
        assert_eq!(deserialized_icce,
        ICCE {
            header: Header {
                sof: 0x5A,
                length: 0x0C,
                control: Control::from(0x10),
                fsn: 0x00,
            },
            body: Body {
                message_id: 0x01,
                command_id: 0x02,
                payloads: vec![
                    Payload {
                        payload_type: 0x01,
                        payload_length: 0x06,
                        payload_value: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                    }
                ],
            },
            checksum: 0xF79A,
        });
    }
    #[test]
    fn test_calculate_dkey() {
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let card_id = vec![0x07, 0x08, 0x9, 0x0a, 0x0b, 0x0c];
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        assert_eq!(dkey, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
    }
    #[test]
    fn test_get_card_iv() {
        let card_iv = carkey_icce_crypto::get_card_iv();
        assert_eq!(card_iv, vec![0x00; 16]);
    }
    #[test]
    fn test_calculate_session_iv() {
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        assert_eq!(session_iv, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }
    #[test]
    fn test_calculate_session_key() {
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let card_id = vec![0x07, 0x08, 0x9, 0x0a, 0x0b, 0x0c];
        let reader_key_parameter = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        let card_iv = carkey_icce_crypto::get_card_iv();

        let session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();
        assert_eq!(session_key.len(), 16);
    }
    #[test]
    fn test_encrypt_and_decrypt_with_session_key() {
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let card_id = vec![0x07, 0x08, 0x9, 0x0a, 0x0b, 0x0c];
        let reader_key_parameter = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        let card_iv = carkey_icce_crypto::get_card_iv();

        let session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let plain_text = b"Hello,World";
        let encrypt_text = carkey_icce_crypto::encrypt_with_session_key(&session_key, &session_iv, plain_text).unwrap();
        let decrypt_text = carkey_icce_crypto::decrypt_with_session_key(&session_key, &session_iv, &encrypt_text).unwrap();
        assert_eq!(decrypt_text, plain_text);
    }
    #[test]
    fn test_create_icce_auth_request() {
        let apdu = vec![0x01, 0x02, 0x03, 0x04];
        let icce = create_icce_auth_request(&apdu);
        assert_eq!(icce, ICCE {
            header: Header {
                sof: 0x5A,
                length: 0x0a,
                control: Control::from(0x10),
                fsn: 0x00,
            },
            body: Body {
                message_id: 0x01,
                command_id: 0x01,
                payloads: vec![
                    Payload {
                        payload_type: 0x01,
                        payload_length: 0x04,
                        payload_value: vec![0x01, 0x02, 0x03, 0x04],
                    }
                ],
            },
            checksum: 0x5237,
        })
    }
    #[test]
    fn test_create_icce_auth_response() {
        let status = 0x00;
        let apdu = vec![0x01, 0x02, 0x03, 0x04];
        let icce = create_icce_auth_response(status, &apdu);
        assert_eq!(icce, ICCE {
            header: Header {
                sof: 0x5A,
                length: 0x0D,
                control: Control::from(0x00),
                fsn: 0x00,
            },
            body: Body {
                message_id: 0x01,
                command_id: 0x01,
                payloads: vec![
                    Payload {
                        payload_type: 0x00,
                        payload_length: 0x01,
                        payload_value: vec![0x00],
                    },
                    Payload {
                        payload_type: 0x01,
                        payload_length: 0x04,
                        payload_value: vec![0x01, 0x02, 0x03, 0x04],
                    }
                ],
            },
            checksum: 0xB7B5,
        });
    }
    #[test]
    fn test_auth_get_process_data_payload() {
        let reader_type = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let reader_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xe, 0x0f, 0x00];
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let auth_get_process_data_payload = create_auth_get_process_data_payload(&reader_type, &reader_id, &reader_rnd, &reader_key_parameter);

        assert_eq!(auth_get_process_data_payload,
            vec![128, 202, 0, 0, 50, 159, 53, 6, 1, 2, 3, 4, 5, 6, 159, 30, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0,
            159, 55, 8, 1, 2, 3, 4, 5, 6, 7, 8, 159, 12, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
    }
    #[test]
    fn test_auth_handle_get_process_data_reponse_payload() {
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_id = vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let card_info1 = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let card_atc = vec![0x01, 0x02, 0x03, 0x04];
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        let card_iv = carkey_icce_crypto::get_card_iv();
        let session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

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
        let encrypted_text = carkey_icce_crypto::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

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
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_auth_parameter = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_id = vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let card_atc = vec![0x01, 0x02, 0x03, 0x04];

        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        let card_iv = carkey_icce_crypto::get_card_iv();
        let session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let payload = create_auth_auth_payload(&card_atc, &reader_auth_parameter, &card_rnd, &session_key, &session_iv).unwrap();

        assert_eq!(payload,
            vec![128, 128, 0, 0, 33, 119, 86, 205, 242, 220, 61, 119, 151, 140, 149, 3, 130, 196, 200, 99, 67, 64, 73, 4, 45, 60, 103, 26, 89, 18, 242, 190, 141, 240, 186, 136, 123, 236, 0]);
    }
    #[test]
    fn test_auth_auth_response_payload() {
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_id = vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let card_auth_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_auth_parameter = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        let card_iv = carkey_icce_crypto::get_card_iv();
        let session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

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
        let encrypted_text = carkey_icce_crypto::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

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
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_id = vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let card_info1 = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let card_atc = vec![0x01, 0x02, 0x03, 0x04];
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        let card_iv = carkey_icce_crypto::get_card_iv();
        let session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

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
        let encrypted_text = carkey_icce_crypto::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        let icce = create_icce_auth_response(0x00, &payload);
    }
    #[test]
    fn test_create_auth_auth_response_payload() {
        let card_seid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_id = vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let card_rnd = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let card_auth_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let reader_auth_parameter = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

        let session_iv = carkey_icce_crypto::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = carkey_icce_crypto::calculate_dkey(&card_seid, &card_id);
        let card_iv = carkey_icce_crypto::get_card_iv();
        let session_key = carkey_icce_crypto::calculate_sesion_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

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
        let encrypted_text = carkey_icce_crypto::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();

        payload.append(&mut encrypted_text.clone().to_vec());
        payload.push(0x90);
        payload.push(0x00);

        let icce = create_icce_auth_response(0x00, &payload);
    }
    #[test]
    fn test_create_rke_control_request() {
        let rke_type = 0x01;
        let rke_cmd = vec![0x01, 0x02, 0x03, 0x04];

        let icce = create_icce_rke_control_request(rke_type, &rke_cmd);
        println!("RKE Command ICCE is {:02X?}", icce.serialize());
        println!("RKE Command is {:?}", icce);

        let decrypted_icce = ICCE::deserialize(&icce.serialize()).unwrap();
        println!("decrypted_icce is {:?}", decrypted_icce);
    }
}
