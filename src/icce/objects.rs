use std::sync::Mutex;

use crc16::CCITT_FALSE;

use crate::icce::aes128;

type Result<T> = std::result::Result<T, String>;

lazy_static! {
    static ref BLE_DEFAULT_MTU: u16 = 500;
    static ref SESSION_KEY: Mutex<[u8; 16]> = Mutex::new([0; 16]);
    static ref SESSION_IV: Mutex<[u8; 16]> = Mutex::new([0; 16]);
    static ref CARD_ATC: Mutex<[u8; 4]> = Mutex::new([0; 4]);
    static ref ICCE_FRAGMENTS: Mutex<Vec<ICCE>> = Mutex::new(Vec::new());
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
    pub fn is_no_frag(&self) -> bool {
        if self.0 & 0b0000_0011 == 0b0000_0000 {
            true
        } else {
            false
        }
    }
    pub fn is_first_frag(&self) -> bool {
        if self.0 & 0b0000_0001 == 0b0000_0001 {
            true
        } else {
            false
        }
    }
    pub fn is_conti_frag(&self) -> bool {
        if self.0 & 0b0000_0010 == 0b0000_0010 {
            true
        } else {
            false
        }
    }
    pub fn is_last_frag(&self) -> bool {
        if self.0 & 0b0000_0011 == 0b0000_0011 {
            true
        } else {
            false
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
    payload_length: usize,
    payload_value: Vec<u8>,
}

impl Payload {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_payload_type(&mut self, payload_type: u8) {
        self.payload_type = payload_type;
    }
    pub fn set_payload_length(&mut self, payload_length: usize) {
        self.payload_length = payload_length;
    }
    pub fn set_payload_value(&mut self, payload_value: &[u8]) {
        self.payload_value = payload_value.to_vec();
    }
    pub fn get_payload_type(&self) -> u8 {
        self.payload_type
    }
    pub fn get_payload_length(&self) -> usize {
        self.payload_length
    }
    pub fn get_payload_value(&self) -> &[u8] {
        &self.payload_value
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        serialized_data.push(self.payload_type);
        if self.payload_length >= 255 {
            serialized_data.push(0xFF);
            serialized_data.push((self.payload_length >> 8) as u8);
        }
        serialized_data.push(self.payload_length as u8);
        serialized_data.append(&mut self.payload_value.to_vec());

        serialized_data
    }
    pub fn deserialize(byte_stream: &[u8]) -> Result<Self> {
        if byte_stream.len() < 2 || byte_stream.len() < 2 + byte_stream[1] as usize {
            return Err("Invalid byte stream length".to_string());
        }
        let mut payload = Payload::new();
        payload.set_payload_type(byte_stream[0]);
        let mut value_offset = 2;
        if byte_stream[1] == 0xFF {
            let mut ret = 0;
            for i in 2..4 {
                let x = byte_stream[i];
                ret = ret << 8 | usize::from(x);
            }
            payload.set_payload_length(ret);
            value_offset = 4;
        } else {
            payload.set_payload_length(usize::from(byte_stream[1]));
        }
        payload.set_payload_value(&byte_stream[value_offset..value_offset+payload.payload_length]);

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
    pub fn serialize(&self, frag_flag: bool) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        if frag_flag == false {
            serialized_data.push(self.message_id);
            serialized_data.push(self.command_id);
            self.payloads.iter().for_each(|payload| {
                serialized_data.append(&mut payload.serialize().to_vec());
            });
        } else {
            serialized_data.append(&mut self.payloads[0].get_payload_value().to_vec());
        }

        serialized_data
    }
    pub fn deserialize(byte_stream: &[u8], frag_flag: bool) -> Result<Self> {
        if byte_stream.len() < 2 {
            return Err("Invalid byte stream length".to_string());
        }
        let mut body = Body::new();
        if frag_flag == false {
            body.set_message_id(byte_stream[0]);
            body.set_command_id(byte_stream[1]);
            let mut index = 2;
            while index < byte_stream.len() {
                let payload = Payload::deserialize(&byte_stream[index..])?;
                index = index + 2 + payload.payload_length as usize;
                body.set_payload(payload);
            }
        } else {
            let mut payload = Payload::new();
            payload.set_payload_length(byte_stream.len());
            payload.set_payload_value(byte_stream);
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
        let frag_flag = self.get_header().get_control().is_conti_frag() || self.get_header().get_control().is_last_frag();
        let crc16_body = self.body.serialize(frag_flag);
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
        let frag_flag = self.get_header().get_control().is_conti_frag() || self.get_header().get_control().is_last_frag();
        if self.get_header().get_control().is_crypto() == false {
            serialized_data.append(&mut self.header.serialize());
            serialized_data.append(&mut self.body.serialize(frag_flag));
            serialized_data.append(&mut self.checksum.to_le_bytes().to_vec());
        } else {
            //handle body encrypt
            let mut plain_text = Vec::new();
            plain_text.append(&mut self.body.serialize(frag_flag));
            let encrypted_text = aes128::encrypt_with_session_key(
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
        let frag_flag = icce.get_header().get_control().is_conti_frag() || icce.get_header().get_control().is_last_frag();
        if icce.get_header().get_control().is_crypto() == false {
            icce.set_body(Body::deserialize(&byte_stream[5..byte_stream.len()-2], frag_flag)?);
            let checksum_bytes: [u8; 2] = [byte_stream[byte_stream.len()-2], byte_stream[byte_stream.len()-1]];
            icce.set_checksum(u16::from_le_bytes(checksum_bytes));
        } else {
            let mut new_header = Header::new();
            new_header.set_sof(0x5A);
            new_header.set_control(icce.get_header().get_control());
            new_header.set_fsn(icce.get_header().get_fsn());

            let encrypted_text = &byte_stream[5..byte_stream.len()-2];
            let plain_text = aes128::decrypt_with_session_key(
                &SESSION_KEY.lock().unwrap().to_vec(),
                &SESSION_IV.lock().unwrap().to_vec(),
                encrypted_text)?;
            new_header.set_length(2 + plain_text.len() as u16);
            icce.set_header(new_header);

            icce.set_body(Body::deserialize(&plain_text, frag_flag)?);
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
    payload.set_payload_length(payload_value.len());
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

pub fn is_session_key_valid() -> bool {
    let session_key = SESSION_KEY.lock().unwrap().to_vec();
    if session_key.ne(&[0u8; 16]) {
        true
    } else {
        false
    }
}

pub fn update_session_key(key: &[u8]) {
    let mut session_key = SESSION_KEY.lock().unwrap();
    session_key.copy_from_slice(key);
}

pub fn update_session_iv(iv: &[u8]) {
    let mut session_iv = SESSION_IV.lock().unwrap();
    session_iv.copy_from_slice(iv);
}

pub fn update_card_atc(atc: &[u8]) {
    let mut card_atc = CARD_ATC.lock().unwrap();
    card_atc.copy_from_slice(atc);
}

pub fn get_session_key() -> Vec<u8> {
    SESSION_KEY.lock().unwrap().to_vec()
}

pub fn get_session_iv() -> Vec<u8> {
    SESSION_IV.lock().unwrap().to_vec()
}

pub fn collect_icce_fragments(icce: ICCE) {
    let mut icce_fragments = ICCE_FRAGMENTS.lock().unwrap();
    icce_fragments.push(icce);
}

pub fn reassemble_icce_fragments() -> ICCE {
    let mut icce = ICCE::new();
    let mut icce_fragments = ICCE_FRAGMENTS.lock().unwrap();
    icce_fragments.sort_by(|a, b| a.get_header().get_fsn().cmp(&b.get_header().get_fsn()));
    let mut total_length: u16 = 0x0000;
    for (index, tmp_icce) in icce_fragments.iter().enumerate() {
        if index == 0 {
            let mut header = Header::new();
            header.set_sof(0x5A);
            header.set_control(tmp_icce.get_header().get_control());
            header.control.set_no_frag();
            header.set_fsn(0x00);
            icce.set_header(header);
            let mut payload = Payload::new();
            payload.set_payload_type(tmp_icce.body.get_payloads()[0].get_payload_type());
            payload.set_payload_length(tmp_icce.body.get_payloads()[0].get_payload_length());
            payload.set_payload_value(tmp_icce.get_body().get_payloads()[0].get_payload_value());
            let mut body = Body::new();
            body.set_message_id(tmp_icce.get_body().get_message_id());
            body.set_command_id(tmp_icce.get_body().get_command_id());
            body.set_payload(payload);
            icce.set_body(body);
            total_length += 4 + 1 + tmp_icce.body.get_payloads()[0].get_payload_value().len() as u16;
        } else {
            let mut src_value = tmp_icce.get_body().get_payloads()[0].get_payload_value().to_vec();
            icce.body.payloads[0].payload_value.append(&mut src_value);
            icce.body.payloads[0].payload_length += tmp_icce.body.get_payloads()[0].get_payload_value().len();
            total_length += tmp_icce.body.get_payloads()[0].get_payload_value().len() as u16;

        }
    }
    if total_length - 5 >= 255 {
        total_length += 3
    } else {
        total_length += 1
    }
    icce.header.set_length(total_length);
    icce.calculate_checksum();
    icce_fragments.clear();
    icce
}

pub fn split_icce(icce: &ICCE) -> Option<Vec<ICCE>> {
    if icce.get_header().get_length() + 5 < *BLE_DEFAULT_MTU {
        return None
    }
    let mut splitted_icce = Vec::new();
    let mut position = 0x00;
    let mut fsn = 0x00;
    let total_payload_length = icce.get_header().get_length() - 4 - 1 - 3;
    loop {
        let mut tmp_icce = ICCE::new();
        tmp_icce.header.set_sof(icce.get_header().sof);
        tmp_icce.header.set_control(icce.get_header().get_control());
        let payload_length = if position == 0x00 {
            tmp_icce.header.control.set_first_frag();
            *BLE_DEFAULT_MTU - 13
        } else if position + *BLE_DEFAULT_MTU - 7 < total_payload_length {
            tmp_icce.header.control.set_conti_frag();
            *BLE_DEFAULT_MTU - 7
        } else {
            tmp_icce.header.control.set_last_frag();
            total_payload_length - position
        };
        let total_payload = icce.get_body().get_payloads()[0].get_payload_value().to_vec();
        if position == 0x00 {
            tmp_icce.header.set_length(payload_length + 8);
            tmp_icce.header.set_fsn(fsn);
            fsn += 1;
            tmp_icce.body.set_message_id(icce.get_body().get_message_id());
            tmp_icce.body.set_command_id(icce.get_body().get_command_id());
            let mut payload = Payload::new();
            payload.set_payload_type(icce.body.get_payloads()[0].get_payload_type());
            payload.set_payload_length(payload_length as usize);
            payload.set_payload_value(&total_payload[position as usize ..(position+payload_length) as usize]);
            tmp_icce.body.set_payload(payload);
        } else {
            tmp_icce.header.set_length(payload_length + 2);
            tmp_icce.header.set_fsn(fsn);
            fsn += 1;
            let mut payload = Payload::new();
            payload.set_payload_value(&total_payload[position as usize .. (position + payload_length) as usize]);
            tmp_icce.body.set_payload(payload);
        }
        tmp_icce.calculate_checksum();
        splitted_icce.push(tmp_icce);
        position += payload_length;
        if position == total_payload_length {
            break;
        }
    }
    Some(splitted_icce)
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
        
        let serialized_body = body.serialize(false);
        let deserialized_body: Body = Body::deserialize(&serialized_body, false).unwrap();
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
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        assert_eq!(dkey, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
    }
    #[test]
    fn test_get_card_iv() {
        let card_iv = aes128::get_card_iv();
        assert_eq!(card_iv, vec![0x00; 16]);
    }
    #[test]
    fn test_calculate_session_iv() {
        let reader_rnd = aes128::get_reader_rnd();
        let card_rnd = aes128::get_card_rnd();
        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        assert_eq!(session_iv, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }
    #[test]
    fn test_calculate_session_key() {
        let reader_rnd = aes128::get_reader_rnd();
        let card_rnd = aes128::get_card_rnd();
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let reader_key_parameter = aes128::get_reader_key_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();

        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();
        assert_eq!(session_key.len(), 16);
        println!("session_key = {:02X?}", session_key);
    }
    #[test]
    fn test_encrypt_and_decrypt_with_session_key() {
        let reader_rnd = aes128::get_reader_rnd();
        let card_rnd = aes128::get_card_rnd();
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let reader_key_parameter = aes128::get_reader_key_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();

        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        let plain_text = b"Hello,World";
        let encrypt_text = aes128::encrypt_with_session_key(&session_key, &session_iv, plain_text).unwrap();
        let decrypt_text = aes128::decrypt_with_session_key(&session_key, &session_iv, &encrypt_text).unwrap();
        assert_eq!(decrypt_text, plain_text);
    }
    #[test]
    fn test_encrypted_with_session_key_and_session_iv() {
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let card_rnd = aes128::get_card_rnd();
        let card_info1 = aes128::get_card_info1();
        let card_auth_parameter = aes128::get_card_auth_parameter();
        let card_atc = aes128::get_card_atc();
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();
        let reader_auth_parameter = aes128::get_reader_auth_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();
        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        //emulate auth get process data response package from mobile
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

        let icce = crate::icce::auth::create_icce_auth_response(0x00, &payload);
        println!("[get process data response] = {:02X?}", icce.serialize());

        //handle get process data response on vehicle
        let _auth_auth_request = crate::icce::bluetooth_io::handle_icce_mobile_response(&icce).unwrap();

        //emulate auth auth response package from mobile with encrypted body payload
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

        let icce = crate::icce::auth::create_icce_auth_response(0x00, &payload);
        println!("[auth auth data response] = {:02X?}", icce.serialize());

        //handle get process data response on vehicle
        let _ = crate::icce::bluetooth_io::handle_icce_mobile_response(&icce).unwrap();

        //emulate RKE Control Command package from vehicle with encrypted body payload
        let rke_type = 0x01;
        let rke_cmd = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

        let icce = crate::icce::command::create_icce_rke_control_request(rke_type, &rke_cmd);
        println!("RKE Command ICCE is {:02X?}", icce.serialize());
        let origin_icce = ICCE::deserialize(&icce.serialize()).unwrap();

        let _ = crate::icce::bluetooth_io::handle_icce_mobile_request(&origin_icce).unwrap();

        println!("SESSION_KEY = {:02X?}", SESSION_KEY.lock().unwrap());
        println!("SESSION_IV = {:02X?}", SESSION_IV.lock().unwrap());
    }
    #[test]
    fn test_encrypt_and_decrypt_with_session_key_iv() {
        let card_seid = aes128::get_card_seid();
        let card_id = aes128::get_card_id();
        let card_rnd = aes128::get_card_rnd();
        let card_info1 = aes128::get_card_info1();
        let card_auth_parameter = aes128::get_card_auth_parameter();
        let card_atc = aes128::get_card_atc();
        let reader_rnd = aes128::get_reader_rnd();
        let reader_key_parameter = aes128::get_reader_key_parameter();
        let reader_auth_parameter = aes128::get_reader_auth_parameter();

        let session_iv = aes128::calculate_session_iv(&reader_rnd, &card_rnd);
        let dkey = aes128::calculate_dkey(&card_seid, &card_id);
        let card_iv = aes128::get_card_iv();
        let session_key = aes128::calculate_session_key(&dkey, &card_iv, &session_iv, &reader_key_parameter).unwrap();

        //emulate auth get process data response package from mobile
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

        let icce = crate::icce::auth::create_icce_auth_response(0x00, &payload);

        //handle get process data response on vehicle
        let _auth_auth_request = crate::icce::bluetooth_io::handle_icce_mobile_response(&icce).unwrap();

        //emulate auth auth response package from mobile with encrypted body payload
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

        let icce = crate::icce::auth::create_icce_auth_response(0x00, &payload);

        //handle get process data response on vehicle
        let _ = crate::icce::bluetooth_io::handle_icce_mobile_response(&icce).unwrap();

        //emulate RKE Control Command package from vehicle with encrypted body payload
        let rke_type = 0x01;
        let rke_cmd = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

        let icce = crate::icce::command::create_icce_rke_control_request(rke_type, &rke_cmd);
        let origin_icce = ICCE::deserialize(&icce.serialize()).unwrap();
        let _ = crate::icce::bluetooth_io::handle_icce_mobile_request(&origin_icce).unwrap();

        let session_key = SESSION_KEY.lock().unwrap().to_vec();
        let session_iv = SESSION_IV.lock().unwrap().to_vec();
        let plain_text: Vec<u8> = vec![0x5A, 0x0C, 0x00, 0x10, 0x00, 0x01, 0x02, 0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x5, 0x06];
        let encrypted_text = aes128::encrypt_with_session_key(&session_key, &session_iv, &plain_text).unwrap();
        let decrypted_text = aes128::decrypt_with_session_key(&session_key, &session_iv, &encrypted_text).unwrap();
        println!("session_key = {:02X?}", session_key);
        println!("sesion_iv = {:02X?}", session_iv);
        println!("plain_text = {:02X?}", plain_text);
        println!("encrypted_text = {:02X?}", encrypted_text);
        println!("decrypted_text = {:02X?}", decrypted_text);
    }
    #[test]
    fn test_large_payload() {
        let mut value = vec![];
        for i in 0..255 {
            value.push(i);
        }
        for i in 0..255 {
            value.push(i);
        }
        for i in 0..255 {
            value.push(i);
        }
        for i in 0..255 {
            value.push(i);
        }
        let mut payload = Payload::new();
        payload.set_payload_type(0x01);
        println!("value length = {}", value.len());
        payload.set_payload_length(value.len());
        payload.set_payload_value(&value);
        println!("serialized payload = {:02X?}", payload.serialize());
        let deserialized_payload = Payload::deserialize(&payload.serialize()).unwrap();
        println!("deserialzied_payload = {:?}", deserialized_payload);
    }
    #[test]
    fn test_fragment_payload() {
        let mut control1 = Control::new();
        control1.set_request();
        control1.set_no_crypto();
        control1.set_sync();
        control1.set_first_frag();
        let mut header1 = Header::new();
        header1.set_sof(0x5A);
        header1.set_length(4+2+4);
        header1.set_control(control1);
        header1.set_fsn(0x01);
        let mut payload1 = Payload::new();
        payload1.set_payload_type(0x01);
        payload1.set_payload_length(0x04);
        payload1.set_payload_value(&vec![0x01, 0x02, 0x03,0x04]);
        let mut body1 = Body::new();
        body1.set_message_id(0x02);
        body1.set_command_id(0x01);
        body1.set_payload(payload1);
        let mut icce1 = ICCE::new();
        icce1.set_header(header1);
        icce1.set_body(body1);
        icce1.calculate_checksum();
        println!("serialized icce1 = {:02X?}", icce1.serialize());
        let deserialzied_icce1 = ICCE::deserialize(&icce1.serialize()).unwrap();
        println!("deserialized icce1 = {:02X?}", deserialzied_icce1);

        let mut control2 = Control::new();
        control2.set_request();
        control2.set_no_crypto();
        control2.set_sync();
        control2.set_conti_frag();
        let mut header2 = Header::new();
        header2.set_sof(0x5A);
        header2.set_length(2+4);
        header2.set_control(control2);
        header2.set_fsn(0x02);
        let mut payload2 = Payload::new();
        payload2.set_payload_length(0x04);
        payload2.set_payload_value(&vec![0x05, 0x06, 0x07, 0x08]);
        let mut body2 = Body::new();
        body2.set_payload(payload2);
        let mut icce2 = ICCE::new();
        icce2.set_header(header2);
        icce2.set_body(body2);
        icce2.calculate_checksum();
        println!("serialized icce2 = {:02X?}", icce2.serialize());
        let deserialized_icce2 = ICCE::deserialize(&icce2.serialize()).unwrap();
        println!("deserialized icce2 = {:02X?}", deserialized_icce2);

        let mut control3 = Control::new();
        control3.set_request();
        control3.set_no_crypto();
        control3.set_sync();
        control3.set_last_frag();
        let mut header3 = Header::new();
        header3.set_sof(0x5A);
        header3.set_length(2+2);
        header3.set_control(control3);
        header3.set_fsn(0x03);
        let mut payload3 = Payload::new();
        payload3.set_payload_length(0x02);
        payload3.set_payload_value(&vec![0x09, 0x0a]);
        let mut body3 = Body::new();
        body3.set_payload(payload3);
        let mut icce3 = ICCE::new();
        icce3.set_header(header3);
        icce3.set_body(body3);
        icce3.calculate_checksum();
        println!("serialzied icce3 = {:02X?}", icce3.serialize());
        let deserialized_icce3 = ICCE::deserialize(&icce3.serialize()).unwrap();
        println!("deserialized icce3 = {:02X?}", deserialized_icce3);

        collect_icce_fragments(icce3);
        collect_icce_fragments(icce2);
        collect_icce_fragments(icce1);
        let reassemble_icce = reassemble_icce_fragments();
        println!("reassemble_icce = {:02X?}", reassemble_icce);
    }
    #[test]
    fn test_split_icce() {
        let mut control1 = Control::new();
        control1.set_request();
        control1.set_no_crypto();
        control1.set_sync();
        control1.set_no_frag();
        let mut header1 = Header::new();
        header1.set_sof(0x5A);
        header1.set_length(4+4+1024);
        header1.set_control(control1);
        header1.set_fsn(0x00);
        let mut value = vec![];
        for i in 0..=255 {
            value.push(i);
        }
        for i in 0..=255 {
            value.push(i);
        }
        for i in 0..=255 {
            value.push(i);
        }
        for i in 0..=255 {
            value.push(i);
        }
        let mut payload1 = Payload::new();
        payload1.set_payload_type(0x01);
        payload1.set_payload_length(value.len());
        payload1.set_payload_value(&value);
        let mut body1 = Body::new();
        body1.set_message_id(0x02);
        body1.set_command_id(0x01);
        body1.set_payload(payload1);
        let mut icce1 = ICCE::new();
        icce1.set_header(header1);
        icce1.set_body(body1);
        icce1.calculate_checksum();
        println!("{:02X?}", icce1);
        println!("serialized icce = {:02X?}", icce1.serialize());
        let splitted_icce = split_icce(&icce1).unwrap();
        println!("--------------------------");
        println!("splitted_icce counts = {}", splitted_icce.len());
        for item in splitted_icce {
            println!("{:02X?}", item);
            collect_icce_fragments(item);
        }
        println!("--------------------------");
        println!("=========================");
        let collected_icce = reassemble_icce_fragments();
        println!("{:02X?}", collected_icce);
        println!("=========================");

    }
}
