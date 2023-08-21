use std::sync::Mutex;
use aes::Aes128;
use cmac::{Cmac, Mac};

use super::{errors::*, status::{Status, StatusTag, StatusBuilder}};

lazy_static! {
    static ref ICCOA_HEADER_LENGTH: usize = 12;
    static ref ICCOA_HEADER_MARK_LENGTH: usize = 2;
    static ref ICCOA_REQUEST_TRANSACTION_ID: Mutex<u16> = Mutex::new(0x0000);
    static ref ICCOA_RESPONSE_TRANSACTION_ID: Mutex<u16> = Mutex::new(0x0000);
    static ref SHARED_KEY: Mutex<[u8; 32]> = Mutex::new([0x00; 32]);
    static ref CMAC_KEY_VEHICLE: Mutex<[u8; 16]> = Mutex::new([0x00; 16]);
    static ref CMAC_KEY_MOBILE: Mutex<[u8; 16]> = Mutex::new([0x00; 16]);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    REQUEST_PACKET,
    EVENT_PACKET,
    REPLY_PACKET,
}

impl Default for PacketType {
    fn default() -> Self {
        PacketType::REQUEST_PACKET
    }
}

impl TryFrom<u8> for PacketType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<PacketType, std::string::String> {
        match value {
            0x00 => Ok(PacketType::REQUEST_PACKET),
            0x01 => Ok(PacketType::EVENT_PACKET),
            0x02 => Ok(PacketType::REPLY_PACKET),
            _ => Err(String::from("Invalid Packet Type Value")),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(value: PacketType) -> Self {
        match value {
            PacketType::REQUEST_PACKET => 0x00,
            PacketType::EVENT_PACKET => 0x01,
            PacketType::REPLY_PACKET => 0x02,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptType {
    NO_ENCRYPT,
    ENCRYPT_BEFORE_AUTH,
    ENCRYPT_AFTER_AUTH,
    RFU,
}

impl Default for EncryptType {
    fn default() -> Self {
        EncryptType::NO_ENCRYPT
    }
}

impl TryFrom<u8> for EncryptType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<EncryptType, std::string::String> {
        match value {
            0x00 => Ok(EncryptType::NO_ENCRYPT),
            0x01 => Ok(EncryptType::ENCRYPT_BEFORE_AUTH),
            0x02 => Ok(EncryptType::RFU),
            0x03 => Ok(EncryptType::ENCRYPT_AFTER_AUTH),
            _ => Err(String::from("Invalid Encrypt Type")),
        }
    }
}

impl From<EncryptType> for u8 {
    fn from(value: EncryptType) -> Self {
        match value {
            EncryptType::NO_ENCRYPT => 0x00,
            EncryptType::ENCRYPT_BEFORE_AUTH => 0x01,
            EncryptType::RFU => 0x02,
            EncryptType::ENCRYPT_AFTER_AUTH => 0x03,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Mark {
    pub encrypt_type: EncryptType,
    pub more_fragment: bool,
    pub fragment_offset: u16,
}

impl Mark {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_encrypt_type(&mut self, encrypt_type: EncryptType) {
        self.encrypt_type = encrypt_type
    }
    pub fn get_encrypt_type(&self) -> EncryptType {
        self.encrypt_type
    }
    pub fn set_more_fragment(&mut self, more_fragment: bool) {
        self.more_fragment = more_fragment
    }
    pub fn get_more_fragment(&self) -> bool {
        self.more_fragment
    }
    pub fn set_fragment_offset(&mut self, fragment_offset: u16) {
        self.fragment_offset = fragment_offset
    }
    pub fn get_fragment_offset(&self) -> u16 {
        self.fragment_offset
    }
    pub fn serialize(&self) -> Vec<u8> {
        let encrypt_type = (u8::from(self.encrypt_type) as u16) << 14;
        let more_fragment = if self.more_fragment {
            1u16 << 13
        } else {
            0u16
        };
        let fragment_offset = self.fragment_offset & 0x1FFF;
        let mark = encrypt_type + more_fragment + fragment_offset;
        mark.to_be_bytes().to_vec()
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < *ICCOA_HEADER_MARK_LENGTH {
            return Err(ErrorKind::ICCOAObjectError("deserialize Mark length error".to_string()).into());
            //return Err(String::from("deserialized buffer length less than Mark minium length"));
        }
        let mut mark = Mark::new();
        let mark_u16 = u16::from_be_bytes(buffer.try_into().unwrap());
        let encrypt_type = EncryptType::try_from((mark_u16 >> 14) as u8)?;
        let more_fragment = if (mark_u16 >> 13) & 0x01 != 0 {
            true
        } else {
            false
        };
        let fragment_offset = mark_u16 & 0x1FFF;
        mark.set_encrypt_type(encrypt_type);
        mark.set_more_fragment(more_fragment);
        mark.set_fragment_offset(fragment_offset);
        Ok(mark)
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct Header {
    pub version: u8,
    pub connection_id: u8,
    pub packet_type: PacketType,
    pub rfu: u8,
    pub source_transaction_id: u16,
    pub dest_transaction_id: u16,
    pub pdu_length: u16,
    pub mark: Mark,
}

impl Header {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }
    pub fn get_version(&self) -> u8 {
        self.version
    }
    pub fn set_connection_id(&mut self, connection_id: u8) {
        self.connection_id = connection_id;
    }
    pub fn get_connection_id(&self) -> u8 {
        self.connection_id
    }
    pub fn set_packet_type(&mut self, packet_type: PacketType) {
        self.packet_type = packet_type; 
    }
    pub fn get_packet_type(&self) -> PacketType {
        self.packet_type
    }
    pub fn set_source_transaction_id(&mut self, tid: u16) {
        self.source_transaction_id = tid;
    }
    pub fn get_source_transaction_id(&self) -> u16 {
        self.source_transaction_id
    }
    pub fn update_source_transaction_id(&mut self) {
        let mut transaction_id = ICCOA_RESPONSE_TRANSACTION_ID.lock().unwrap();
        *transaction_id += 1;
        if *transaction_id == 0 {
            *transaction_id += 1;
        }
        self.set_source_transaction_id(*transaction_id);
    }
    pub fn set_dest_transaction_id(&mut self, tid: u16) {
        self.dest_transaction_id = tid;
    }
    pub fn get_dest_transaction_id(&self) -> u16 {
        self.dest_transaction_id
    }
    pub fn update_dest_transaction_id(&mut self) {
        let mut transaction_id = ICCOA_REQUEST_TRANSACTION_ID.lock().unwrap();
        *transaction_id += 1;
        if *transaction_id == 0 {
            *transaction_id += 1;
        }
        self.set_dest_transaction_id(*transaction_id);
    }
    pub fn set_pdu_length(&mut self, length: u16) {
        self.pdu_length = length;
    }
    pub fn get_pdu_length(&self) -> u16 {
        self.pdu_length
    }
    pub fn set_mark(&mut self, mark: Mark) {
        self.mark = mark;
    }
    pub fn set_encrypt_mode(&mut self, encrypt_type: EncryptType) {
        self.mark.set_encrypt_type(encrypt_type);
    }
    pub fn set_fragment_mode(&mut self, more_flag: bool, offset: u16) {
        self.mark.set_more_fragment(more_flag);
        self.mark.set_fragment_offset(offset);
    }
    pub fn get_mark(&self) -> Mark {
        self.mark
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.push(self.version);
        buffer.push(self.connection_id);
        buffer.push(u8::from(self.packet_type));
        buffer.push(self.rfu);
        buffer.append(&mut self.source_transaction_id.to_be_bytes().to_vec());
        buffer.append(&mut self.dest_transaction_id.to_be_bytes().to_vec());
        buffer.append(&mut self.pdu_length.to_be_bytes().to_vec());
        buffer.append(&mut self.mark.serialize().to_vec());
        buffer
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < *ICCOA_HEADER_LENGTH {
            return Err(ErrorKind::ICCOAObjectError("deserialize Header length error".to_string()).into());
        }
        let version = buffer[0];
        let connection_id = buffer[1];
        let packet_type = PacketType::try_from(buffer[2])?;
        let _rfu = buffer[3];
        let source_transcation_id = u16::from_be_bytes((&buffer[4..6]).try_into().unwrap());
        let dest_transcation_id = u16::from_be_bytes((&buffer[6..8]).try_into().unwrap());
        let pdu_length = u16::from_be_bytes((&buffer[8..10]).try_into().unwrap());
        let mark = Mark::deserialize(&buffer[10..12])?;
        let mut header = Header::new();
        header.set_version(version);
        header.set_connection_id(connection_id);
        header.set_packet_type(packet_type);
        header.set_source_transaction_id(source_transcation_id);
        header.set_dest_transaction_id(dest_transcation_id);
        header.set_pdu_length(pdu_length);
        header.set_mark(mark);
        Ok(header)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    OEM_DEFINED,
    VEHICLE_PAIRING,
    AUTH,
    COMMAND,
    NOTIFICATION,
    RFU,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::OEM_DEFINED
    }
}

impl TryFrom<u8> for MessageType {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<MessageType, std::string::String> {
        match value {
            0x00 => Ok(MessageType::OEM_DEFINED),
            0x01 => Ok(MessageType::VEHICLE_PAIRING),
            0x02 => Ok(MessageType::AUTH),
            0x03 => Ok(MessageType::COMMAND),
            0x04 => Ok(MessageType::NOTIFICATION),
            _ => Ok(MessageType::RFU),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::OEM_DEFINED => 0x00,
            MessageType::VEHICLE_PAIRING => 0x01,
            MessageType::AUTH => 0x02,
            MessageType::COMMAND => 0x03,
            MessageType::NOTIFICATION => 0x04,
            MessageType::RFU => 0x05,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct MessageData {
    pub status: Status,
    pub tag: u8,
    pub value: Vec<u8>,
}

impl MessageData {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_status(&mut self, status: Status) {
        self.status = status
    }
    pub fn get_status(&self) -> Status {
        self.status
    }
    pub fn set_tag(&mut self, tag: u8) {
        self.tag = tag;
    }
    pub fn get_tag(&self) -> u8 {
        self.tag
    }
    pub fn set_value(&mut self, value: &[u8]) {
        self.value = value.to_vec();
    }
    pub fn get_value(&self) -> &[u8] {
        &self.value
    }
    pub fn serialize(&self, request: bool, fragment: bool) -> Vec<u8> {
        let mut buffer = Vec::new();
        if fragment == false {
            if request == false {
                buffer.append(&mut self.status.serialize());
            }
            buffer.push(self.tag);
            let length = self.value.len() as u16;
            buffer.append(&mut length.to_be_bytes().to_vec());
        }
        buffer.append(&mut self.value.to_vec());
        buffer
    }
    pub fn deserialize(buffer: &[u8], request: bool, fragment: bool) -> Result<Self> {
        let mut message_data = MessageData::new();
        let mut index = 0;
        if fragment == false {
            if request == false {
                let status_tag = StatusTag::from(buffer[index]);
                let status_code = buffer[index+1];
                let status = match status_tag {
                    StatusTag::SUCCESS => StatusBuilder::new().success().build(),
                    StatusTag::COMMUNICATION_PROTOCOL_ERROR => StatusBuilder::new().communication_protocol_error(status_code).build(),
                    StatusTag::DATA_ERROR => StatusBuilder::new().data_error(status_code).build(),
                    StatusTag::REQUEST_ERROR => StatusBuilder::new().request_error(status_code).build(),
                    StatusTag::BUSINESS_ERROR => StatusBuilder::new().business_error(status_code).build(),
                    StatusTag::RFU => StatusBuilder::new().rfu().build(),
                };
                message_data.set_status(status);
                index += 2;
            }
            message_data.set_tag(buffer[index]);
            index += 3;
        }
        message_data.set_value(&buffer[index..]);
        Ok(message_data)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Body {
    pub message_type: MessageType,
    pub message_data: MessageData,
}

impl Body {
    pub fn new() -> Self {
        Body {
            message_type: MessageType::RFU,
            ..Default::default()
        }
    }
    pub fn set_message_type(&mut self, message_type: MessageType) {
        self.message_type = message_type;
    }
    pub fn get_message_type(&self) -> u8 {
        self.message_type.into()
    }
    pub fn set_message_data(&mut self, message_data: MessageData) {
        self.message_data = message_data
    }
    pub fn get_message_data(&self) -> &MessageData {
        &self.message_data
    }
    pub fn serialize(&self, request: bool, fragment: bool) -> Vec<u8> {
        let mut buffer = Vec::new();
        if fragment == false {
            buffer.push(self.message_type.into());
        }
        buffer.append(&mut self.message_data.serialize(request, fragment));

        buffer
    }
    pub fn deserialize(buffer: &[u8], request: bool, fragment: bool) -> Result<Self> {
        let mut body = Body::new();
        let mut index = 0;
        if fragment == false {
            body.set_message_type(MessageType::try_from(buffer[index])?);
            index += 1;
        }
        body.set_message_data(MessageData::deserialize(&buffer[index..], request, fragment)?);

        Ok(body)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ICCOA {
    pub header: Header,
    pub body: Body,
    pub mac: [u8; 8],
}

impl ICCOA {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn set_header(&mut self, header: Header) {
        self.header = header
    }
    pub fn get_header(&self) -> &Header {
        &self.header
    }
    pub fn set_body(&mut self, body: Body) {
        self.body = body
    }
    pub fn get_body(&self) -> &Body {
        &self.body
    }
    pub fn calculate_mac(&mut self) {
        let key = CMAC_KEY_VEHICLE.lock().unwrap().to_vec();
        let mut calculator = Cmac::<Aes128>::new_from_slice(&key).unwrap();
        let mut message = Vec::new();
        message.append(&mut self.header.serialize());
        let request = match self.get_header().get_packet_type() {
            PacketType::REQUEST_PACKET | PacketType::EVENT_PACKET => true,
            _ => false,
        };
        let fragment = if self.get_header().get_mark().get_fragment_offset() != 0 {
            true
        } else {
            false
        };
        message.append(&mut self.body.serialize(request, fragment));
        calculator.update(&message);
        let _result = calculator.finalize();
        //println!("[cmac-aes-128] = {:02X?}", result.into_bytes());
        self.mac = [0x00; 8];
    }
    pub fn verify_mac(&mut self) -> bool {
        let key = CMAC_KEY_MOBILE.lock().unwrap().to_vec();
        let mut calculator = Cmac::<Aes128>::new_from_slice(&key).unwrap();
        let mut message = Vec::new();
        message.append(&mut self.header.serialize());
        let request = match self.get_header().get_packet_type() {
            PacketType::REQUEST_PACKET | PacketType::EVENT_PACKET => true,
            _ => false,
        };
        let fragment = if self.get_header().get_mark().get_fragment_offset() != 0 {
            true
        } else {
            false
        };
        message.append(&mut self.body.serialize(request, fragment));
        calculator.update(&message);
        let result = calculator.finalize();
        result.into_bytes().to_vec().eq(&self.mac.to_vec())
    }
    pub fn get_mac(&self) -> &[u8; 8] {
        &self.mac
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.append(&mut self.header.serialize().to_vec());
        let request = match self.get_header().get_packet_type() {
            PacketType::REQUEST_PACKET | PacketType::EVENT_PACKET => true,
            _ => false,
        };
        let fragment = if self.get_header().get_mark().get_fragment_offset() != 0 {
            true
        } else {
            false
        };
        buffer.append(&mut self.body.serialize(request, fragment).to_vec());
        buffer.append(&mut self.mac.to_vec());
        buffer
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let header = Header::deserialize(buffer)?;
        let request = match header.get_packet_type() {
            PacketType::REQUEST_PACKET | PacketType::EVENT_PACKET => true,
            _ => false,
        };
        let fragment = if header.get_mark().get_fragment_offset() != 0 {
            true
        } else {
            false
        };
        let body = Body::deserialize(&buffer[*ICCOA_HEADER_LENGTH..buffer.len()-8], request, fragment)?;
        let mac = buffer[buffer.len()-8..].try_into().map_err(|_| ErrorKind::ICCOAObjectError("deserialized ICCOA mac error".to_string()))?;
        Ok(ICCOA {
            header,
            body,
            mac,
        })
    }
}

pub fn create_iccoa_header(packet_type: PacketType, transaction_id: u16, body_length: u16, mark: Mark) -> Header {
    let mut header = Header::new();
    header.set_packet_type(packet_type);
    if packet_type == PacketType::REQUEST_PACKET || packet_type == PacketType::EVENT_PACKET {
        if transaction_id == 0x0000 {
            header.update_dest_transaction_id();
        } else {
            header.set_dest_transaction_id(transaction_id);
        }
    } else {
        if transaction_id == 0x0000 {
            header.update_source_transaction_id();
        } else {
            header.set_source_transaction_id(transaction_id);
        }
    }
    header.set_pdu_length(12+body_length+8);
    header.set_mark(mark);

    header
}

pub fn create_iccoa_body_message_data(response: bool, status: Status, tag: u8, value: &[u8]) -> MessageData {
    let mut message_data = MessageData::new();
    if response {
        message_data.set_status(status);
    }
    message_data.set_tag(tag);
    message_data.set_value(value);

    message_data
}

pub fn create_iccoa_body(message_type: MessageType, message_data: MessageData) -> Body {
    let mut body = Body::new();
    body.set_message_type(message_type);
    body.set_message_data(message_data);

    body
}

pub fn create_iccoa(header: Header, body: Body) -> ICCOA {
    let mut iccoa = ICCOA::new();
    iccoa.set_header(header);
    iccoa.set_body(body);
    iccoa.calculate_mac();

    iccoa
}

pub fn update_cmac_key(key_type: &str, key: &[u8; 16]) {
    let mut cmac_key = if key_type == "vehicle" {
        CMAC_KEY_VEHICLE.lock().unwrap()
    } else {
        CMAC_KEY_MOBILE.lock().unwrap()
    };
    *cmac_key = *key;
}

pub fn update_shared_key(key: &[u8; 32]) {
    let mut shared_key = SHARED_KEY.lock().unwrap();
    *shared_key = *key;
}

#[cfg(test)]
mod tests {
    use crate::iccoa::status::StatusBuilder;

    use super::*;

    #[test]
    fn test_iccoa_default_header() {
        let header = Header::new();
        assert_eq!(header, Header {
            version: 0x00,
            connection_id: 0x00,
            packet_type: PacketType::REQUEST_PACKET,
            rfu: 0x00,
            source_transaction_id: 0x00,
            dest_transaction_id: 0x00,
            pdu_length: 0x00,
            mark: Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            }
        });
    }
    #[test]
    fn test_iccoa_header_with_value() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REQUEST_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        });
        assert_eq!(header, Header {
            version: 0x01,
            connection_id: 0x02,
            packet_type: PacketType::REQUEST_PACKET,
            rfu: 0x00,
            source_transaction_id: 0x0001,
            dest_transaction_id: 0x00002,
            pdu_length: 0x0003,
            mark: Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            }
        });
    }
    #[test]
    fn test_iccoa_header_serialize() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REQUEST_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        });
        let serialized_header = header.serialize();
        assert_eq!(serialized_header, vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00]);
    }
    #[test]
    fn test_iccoa_header_deserialize() {
        let serialized_header = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00];
        let header = Header::deserialize(&serialized_header).unwrap();
        assert_eq!(header, Header {
            version: 0x01,
            connection_id: 0x02,
            packet_type: PacketType::REQUEST_PACKET,
            rfu: 0x00,
            source_transaction_id: 0x0001,
            dest_transaction_id: 0x00002,
            pdu_length: 0x0003,
            mark: Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            }
        });
    }
    #[test]
    fn test_iccoa_default_body() {
        let body = Body::new();
        assert_eq!(body, Body {
            message_type: MessageType::RFU,
            message_data: MessageData {
                status: StatusBuilder::new().success().build(),
                tag: 0x00,
                value: vec![],
            }
        });
    }
    #[test]
    fn test_iccoa_body_with_value() {
        let mut message_data = MessageData::new();
        message_data.set_status(StatusBuilder::new().success().build());
        message_data.set_tag(0x02);
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_type(MessageType::VEHICLE_PAIRING);
        body.set_message_data(message_data);
        assert_eq!(body, Body {
            message_type: MessageType::VEHICLE_PAIRING,
            message_data: MessageData {
                status: StatusBuilder::new().success().build(),
                tag: 0x02,
                value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            }
        });
    }
    #[test]
    fn test_iccoa_body_serialize() {
        let mut message_data = MessageData::new();
        message_data.set_status(StatusBuilder::new().communication_protocol_error(0x01).build());
        message_data.set_tag(0x02);
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_type(MessageType::VEHICLE_PAIRING);
        body.set_message_data(message_data);

        let serialized_request_body = body.serialize(true, false);
        assert_eq!(serialized_request_body, vec![0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        
        let serialized_request_fragment_body = body.serialize(true, true);
        assert_eq!(serialized_request_fragment_body, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let serialized_response_body = body.serialize(false, false);
        assert_eq!(serialized_response_body, vec![0x01, 0x01, 0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let serialized_response_fragment_body = body.serialize(false, true);
        assert_eq!(serialized_response_fragment_body, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }
    #[test]
    fn test_iccoa_body_deserialize() {
        let serialized_request_body = vec![0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let request_body = Body::deserialize(&serialized_request_body, true, false).unwrap();
        assert_eq!(request_body, Body {
            message_type: MessageType::VEHICLE_PAIRING,
            message_data: MessageData {
                tag: 0x02,
                value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ..Default::default()
            }
        });
        let serialized_request_fragment_body = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let request_fragment_body = Body::deserialize(&serialized_request_fragment_body, true, true).unwrap();
        assert_eq!(request_fragment_body, Body {
            message_type: MessageType::RFU,
            message_data: MessageData {
                value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ..Default::default()
            }
        });
        let serialized_response_body = vec![0x01, 0x01, 0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let response_body = Body::deserialize(&serialized_response_body, false, false).unwrap();
        assert_eq!(response_body, Body {
            message_type: MessageType::VEHICLE_PAIRING,
            message_data: MessageData {
                status: StatusBuilder::new().communication_protocol_error(0x01).build(),
                tag: 0x02,
                value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            }
        });
        let serialized_response_fragment_body = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let response_fragment_body = Body::deserialize(&serialized_response_fragment_body, false, true).unwrap();
        assert_eq!(response_fragment_body, Body {
            message_type: MessageType::RFU,
            message_data: MessageData {
                value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ..Default::default()
            }
        });
    }
    #[test]
    fn test_iccoa_default() {
        let iccoa = ICCOA::new();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                ..Default::default()
            },
            body: Body {
                ..Default::default()
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_iccoa_with_request_no_fragment() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REQUEST_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        });
        let mut message_data = MessageData::new();
        message_data.set_tag(0x02);
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_type(MessageType::VEHICLE_PAIRING);
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REQUEST_PACKET,
                rfu: 0x00,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                }
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                    ..Default::default()
                }
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_iccoa_with_request_fragment() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REQUEST_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0001,
        });
        let mut message_data = MessageData::new();
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REQUEST_PACKET,
                rfu: 0x00,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0001,
                }
            },
            body: Body {
                message_type: MessageType::RFU,
                message_data: MessageData {
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_iccoa_with_response_no_fragment() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REPLY_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        });
        let mut message_data = MessageData::new();
        message_data.set_status(StatusBuilder::new().success().build());
        message_data.set_tag(0x02);
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_type(MessageType::VEHICLE_PAIRING);
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: StatusBuilder::new().success().build(),
                    tag: 0x02,
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                }
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_iccoa_with_response_fragment() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REPLY_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0001,
        });
        let mut message_data = MessageData::new();
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0001,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::RFU,
                message_data: MessageData {
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_iccoa_request_no_fragment_serialize() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REQUEST_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        });
        let mut message_data = MessageData::new();
        message_data.set_tag(0x02);
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_type(MessageType::VEHICLE_PAIRING);
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        let serialized_iccoa = iccoa.serialize();
        assert_eq!(
            serialized_iccoa,
            vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }
    #[test]
    fn test_iccoa_request_fragment_serialize() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REQUEST_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0001,
        });
        let mut message_data = MessageData::new();
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        let serialized_iccoa = iccoa.serialize();
        assert_eq!(
            serialized_iccoa,
            vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
    }
    #[test]
    fn test_iccoa_response_no_fragment_serialize() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REPLY_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0000,
        });
        let mut message_data = MessageData::new();
        message_data.set_status(StatusBuilder::new().communication_protocol_error(0x01).build());
        message_data.set_tag(0x02);
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_type(MessageType::VEHICLE_PAIRING);
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        let serialized_iccoa = iccoa.serialize();
        assert_eq!(
            serialized_iccoa,
            vec![0x01, 0x02, 0x02, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
    }
    #[test]
    fn test_iccoa_response_fragment_serialize() {
        let mut header = Header::new();
        header.set_version(0x01);
        header.set_connection_id(0x02);
        header.set_packet_type(PacketType::REPLY_PACKET);
        header.set_source_transaction_id(0x0001);
        header.set_dest_transaction_id(0x0002);
        header.set_pdu_length(0x0003);
        header.set_mark(Mark {
            encrypt_type: EncryptType::NO_ENCRYPT,
            more_fragment: false,
            fragment_offset: 0x0001,
        });
        let mut message_data = MessageData::new();
        message_data.set_value(&vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut body = Body::new();
        body.set_message_data(message_data);
        let mut iccoa = ICCOA::new();
        iccoa.set_header(header);
        iccoa.set_body(body);
        iccoa.calculate_mac();
        let serialized_iccoa = iccoa.serialize();
        assert_eq!(
            serialized_iccoa,
            vec![0x01, 0x02, 0x02, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
    }
    #[test]
    fn test_iccoa_request_no_fragment_deserialize() {
        let serialized_iccoa = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let iccoa = ICCOA::deserialize(&serialized_iccoa).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REQUEST_PACKET,
                rfu: 0x00,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                }
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    tag: 0x02,
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                    ..Default::default()
                }
            },
            mac: [0x00; 8],
        })
    }
    #[test]
    fn test_iccoa_request_fragment_deserialize() {
        let serialized_iccoa = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let iccoa = ICCOA::deserialize(&serialized_iccoa).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REQUEST_PACKET,
                rfu: 0x00,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0001,
                }
            },
            body: Body {
                message_type: MessageType::RFU,
                message_data: MessageData {
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_iccoa_response_no_fragment_deserialize() {
        let serialized_iccoa = vec![0x01, 0x02, 0x02, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let iccoa = ICCOA::deserialize(&serialized_iccoa).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0000,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::VEHICLE_PAIRING,
                message_data: MessageData {
                    status: StatusBuilder::new().communication_protocol_error(0x01).build(),
                    tag: 0x02,
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                }
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_iccoa_response_fragment_deserialize() {
        let serialized_iccoa = vec![0x01, 0x02, 0x02, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let iccoa = ICCOA::deserialize(&serialized_iccoa).unwrap();
        assert_eq!(iccoa, ICCOA {
            header: Header {
                version: 0x01,
                connection_id: 0x02,
                packet_type: PacketType::REPLY_PACKET,
                source_transaction_id: 0x0001,
                dest_transaction_id: 0x0002,
                pdu_length: 0x0003,
                mark: Mark {
                    encrypt_type: EncryptType::NO_ENCRYPT,
                    more_fragment: false,
                    fragment_offset: 0x0001,
                },
                ..Default::default()
            },
            body: Body {
                message_type: MessageType::RFU,
                message_data: MessageData {
                    value: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                    ..Default::default()
                },
            },
            mac: [0x00; 8],
        });
    }
    #[test]
    fn test_cmac_aes_128_for_iccoa() {
        let serialized_iccoa = vec![0x01, 0x02, 0x02, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut iccoa = ICCOA::deserialize(&serialized_iccoa).unwrap();
        let cmac_key = [0x85, 0x7d, 0x0d, 0xb7, 0xf5, 0xe0, 0x63, 0x85, 0x85, 0x3b, 0xf4, 0xb8, 0xab, 0xd4, 0x3b, 0x5a];
        println!("cmac key is {:02X?}", cmac_key);
        update_cmac_key("vehicle", &cmac_key);
        let message = [
            0x04, 0xc0, 0x59, 0x53, 0xea, 0x9d, 0x1c, 0xd6,
            0x24, 0x8b, 0x8c, 0x61, 0xbe, 0xcd, 0x7d, 0x55,
            0xe4, 0x62, 0x37, 0x52, 0x6d, 0x8b, 0x1e, 0x23,
            0x49, 0x5e, 0xa7, 0x56, 0x6b, 0x7f, 0x6b, 0xc2,
            0x4b, 0x3d, 0xa1, 0xcf, 0xb2, 0xe8, 0x8a, 0x97,
            0x5f, 0xcf, 0xb5, 0xdc, 0x4e, 0x72, 0xb5, 0xcb,
            0xea, 0x50, 0x9b, 0x1c, 0xfd, 0xd1, 0xef, 0x8f,
            0x81, 0x95, 0xfa, 0x8b, 0xf2, 0xbd, 0x5c, 0xa1,
            0xe5
        ];
        //calculate_mac2(&message);
    }
    #[test]
    fn test_auto_dest_transaction_id() {
        let header = create_iccoa_header(
            PacketType::REQUEST_PACKET,
            0x0000,
            0x000C,
            Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            }
        );
        let dest_transaction_id = header.get_dest_transaction_id();
        assert_eq!(header, Header {
            packet_type: PacketType::REQUEST_PACKET,
            dest_transaction_id: dest_transaction_id,
            pdu_length: 12+12+8,
            mark: Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            },
            ..Default::default()
        });
    }
    #[test]
    fn test_auto_source_transaction_id() {
        let header = create_iccoa_header(
            PacketType::REPLY_PACKET,
            0x0000,
            0x000C,
            Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            }
        );
        let source_transaction_id = header.get_source_transaction_id();
        assert_eq!(header, Header {
            packet_type: PacketType::REPLY_PACKET,
            source_transaction_id: source_transaction_id,
            pdu_length: 12+12+8,
            mark: Mark {
                encrypt_type: EncryptType::NO_ENCRYPT,
                more_fragment: false,
                fragment_offset: 0x0000,
            },
            ..Default::default()
        });
    }
}