use crc16::CCITT_FALSE;

#[derive(Default, Debug, Copy, Clone, PartialEq, bitcode::Encode, bitcode::Decode)]
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
    pub fn serialize(&self) -> Vec<u8> {
        return bitcode::encode(self).unwrap();
    }
    pub fn deserialize(byte_stream: &[u8]) -> Self {
        return bitcode::decode::<Control>(byte_stream).unwrap();
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

#[derive(Default, Debug, Copy, Clone, PartialEq, bitcode::Encode, bitcode::Decode)]
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
    pub fn serialize(&self) -> Vec<u8> {
        return bitcode::encode(self).unwrap();
    }
    pub fn deserialize(byte_stream: &[u8]) -> Self {
        return bitcode::decode::<Header>(&byte_stream).unwrap();
    }
}

#[derive(Default, Debug, Clone, PartialEq, bitcode::Encode, bitcode::Decode)]
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
    pub fn serialize(&self) -> Vec<u8> {
        return bitcode::encode(self).unwrap();
    }
    pub fn deserialize(byte_stream: &[u8]) -> Self {
        return bitcode::decode::<Payload>(&byte_stream).unwrap();
    }
}

#[derive(Default, Debug, Clone, PartialEq, bitcode::Encode, bitcode::Decode)]
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
    pub fn serialize(&self) -> Vec<u8> {
        return bitcode::encode(self).unwrap();
    }
    pub fn deserialize(byte_stream: &[u8]) -> Self {
        return bitcode::decode::<Body>(&byte_stream).unwrap();
    }
}

#[derive(Default, Debug, Clone, PartialEq, bitcode::Encode, bitcode::Decode)]
pub struct ICCE {
    header: Header,
    body: Body,
    checksum: u16,
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
    pub fn calculate_checksum(&mut self) {
        let crc16_header= bitcode::encode(&self.header).unwrap();
        let crc16_body = bitcode::encode(&self.body).unwrap();
        let mut crc16_ccitt = crc16::State::<CCITT_FALSE>::new();
        crc16_ccitt.update(&crc16_header);
        crc16_ccitt.update(&crc16_body);
        self.checksum = crc16_ccitt.get();
    }
    pub fn serialize(&self) -> Vec<u8> {
        return bitcode::encode(self).unwrap();
    }
    pub fn deserialize(byte_stream: &[u8]) -> Self {
        return bitcode::decode::<ICCE>(&byte_stream).unwrap();
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
        let encoded_control = bitcode::encode(&control).unwrap();
        let decoded_control = Control::deserialize(&encoded_control);
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
        let deserialized_header = Header::deserialize(&serialized_header);
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
        let deserialized_payload: Payload = Payload::deserialize(&serialized_payload);
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
    fn tset_body_serialized_and_deserialized() {
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
        let deserialized_body: Body = Body::deserialize(&serialized_body);
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
            checksum: 0x50EF,
        });
    }
    #[test]
    fn tst_icce_serialize_and_deserialize() {
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
        let deserialized_icce = ICCE::deserialize(&serialized_icce);
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
            checksum: 0x50EF,
        });
    }
}
