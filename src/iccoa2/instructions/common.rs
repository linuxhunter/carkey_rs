use std::fmt::{Display, Formatter};
use crate::iccoa2::errors::*;

#[allow(dead_code)]
const COMMAND_APDU_HEADER_LENGTH: usize = 0x04;
#[allow(dead_code)]
const RESPONSE_APDU_TRAILER_LENGTH: usize = 0x02;

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduHeader {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
}

#[allow(dead_code)]
impl CommandApduHeader {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        CommandApduHeader {
            cla,
            ins,
            p1,
            p2,
        }
    }
    pub fn get_cla(&self) -> u8 {
        self.cla
    }
    pub fn set_cla(&mut self, cla: u8) {
        self.cla = cla;
    }
    pub fn get_ins(&self) -> u8 {
        self.ins
    }
    pub fn set_ins(&mut self, ins: u8) {
        self.ins = ins;
    }
    pub fn get_p1(&self) -> u8 {
        self.p1
    }
    pub fn set_p1(&mut self, p1: u8) {
        self.p1 = p1;
    }
    pub fn get_p2(&self) -> u8 {
        self.p2
    }
    pub fn set_p2(&mut self, p2: u8) {
        self.p2 = p2;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(vec![
            self.get_cla(),
            self.get_ins(),
            self.get_p1(),
            self.get_p2(),
        ])
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < COMMAND_APDU_HEADER_LENGTH {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize Command APDU Header length error")).into());
        }
        Ok(CommandApduHeader::new(
            data[0],
            data[1],
            data[2],
            data[3],
        ))
    }
}

impl Display for CommandApduHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CLA: {}, INS: {}, P1: {}, P2: {}", self.cla, self.ins, self.p1, self.p2)
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApduTrailer {
    data: Option<Vec<u8>>,
    le: Option<u8>,
}

#[allow(dead_code)]
impl CommandApduTrailer {
    pub fn new(data: Option<Vec<u8>>, le: Option<u8>) -> Self {
        CommandApduTrailer {
            data,
            le,
        }
    }
    pub fn get_data(&self) -> Option<&[u8]> {
        if let Some(ref data) = self.data {
            Some(data)
        } else {
            None
        }
    }
    pub fn set_data(&mut self, data: Option<Vec<u8>>) {
        self.data = data;
    }
    pub fn get_le(&self) -> Option<&u8> {
        if let Some(ref le) = self.le {
            Some(le)
        } else {
            None
        }
    }
    pub fn set_le(&mut self, le: Option<u8>) {
        self.le = le;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        if self.get_data().is_none() && self.get_le().is_none() {
            return Err(ErrorKind::ApduInstructionErr(format!("Command Apdu Trailer Data and Le are all None")).into());
        }
        let mut buffer = Vec::new();
        if let Some(ref data) = self.data {
            buffer.push(data.len() as u8);
            buffer.append(&mut data.clone());
        }
        if let Some(le) = self.get_le() {
            buffer.push(*le);
        }
        Ok(buffer)
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 1 {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize origin data length is zero")).into());
        }
        if data.len() == 1 {
            Ok(CommandApduTrailer::new(
                None,
                Some(data[0]),
            ))
        } else {
            let lc = data[0];
            if data.len() < 1 + lc as usize {
                return Err(ErrorKind::ApduInstructionErr(format!("deserialize Command APDU Trailer data length error")).into());
            }
            let payload = (&data[1..1 + lc as usize])
                .try_into()
                .map_err(|e| ErrorKind::ApduInstructionErr(format!("deserialize Command APDU Trailer data error: {}", e)))?;
            let le = if data.len() == 2 + lc as usize {
                data[1+lc as usize]
            } else {
                0
            };
            Ok(CommandApduTrailer::new(
                Some(payload),
                Some(le),
            ))
        }
    }
}

impl Display for CommandApduTrailer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(data) = self.get_data() {
            write!(f, "Lc: {}, Data: {:02X?}", data.len(), data)?;
        }
        if let Some(le) = self.get_le() {
            write!(f, "Le: {}", le)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialOrd, PartialEq)]
pub struct CommandApdu {
    header: CommandApduHeader,
    trailer: Option<CommandApduTrailer>,
}

#[allow(dead_code)]
impl CommandApdu {
    pub fn new(header: CommandApduHeader, trailer: Option<CommandApduTrailer>) -> Self {
        CommandApdu {
            header,
            trailer,
        }
    }
    pub fn get_header(&self) -> &CommandApduHeader {
        &self.header
    }
    pub fn set_header(&mut self, header: CommandApduHeader) {
        self.header = header;
    }
    pub fn get_trailer(&self) -> Option<&CommandApduTrailer> {
        if let Some(ref trailer) = self.trailer {
            Some(trailer)
        } else {
            None
        }
    }
    pub fn set_trailer(&mut self, trailer: Option<CommandApduTrailer>) {
        self.trailer = trailer;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.append(&mut self.get_header().serialize()?);
        if let Some(trailer) = self.get_trailer() {
            buffer.append(&mut trailer.serialize()?);
        }
        Ok(buffer)
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let data_len = data.len();
        if data_len < COMMAND_APDU_HEADER_LENGTH {
            Err(ErrorKind::ApduInstructionErr(format!("deserialize data length less than {}", COMMAND_APDU_HEADER_LENGTH)).into())
        } else if data_len == COMMAND_APDU_HEADER_LENGTH {
            let header = CommandApduHeader::deserialize(&data[0..COMMAND_APDU_HEADER_LENGTH])?;
            Ok(CommandApdu::new(header, None))
        } else {
            let header = CommandApduHeader::deserialize(&data[0..COMMAND_APDU_HEADER_LENGTH])?;
            let trailer = if data.len() > COMMAND_APDU_HEADER_LENGTH {
                Some(CommandApduTrailer::deserialize(&data[COMMAND_APDU_HEADER_LENGTH..])?)
            } else {
                None
            };
            Ok(CommandApdu::new(header, trailer))
        }
    }
}

impl Display for CommandApdu {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Header: {}", self.get_header())?;
        if let Some(trailer) = self.get_trailer() {
            write!(f, "Trailer: {}", trailer)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Copy, Clone, PartialOrd, PartialEq)]
pub struct ResponseApduTrailer {
    sw1: u8,
    sw2: u8,
}

#[allow(dead_code)]
impl ResponseApduTrailer {
    pub fn new(sw1: u8, sw2: u8) -> Self {
        ResponseApduTrailer {
            sw1,
            sw2,
        }
    }
    pub fn get_sw1(&self) -> u8 {
        self.sw1
    }
    pub fn set_sw1(&mut self, sw1: u8) {
        self.sw1 = sw1;
    }
    pub fn get_sw2(&self) -> u8 {
        self.sw2
    }
    pub fn set_sw2(&mut self, sw2: u8) {
        self.sw2 = sw2;
    }
    pub fn is_success(&self) -> bool {
        if self.get_sw1() == 0x90 && self.get_sw2() == 0x00 {
            true
        } else {
            false
        }
    }
    pub fn has_remain(&self) -> bool {
        if self.get_sw1() == 0x61 {
            true
        } else {
            false
        }
    }
    pub fn remain_bytes(&self) -> u8 {
        if self.get_sw1() == 0x61 {
            self.get_sw2()
        } else {
            0
        }
    }
    pub fn get_error_message(&self) -> String {
        let sw1 = self.get_sw1();
        let sw2 = self.get_sw2();
        if sw1 == 0x6E && sw2 == 0x00 {
            String::from("Invalid CLA")
        } else if sw1 == 0x6D && sw2 == 0x00 {
            String::from("Invalid INS")
        } else if sw1 == 0x67 && sw2 == 0x00 {
            String::from("Data Length Error")
        } else if sw1 == 0x6A {
            if sw2 == 0x88 {
                String::from("Reference Data is not exist")
            } else if sw2 == 0x86 {
                String::from("P1/P2 parameter error")
            } else if sw2 == 0x82 {
                String::from("Application or File is not exist")
            } else if sw2 == 0x80 {
                String::from("Data Format error")
            } else {
                String::from(format!("Unsupported Status word: {}/{}", sw1, sw2))
            }
        } else {
            String::from(format!("Unsupported Status word: {}/{}", sw1, sw2))
        }
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(vec![
            self.get_sw1(),
            self.get_sw2(),
        ])
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() != RESPONSE_APDU_TRAILER_LENGTH {
            return Err(ErrorKind::ApduInstructionErr(format!("deserialize data length not equal {}", RESPONSE_APDU_TRAILER_LENGTH)).into());
        }
        Ok(ResponseApduTrailer::new(data[0], data[1]))
    }
}

impl Display for ResponseApduTrailer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_success() {
            write!(f, "Success")
        } else if self.has_remain() {
            write!(f, "remain bytes: {}", self.remain_bytes())
        } else {
            write!(f, "error: {}", self.get_error_message())
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct ResponseApdu {
    body: Option<Vec<u8>>,
    trailer: ResponseApduTrailer,
}

#[allow(dead_code)]
impl ResponseApdu {
    pub fn new(body: Option<Vec<u8>>, trailer: ResponseApduTrailer) -> Self {
        ResponseApdu {
            body,
            trailer,
        }
    }
    pub fn get_body(&self) -> Option<&[u8]> {
        if let Some(ref body) = self.body {
            Some(body)
        } else {
            None
        }
    }
    pub fn set_body(&mut self, body: Option<Vec<u8>>) {
        self.body = body;
    }
    pub fn get_trailer(&self) -> &ResponseApduTrailer {
        &self.trailer
    }
    pub fn set_trailer(&mut self, trailer: ResponseApduTrailer) {
        self.trailer = trailer;
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        if let Some(body) = self.get_body() {
            buffer.append(&mut body.to_vec());
        }
        buffer.append(&mut self.trailer.serialize()?);
        Ok(buffer)
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let data_len = data.len();
        if data_len < 2 {
            Err(ErrorKind::ApduInstructionErr(format!("deserialize origin data length is zero")).into())
        } else if data_len == 2 {
            let trailer = ResponseApduTrailer::new(data[0], data[1]);
            Ok(ResponseApdu::new(None, trailer))
        } else {
            let body = data[..data_len-2].to_vec();
            let trailer = ResponseApduTrailer::new(data[data_len-2], data[data_len-1]);
            Ok(ResponseApdu::new(Some(body), trailer))
        }
    }
}

impl Display for ResponseApdu {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(body) = self.get_body() {
            write!(f, "Body: {:02X?}, Trailer: {}", body, self.trailer)
        } else {
            write!(f, "Trailer: {}", self.trailer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_command_apdu() {
        let cla = 0x00;
        let ins = 0x01;
        let p1 = 0x02;
        let p2 = 0x03;
        let le = 0x09;
        let data = vec![0x05, 0x06, 0x07, 0x08];
        let header = CommandApduHeader::new(cla, ins, p1, p2);
        let trailer = CommandApduTrailer::new(Some(data.clone()), Some(le));
        let command_apdu = CommandApdu::new(header, Some(trailer));
        assert_eq!(command_apdu.get_header(), &CommandApduHeader::new(cla, ins, p1, p2));
        assert_eq!(command_apdu.get_header().get_cla(), cla);
        assert_eq!(command_apdu.get_header().get_ins(), ins);
        assert_eq!(command_apdu.get_header().get_p1(), p1);
        assert_eq!(command_apdu.get_header().get_p2(), p2);
        if let Some(trailer) = command_apdu.get_trailer() {
            assert_eq!(trailer, &CommandApduTrailer::new(Some(data.clone()), Some(le)));
            assert_eq!(trailer.get_data(), Some(data.as_ref()));
            assert_eq!(trailer.get_le(), Some(&le));
        }
    }
    #[test]
    fn test_update_command_apdu() {
        let cla = 0x00;
        let ins = 0x01;
        let p1 = 0x02;
        let p2 = 0x03;
        let le = 0x09;
        let data = vec![0x05, 0x06, 0x07, 0x08];
        let header = CommandApduHeader::new(cla, ins, p1, p2);
        let trailer = CommandApduTrailer::new(Some(data), Some(le));
        let mut command_apdu = CommandApdu::new(header, Some(trailer));
        let new_cla = 0x10;
        let new_ins = 0x11;
        let new_p1 = 0x12;
        let new_p2 = 0x13;
        let new_data = vec![0x15, 0x16, 0x17, 0x18];
        let new_le = 0x19;
        let new_header = CommandApduHeader::new(new_cla, new_ins, new_p1, new_p2);
        let new_trailer = CommandApduTrailer::new(Some(new_data.clone()), Some(new_le));
        command_apdu.set_header(new_header);
        command_apdu.set_trailer(Some(new_trailer));
        assert_eq!(command_apdu.get_header(), &CommandApduHeader::new(new_cla, new_ins, new_p1, new_p2));
        assert_eq!(command_apdu.get_header().get_cla(), new_cla);
        assert_eq!(command_apdu.get_header().get_ins(), new_ins);
        assert_eq!(command_apdu.get_header().get_p1(), new_p1);
        assert_eq!(command_apdu.get_header().get_p2(), new_p2);
        if let Some(trailer) = command_apdu.get_trailer() {
            assert_eq!(trailer, &CommandApduTrailer::new(Some(new_data.clone()), Some(new_le)));
            assert_eq!(trailer.get_data(), Some(new_data.as_ref()));
            assert_eq!(trailer.get_le(), Some(&new_le));
        }
    }
    #[test]
    fn test_command_apdu_serialize() {
        let cla = 0x00;
        let ins = 0x01;
        let p1 = 0x02;
        let p2 = 0x03;
        let le = 0x09;
        let data = vec![0x05, 0x06, 0x07, 0x08];
        let header = CommandApduHeader::new(cla, ins, p1, p2);
        let trailer = CommandApduTrailer::new(Some(data), Some(le));
        let command_apdu = CommandApdu::new(header, Some(trailer));
        let serialized_command_apdu = command_apdu.serialize();
        assert!(serialized_command_apdu.is_ok());
        let serialized_command_apdu = serialized_command_apdu.unwrap();
        assert_eq!(serialized_command_apdu, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
    }
    #[test]
    fn test_command_apdu_deserialize() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let command_apdu = CommandApdu::deserialize(data.as_ref());
        assert!(command_apdu.is_ok());
        let command_apdu = command_apdu.unwrap();
        assert_eq!(command_apdu.get_header(), &CommandApduHeader::new(0x00, 0x01, 0x02, 0x03));
        assert_eq!(command_apdu.get_trailer(), Some(&CommandApduTrailer::new(Some(vec![0x05, 0x06, 0x07, 0x08]), Some(0x09))));
    }
    #[test]
    fn test_create_response_apdu() {
        let body = vec![0x00, 0x01, 0x02, 0x03];
        let sw1 = 0x90;
        let sw2 = 0x00;
        let trailer = ResponseApduTrailer::new(sw1, sw2);
        let response_apdu = ResponseApdu::new(Some(body.clone()), trailer);
        assert_eq!(response_apdu.get_body(), Some(body.as_ref()));
        assert_eq!(response_apdu.get_trailer(), &trailer);
        assert_eq!(response_apdu.get_trailer().get_sw1(), sw1);
        assert_eq!(response_apdu.get_trailer().get_sw2(), sw2);
        assert_eq!(response_apdu.get_trailer().is_success(), true);
    }
    #[test]
    fn test_update_response_apdu() {
        let body = vec![0x00, 0x01, 0x02, 0x03];
        let sw1 = 0x90;
        let sw2 = 0x00;
        let trailer = ResponseApduTrailer::new(sw1, sw2);
        let mut response_apdu = ResponseApdu::new(Some(body), trailer);
        let new_body = vec![0x10, 0x11, 0x12, 0x13];
        let new_sw1 = 0x61;
        let new_sw2 = 0x10;
        let new_trailer = ResponseApduTrailer::new(new_sw1, new_sw2);
        response_apdu.set_body(Some(new_body.clone()));
        response_apdu.set_trailer(new_trailer);
        assert_eq!(response_apdu.get_body(), Some(new_body.as_ref()));
        assert_eq!(response_apdu.get_trailer(), &new_trailer);
        assert_eq!(response_apdu.get_trailer().get_sw1(), new_sw1);
        assert_eq!(response_apdu.get_trailer().get_sw2(), new_sw2);
        assert_eq!(response_apdu.get_trailer().is_success(), false);
        assert_eq!(response_apdu.get_trailer().has_remain(), true);
        assert_eq!(response_apdu.get_trailer().remain_bytes(), new_sw2);
    }
    #[test]
    fn test_response_apdu_serialize() {
        let body = vec![0x00, 0x01, 0x02, 0x03];
        let sw1 = 0x90;
        let sw2 = 0x00;
        let trailer = ResponseApduTrailer::new(sw1, sw2);
        let response_apdu = ResponseApdu::new(Some(body), trailer);
        let serialized_response_apdu = response_apdu.serialize();
        assert!(serialized_response_apdu.is_ok());
        let serialized_response_apdu = serialized_response_apdu.unwrap();
        assert_eq!(serialized_response_apdu, vec![0x00, 0x01, 0x02, 0x03, 0x90, 0x00]);
    }
    #[test]
    fn test_response_apdu_deserialize() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x90, 0x00];
        let response_apdu = ResponseApdu::deserialize(data.as_ref());
        assert!(response_apdu.is_ok());
        let response_apdu = response_apdu.unwrap();
        assert_eq!(response_apdu.get_body(), Some(vec![0x00, 0x01, 0x02, 0x03].as_ref()));
        assert_eq!(response_apdu.get_trailer().get_sw1(), 0x90);
        assert_eq!(response_apdu.get_trailer().get_sw2(), 0x00);
        assert_eq!(response_apdu.get_trailer().is_success(), true);
    }
    #[test]
    fn test_request_with_header_only() {
        let cla = 0x00;
        let ins = 0x01;
        let p1 = 0x02;
        let p2 = 0x03;
        let header = CommandApduHeader::new(cla, ins, p1, p2);
        let command_apdu = CommandApdu::new(header, None);
        assert_eq!(command_apdu.get_header(), &CommandApduHeader::new(cla, ins, p1, p2));
        assert_eq!(command_apdu.get_trailer(), None);
    }
    #[test]
    fn test_request_with_header_le() {
        let cla = 0x00;
        let ins = 0x01;
        let p1 = 0x02;
        let p2 = 0x03;
        let le = 0x09;
        let data = vec![0x05, 0x06, 0x07, 0x08];
        let header = CommandApduHeader::new(cla, ins, p1, p2);
        let trailer = CommandApduTrailer::new(None, Some(le));
        let command_apdu = CommandApdu::new(header, Some(trailer));
        assert_eq!(command_apdu.get_header(), &CommandApduHeader::new(cla, ins, p1, p2));
        assert_eq!(command_apdu.get_trailer(), Some(&CommandApduTrailer::new(None, Some(le))));
    }
    #[test]
    fn test_request_with_header_data() {
        let cla = 0x00;
        let ins = 0x01;
        let p1 = 0x02;
        let p2 = 0x03;
        let data = vec![0x05, 0x06, 0x07, 0x08];
        let header = CommandApduHeader::new(cla, ins, p1, p2);
        let trailer = CommandApduTrailer::new(Some(data.clone()), None);
        let command_apdu = CommandApdu::new(header, Some(trailer));
        assert_eq!(command_apdu.get_header(), &CommandApduHeader::new(cla, ins, p1, p2));
        assert_eq!(command_apdu.get_trailer(), Some(&CommandApduTrailer::new(Some(data.clone()), None)));
    }
    #[test]
    fn test_response_with_trailer_only() {
        let sw1 = 0x90;
        let sw2 = 0x00;
        let trailer = ResponseApduTrailer::new(sw1, sw2);
        let response_apdu = ResponseApdu::new(None, trailer);
        assert_eq!(response_apdu.get_body(), None);
        assert_eq!(response_apdu.get_trailer(), &trailer);
        assert_eq!(response_apdu.get_trailer().get_sw1(), sw1);
        assert_eq!(response_apdu.get_trailer().get_sw2(), sw2);
        assert_eq!(response_apdu.get_trailer().is_success(), true);

    }
}