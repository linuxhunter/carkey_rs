use super::errors::*;

lazy_static! {
    static ref STATUS_LENGTH: usize = 2;
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StatusTag {
    SUCCESS,
    COMMUNICATION_PROTOCOL_ERROR,
    DATA_ERROR,
    REQUEST_ERROR,
    BUSINESS_ERROR,
    RFU,
}

impl Default for StatusTag {
    fn default() -> Self {
        StatusTag::SUCCESS
    }
}

impl From<u8> for StatusTag {
    fn from(value: u8) -> Self {
        match value {
            0x00 => StatusTag::SUCCESS,
            0x01 => StatusTag::COMMUNICATION_PROTOCOL_ERROR,
            0x02 => StatusTag::DATA_ERROR,
            0x03 => StatusTag::REQUEST_ERROR,
            0x04 => StatusTag::BUSINESS_ERROR,
            _ => StatusTag::RFU,
        }
    }
}

impl From<StatusTag> for u8 {
    fn from(value: StatusTag) -> Self {
        match value {
            StatusTag::SUCCESS => 0x00,
            StatusTag::COMMUNICATION_PROTOCOL_ERROR => 0x01,
            StatusTag::DATA_ERROR => 0x02,
            StatusTag::REQUEST_ERROR => 0x03,
            StatusTag::BUSINESS_ERROR => 0x04,
            StatusTag::RFU => 0xFF,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Status {
    tag: StatusTag,
    code: u8,
}

impl Status {
    pub fn new() -> Self {
        Status {
            ..Default::default()
        }
    }
    pub fn builder(&self) -> StatusBuilder {
        StatusBuilder {
            ..Default::default()
        }
    }
    pub fn length(&self) -> usize {
        2
    }
    pub fn get_tag(&self) -> StatusTag {
        self.tag
    }
    pub fn get_code(&self) -> u8 {
        self.code
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(u8::from(self.tag));
        buffer.push(self.code);

        buffer
    }
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.len() != *STATUS_LENGTH {
            return Err(ErrorKind::ICCOAObjectError("status length error".to_string()).into());
        }
        let mut status = Status::new();
        status.tag = StatusTag::from(buffer[0]);
        status.code = buffer[1];

        Ok(status)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StatusBuilder {
    tag: StatusTag,
    code: u8,
}

impl StatusBuilder {
    pub fn new() -> Self {
        StatusBuilder {
            ..Default::default()
        }
    }
    pub fn success(mut self) -> StatusBuilder {
        self.tag = StatusTag::SUCCESS;
        self.code = 0x00;
        self
    }
    pub fn communication_protocol_error(mut self, code: u8) -> StatusBuilder {
        self.tag = StatusTag::COMMUNICATION_PROTOCOL_ERROR;
        self.code = code;
        self

    }
    pub fn data_error(mut self, code: u8) -> StatusBuilder {
        self.tag = StatusTag::DATA_ERROR;
        self.code = code;
        self
    }
    pub fn request_error(mut self, code: u8) -> StatusBuilder {
        self.tag = StatusTag::REQUEST_ERROR;
        self.code = code;
        self
    }
    pub fn business_error(mut self, code: u8) -> StatusBuilder {
        self.tag = StatusTag::BUSINESS_ERROR;
        self.code = code;
        self
    }
    pub fn rfu(mut self) -> StatusBuilder {
        self.tag = StatusTag::RFU;
        self.code = 0x00;
        self
    }
    pub fn build(&self) -> Status {
        Status {
            tag: self.tag,
            code: self.code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_success() {
        let status = StatusBuilder::new().success().build();
        assert_eq!(status, Status {
            tag: StatusTag::SUCCESS,
            code: 0x00,
        });
    }
    #[test]
    fn test_status_communication_protocol_error() {
        let status = StatusBuilder::new().communication_protocol_error(0x01).build();
        assert_eq!(status, Status {
            tag: StatusTag::COMMUNICATION_PROTOCOL_ERROR,
            code: 0x01,
        });
    }
    #[test]
    fn test_status_data_error() {
        let status = StatusBuilder::new().data_error(0x01).build();
        assert_eq!(status, Status {
            tag: StatusTag::DATA_ERROR,
            code: 0x01,
        });
    }
    #[test]
    fn test_status_request_error() {
        let status = StatusBuilder::new().request_error(0x01).build();
        assert_eq!(status, Status {
            tag: StatusTag::REQUEST_ERROR,
            code: 0x01,
        });
    }
    #[test]
    fn test_status_business_error() {
        let status = StatusBuilder::new().business_error(0x01).build();
        assert_eq!(status, Status {
            tag: StatusTag::BUSINESS_ERROR,
            code: 0x01,
        });
    }
    #[test]
    fn test_status_rfu() {
        let status = StatusBuilder::new().rfu().build();
        assert_eq!(status, Status {
            tag: StatusTag::RFU,
            code: 0x00,
        });
    }
    #[test]
    fn test_status_default() {
        let status = Status::new();
        assert_eq!(status, Status {
            tag: StatusTag::SUCCESS,
            code: 0x00,
        });
    }
}