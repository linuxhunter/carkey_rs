use super::errors::*;

lazy_static! {
    static ref STATUS_LENGTH: usize = 2;
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum StatusTag {
    #[default]
    Success,
    COMMUNICATION_PROTOCOL_ERROR,
    DATA_ERROR,
    REQUEST_ERROR,
    BUSINESS_ERROR,
    Rfu,
}

impl From<u8> for StatusTag {
    fn from(value: u8) -> Self {
        match value {
            0x00 => StatusTag::Success,
            0x01 => StatusTag::COMMUNICATION_PROTOCOL_ERROR,
            0x02 => StatusTag::DATA_ERROR,
            0x03 => StatusTag::REQUEST_ERROR,
            0x04 => StatusTag::BUSINESS_ERROR,
            _ => StatusTag::Rfu,
        }
    }
}

impl From<StatusTag> for u8 {
    fn from(value: StatusTag) -> Self {
        match value {
            StatusTag::Success => 0x00,
            StatusTag::COMMUNICATION_PROTOCOL_ERROR => 0x01,
            StatusTag::DATA_ERROR => 0x02,
            StatusTag::REQUEST_ERROR => 0x03,
            StatusTag::BUSINESS_ERROR => 0x04,
            StatusTag::Rfu => 0xFF,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Status {
    tag: StatusTag,
    code: u8,
}

#[allow(dead_code)]
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
        vec![
            u8::from(self.tag),
            self.code
        ]
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
pub struct StatusBuilder(Status);

impl StatusBuilder {
    pub fn new() -> Self {
        StatusBuilder(Status {
            ..Default::default()
        })
    }
    pub fn success(mut self) -> Self {
        self.0.tag = StatusTag::Success;
        self.0.code = 0x00;
        self
    }
    pub fn communication_protocol_error(mut self, code: u8) -> Self {
        self.0.tag = StatusTag::COMMUNICATION_PROTOCOL_ERROR;
        self.0.code = code;
        self

    }
    pub fn data_error(mut self, code: u8) -> Self {
        self.0.tag = StatusTag::DATA_ERROR;
        self.0.code = code;
        self
    }
    pub fn request_error(mut self, code: u8) -> Self {
        self.0.tag = StatusTag::REQUEST_ERROR;
        self.0.code = code;
        self
    }
    pub fn business_error(mut self, code: u8) -> Self {
        self.0.tag = StatusTag::BUSINESS_ERROR;
        self.0.code = code;
        self
    }
    pub fn rfu(mut self) -> Self {
        self.0.tag = StatusTag::Rfu;
        self.0.code = 0x00;
        self
    }
    pub fn build(self) -> Status {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_success() {
        let status = StatusBuilder::new().success().build();
        assert_eq!(status, Status {
            tag: StatusTag::Success,
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
            tag: StatusTag::Rfu,
            code: 0x00,
        });
    }
    #[test]
    fn test_status_default() {
        let status = Status::new();
        assert_eq!(status, Status {
            tag: StatusTag::Success,
            code: 0x00,
        });
    }
}