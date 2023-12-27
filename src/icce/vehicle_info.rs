use std::sync::Mutex;
use rand::Rng;
use crate::icce::Serde;
use crate::icce::errors::*;

const VEHICLE_READER_TYPE_LENGTH: usize = 0x06;
const VEHICLE_READER_TYPE_VIN_OFFSET: usize = 0x00;
const VEHICLE_READER_TYPE_CUSTOM1_OFFSET: usize = 0x02;
const VEHICLE_READER_TYPE_CODE_OFFSET: usize = 0x03;
const VEHICLE_READER_TYPE_CUSTOM2_OFFSET: usize = 0x05;
const VEHICLE_READER_ID_LENGTH_MIN: usize = 0x08;
const VEHICLE_READER_ID_LENGTH_MAX: usize = 0x14;
const VEHICLE_READER_RND_LENGTH: usize = 0x08;

pub const DEFAULT_READER_TYPE_VIN: u16 = 0x0102;
pub const DEFAULT_READER_TYPE_CUSTOM1: u8 = 0x03;
pub const DEFAULT_READER_TYPE_CODE: u16 = 0x0405;
pub const DEFAULT_READER_TYPE_CUSTOM2: u8 = 0x06;
pub const DEFAULT_READER_ID: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xe, 0x0f, 0x00];
pub const DEFAULT_READER_KEY_PARAMETER: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
pub const DEFAULT_READER_AUTH_PARAMETER: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

lazy_static! {
    static ref VEHICLE_READER_TYPE: Mutex<VehicleReaderType> = Mutex::new(VehicleReaderType::default());
    static ref VEHICLE_READER_ID: Mutex<VehicleReaderId> = Mutex::new(VehicleReaderId::default());
    static ref VEHICLE_READER_RND: Mutex<VehicleReaderRnd> = Mutex::new(VehicleReaderRnd::generate());
    static ref VEHICLE_READER_KEY_PARAMETER: Mutex<VehicleReaderKeyParameter> = Mutex::new(VehicleReaderKeyParameter::default());
    static ref VEHICLE_READER_AUTH_PARAMETER: Mutex<VehicleReaderAuthParameter> = Mutex::new(VehicleReaderAuthParameter::default());
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct VehicleReaderType {
    vin: u16,
    custom1: u8,
    code: u16,
    custom2: u8,
}

impl Default for VehicleReaderType {
    fn default() -> Self {
        VehicleReaderType {
            vin: DEFAULT_READER_TYPE_VIN,
            custom1: DEFAULT_READER_TYPE_CUSTOM1,
            code: DEFAULT_READER_TYPE_CODE,
            custom2: DEFAULT_READER_TYPE_CUSTOM2,
        }
    }
}

#[allow(dead_code)]
impl VehicleReaderType {
    pub fn new(vin: u16, custom1: u8, code: u16, custom2: u8) -> Self {
        VehicleReaderType {
            vin,
            custom1,
            code,
            custom2,
        }
    }
    pub fn get_vin(&self) -> u16 {
        self.vin
    }
    pub fn set_vin(&mut self, vin: u16) {
        self.vin = vin;
    }
    pub fn get_custom1(&self) -> u8 {
        self.custom1
    }
    pub fn set_custom1(&mut self, custom1: u8) {
        self.custom1 = custom1;
    }
    pub fn get_code(&self) -> u16 {
        self.code
    }
    pub fn set_code(&mut self, code: u16) {
        self.code = code;
    }
    pub fn get_custom2(&self) -> u8 {
        self.custom2
    }
    pub fn set_custom2(&mut self, custom2: u8) {
        self.custom2 = custom2;
    }
}

impl Serde for VehicleReaderType {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(6);
        buffer.append(&mut self.get_vin().to_be_bytes().to_vec());
        buffer.push(self.get_custom1());
        buffer.append(&mut self.get_code().to_be_bytes().to_vec());
        buffer.push(self.get_custom2());
        Ok(buffer)
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        if data.len() != VEHICLE_READER_TYPE_LENGTH {
            return Err("vehicle reader type length error".to_string().into());
        }
        let vin = u16::from_be_bytes(
            (&data[VEHICLE_READER_TYPE_VIN_OFFSET..VEHICLE_READER_TYPE_CUSTOM1_OFFSET])
                .try_into()
                .map_err(|_| ErrorKind::VehicleInfoError("deserialize reader type vin error".to_string()))?
        );
        let custom1 = data[VEHICLE_READER_TYPE_CUSTOM1_OFFSET];
        let code = u16::from_be_bytes(
            (&data[VEHICLE_READER_TYPE_CODE_OFFSET..VEHICLE_READER_TYPE_CUSTOM2_OFFSET])
                .try_into()
                .map_err(|_| ErrorKind::VehicleInfoError("deserialize reader type code error".to_string()))?
        );
        let custom2 = data[VEHICLE_READER_TYPE_CUSTOM2_OFFSET];
        Ok(VehicleReaderType::new(
            vin,
            custom1,
            code,
            custom2,
        ))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleReaderId {
    inner: Vec<u8>,
}

impl Default for VehicleReaderId {
    fn default() -> Self {
        VehicleReaderId {
            inner: DEFAULT_READER_ID.to_vec(),
        }
    }
}

#[allow(dead_code)]
impl VehicleReaderId {
    pub fn new(reader_id: &[u8]) -> Self {
        VehicleReaderId {
            inner: reader_id.to_vec(),
        }
    }
    pub fn get_reader_id(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_reader_id(&mut self, reader_id: &[u8]) {
        self.inner = reader_id.to_vec();
    }
}

impl Serde for VehicleReaderId {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_reader_id().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        if data.len() < VEHICLE_READER_ID_LENGTH_MIN ||
            data.len() > VEHICLE_READER_ID_LENGTH_MAX {
            return Err(ErrorKind::VehicleInfoError("vehicle reader id length error".to_string()).into());
        }
        Ok(VehicleReaderId::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleReaderRnd {
    inner: Vec<u8>,
}

#[allow(dead_code)]
impl VehicleReaderRnd {
    pub fn new(rnd: &[u8]) -> Self {
        VehicleReaderRnd {
            inner: rnd.to_vec(),
        }
    }
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut random = Vec::with_capacity(VEHICLE_READER_RND_LENGTH);
        for _ in 0.. VEHICLE_READER_RND_LENGTH {
            random.push(rng.gen::<u8>());
        }
        VehicleReaderRnd {
            inner: random,
        }
    }
    pub fn get_reader_rnd(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_reader_rnd(&mut self, rnd: &[u8]) {
        self.inner = rnd.to_vec();
    }
}

impl Serde for VehicleReaderRnd {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_reader_rnd().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        if data.len() != VEHICLE_READER_RND_LENGTH {
            return Err(ErrorKind::VehicleInfoError("deserialize vehicle reader rnd length error".to_string()).into());
        }
        Ok(VehicleReaderRnd::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleReaderKeyParameter {
    inner: Vec<u8>,
}

impl Default for VehicleReaderKeyParameter {
    fn default() -> Self {
        VehicleReaderKeyParameter {
            inner: DEFAULT_READER_KEY_PARAMETER.to_vec(),
        }
    }
}

#[allow(dead_code)]
impl VehicleReaderKeyParameter {
    pub fn new(parameter: &[u8]) -> Self {
        VehicleReaderKeyParameter {
            inner: parameter.to_vec(),
        }
    }
    pub fn get_reader_key_parameter(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_reader_key_parameter(&mut self, parameter: &[u8]) {
        self.inner = parameter.to_vec();
    }
}

impl Serde for VehicleReaderKeyParameter {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_reader_key_parameter().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        Ok(VehicleReaderKeyParameter::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct VehicleReaderAuthParameter {
    inner: Vec<u8>,
}

impl Default for VehicleReaderAuthParameter {
    fn default() -> Self {
        VehicleReaderAuthParameter {
            inner: DEFAULT_READER_AUTH_PARAMETER.to_vec(),
        }
    }
}

impl VehicleReaderAuthParameter {
    pub fn new(parameter: &[u8]) -> Self {
        VehicleReaderAuthParameter {
            inner: parameter.to_vec(),
        }
    }
    pub fn get_reader_auth_parameter(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_reader_auth_parameter(&mut self, parameter: &[u8]) {
        self.inner = parameter.to_vec();
    }
}

impl Serde for VehicleReaderAuthParameter {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_reader_auth_parameter().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        Ok(VehicleReaderAuthParameter::new(data))
    }
}

#[allow(dead_code)]
pub fn get_vehicle_reader_type() -> VehicleReaderType {
    let vehicle_reader_type = VEHICLE_READER_TYPE.lock().unwrap();
    *vehicle_reader_type
}

#[allow(dead_code)]
pub fn set_vehicle_reader_type(reader_type: &VehicleReaderType) {
    let mut vehicle_reader_type = VEHICLE_READER_TYPE.lock().unwrap();
    vehicle_reader_type.set_vin(reader_type.get_vin());
    vehicle_reader_type.set_custom1(reader_type.get_custom1());
    vehicle_reader_type.set_code(reader_type.get_code());
    vehicle_reader_type.set_custom2(reader_type.get_custom2());
}

#[allow(dead_code)]
pub fn get_vehicle_reader_id() -> VehicleReaderId {
    let vehicle_reader_id = VEHICLE_READER_ID.lock().unwrap();
    VehicleReaderId::new(vehicle_reader_id.get_reader_id())
}

#[allow(dead_code)]
pub fn set_vehicle_reader_id(reader_id: &VehicleReaderId) {
    let mut vehicle_reader_id = VEHICLE_READER_ID.lock().unwrap();
    vehicle_reader_id.set_reader_id(reader_id.get_reader_id());
}

#[allow(dead_code)]
pub fn get_vehicle_reader_rnd() -> VehicleReaderRnd {
    let vehicle_reader_rnd = VEHICLE_READER_RND.lock().unwrap();
    VehicleReaderRnd::new(vehicle_reader_rnd.get_reader_rnd())
}

#[allow(dead_code)]
pub fn update_vehicle_reader_rnd() {
    let mut vehicle_reader_rnd = VEHICLE_READER_RND.lock().unwrap();
    *vehicle_reader_rnd = VehicleReaderRnd::generate();
}

#[allow(dead_code)]
pub fn get_vehicle_reader_key_parameter() -> VehicleReaderKeyParameter {
    let vehicle_reader_key_parameter = VEHICLE_READER_KEY_PARAMETER.lock().unwrap();
    VehicleReaderKeyParameter::new(vehicle_reader_key_parameter.get_reader_key_parameter())
}

#[allow(dead_code)]
pub fn set_vehicle_reader_key_parameter(parameter: &VehicleReaderKeyParameter) {
    let mut vehicle_reader_key_parameter = VEHICLE_READER_KEY_PARAMETER.lock().unwrap();
    vehicle_reader_key_parameter.set_reader_key_parameter(parameter.get_reader_key_parameter());
}

#[allow(dead_code)]
pub fn get_vehicle_reader_auth_parameter() -> VehicleReaderAuthParameter {
    let vehicle_reader_auth_parameter = VEHICLE_READER_AUTH_PARAMETER.lock().unwrap();
    VehicleReaderAuthParameter::new(vehicle_reader_auth_parameter.get_reader_auth_parameter())
}

#[allow(dead_code)]
pub fn set_vehicle_reader_auth_parameter(parameter: &VehicleReaderAuthParameter) {
    let mut vehicle_reader_auth_parameter = VEHICLE_READER_AUTH_PARAMETER.lock().unwrap();
    vehicle_reader_auth_parameter.set_reader_auth_parameter(parameter.get_reader_auth_parameter());
}
