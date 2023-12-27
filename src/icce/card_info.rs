use std::sync::Mutex;
use crate::icce::Serde;
use crate::icce::errors::*;

const CARD_SE_ID_LENGTH: usize = 0x08;
const CARD_ID_LENGTH: usize = 0x10;
const CARD_RND_LENGTH: usize = 0x08;
const CARD_ATC_LENGTH: usize = 0x04;
#[allow(dead_code)]
const CARD_IV_LENGTH: usize = 0x10;

lazy_static! {
    static ref CARD_SE_ID: Mutex<CardSeId> = Mutex::new(CardSeId::default());
    static ref CARD_ID: Mutex<CardId> = Mutex::new(CardId::default());
    static ref CARD_RND: Mutex<CardRnd> = Mutex::new(CardRnd::default());
    static ref CARD_ATC: Mutex<CardATC> = Mutex::new(CardATC::default());
    static ref CARD_INFO1: Mutex<CardInfo1> = Mutex::new(CardInfo1::default());
    static ref CARD_IV: Mutex<CardIV> = Mutex::new(CardIV::default());
    static ref CARD_AUTH_PARAMETER: Mutex<CardAuthParameter> = Mutex::new(CardAuthParameter::default());
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CardSeId {
    inner: Vec<u8>,
}

impl Default for CardSeId {
    fn default() -> Self {
        CardSeId {
            inner: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        }
    }
}

#[allow(dead_code)]
impl CardSeId {
    pub fn new(id: &[u8]) -> Self {
        CardSeId {
            inner: id.to_vec(),
        }
    }
    pub fn get_card_se_id(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_card_se_id(&mut self, id: &[u8]) {
        self.inner = id.to_vec();
    }
}

impl Serde for CardSeId {
    type Output = Self;

    fn serialize(&self) -> crate::icce::errors::Result<Vec<u8>> {
        Ok(self.get_card_se_id().to_vec())
    }

    fn deserialize(data: &[u8]) -> crate::icce::errors::Result<Self::Output> {
        if data.len() != CARD_SE_ID_LENGTH {
            return Err(ErrorKind::CardInfoError("deserialize card se id length error".to_string()).into());
        }
        Ok(CardSeId::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CardId {
    inner: Vec<u8>,
}

impl Default for CardId {
    fn default() -> Self {
        CardId {
            inner: vec![0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00],
        }
    }
}

#[allow(dead_code)]
impl CardId {
    pub fn new(id: &[u8]) -> Self {
        CardId {
            inner: id.to_vec(),
        }
    }
    pub fn get_card_id(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_card_id(&mut self, id: &[u8]) {
        self.inner = id.to_vec();
    }
}

impl Serde for CardId {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_card_id().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        if data.len() != CARD_ID_LENGTH {
            return Err(ErrorKind::CardInfoError("deserialize card id length error".to_string()).into());
        }
        Ok(CardId::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CardRnd {
    inner: Vec<u8>,
}

impl Default for CardRnd {
    fn default() -> Self {
        CardRnd {
            inner: vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        }
    }
}

#[allow(dead_code)]
impl CardRnd {
    pub fn new(rnd: &[u8]) -> Self {
        CardRnd {
            inner: rnd.to_vec(),
        }
    }
    pub fn get_card_rnd(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_card_rnd(&mut self, rnd: &[u8]) {
        self.inner = rnd.to_vec();
    }
}

impl Serde for CardRnd {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_card_rnd().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        if data.len() != CARD_RND_LENGTH {
            return Err(ErrorKind::CardInfoError("deserialize card rnd length error".to_string()).into());
        }
        Ok(CardRnd::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CardInfo1 {
    inner: Vec<u8>,
}

impl Default for CardInfo1 {
    fn default() -> Self {
        CardInfo1 {
            inner: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        }
    }
}

#[allow(dead_code)]
impl CardInfo1 {
    pub fn new(info: &[u8]) -> Self {
        CardInfo1 {
            inner: info.to_vec(),
        }
    }
    pub fn get_card_info1(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_card_info1(&mut self, info: &[u8]) {
        self.inner = info.to_vec();
    }
}

impl Serde for CardInfo1 {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_card_info1().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        Ok(CardInfo1::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CardATC {
    inner: Vec<u8>,
}

impl Default for CardATC {
    fn default() -> Self {
        CardATC {
            inner: vec![0x01, 0x02, 0x03, 0x04],
        }
    }
}

#[allow(dead_code)]
impl CardATC {
    pub fn new(atc: &[u8]) -> Self {
        CardATC {
            inner: atc.to_vec(),
        }
    }
    pub fn get_card_atc(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_card_atc(&mut self, atc: &[u8]) {
        self.inner = atc.to_vec();
    }
}

impl Serde for CardATC {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_card_atc().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        if data.len() != CARD_ATC_LENGTH {
            return Err(ErrorKind::CardInfoError("deserialize card atc length error".to_string()).into());
        }
        Ok(CardATC::new(data))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CardIV {
    inner: Vec<u8>,
}

impl Default for CardIV {
    fn default() -> Self {
        CardIV {
            inner: vec![0x00; 16],
        }
    }
}

#[allow(dead_code)]
impl CardIV {
    pub fn new(iv: &[u8]) -> Self {
        CardIV {
            inner: iv.to_vec(),
        }
    }
    pub fn get_card_iv(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_card_iv(&mut self, iv: &[u8]) {
        self.inner = iv.to_vec();
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct CardAuthParameter {
    inner: Vec<u8>,
}

impl Default for CardAuthParameter {
    fn default() -> Self {
        CardAuthParameter {
            inner: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        }
    }
}

impl CardAuthParameter {
    pub fn new(parameter: &[u8]) -> Self {
        CardAuthParameter {
            inner: parameter.to_vec(),
        }
    }
    pub fn get_card_auth_parameter(&self) -> &[u8] {
        &self.inner
    }
    pub fn set_card_auth_parameter(&mut self, parameter: &[u8]) {
        self.inner = parameter.to_vec();
    }
}

impl Serde for CardAuthParameter {
    type Output = Self;

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_card_auth_parameter().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self::Output> {
        Ok(CardAuthParameter::new(data))
    }
}

#[allow(dead_code)]
pub fn get_card_se_id() -> CardSeId {
    let card_se_id = CARD_SE_ID.lock().unwrap();
    CardSeId::new(card_se_id.get_card_se_id())
}

#[allow(dead_code)]
pub fn set_card_se_id(id: &CardSeId) {
    let mut card_se_id = CARD_SE_ID.lock().unwrap();
    card_se_id.set_card_se_id(id.get_card_se_id())
}

#[allow(dead_code)]
pub fn get_card_id() -> CardId {
    let card_id = CARD_ID.lock().unwrap();
    CardId::new(card_id.get_card_id())
}

#[allow(dead_code)]
pub fn set_card_id(id: &CardId) {
    let mut card_id = CARD_ID.lock().unwrap();
    card_id.set_card_id(id.get_card_id());
}

#[allow(dead_code)]
pub fn get_card_rnd() -> CardRnd {
    let card_rnd = CARD_RND.lock().unwrap();
    CardRnd::new(card_rnd.get_card_rnd())
}

#[allow(dead_code)]
pub fn set_card_rnd(rnd: &CardRnd) {
    let mut card_rnd = CARD_RND.lock().unwrap();
    card_rnd.set_card_rnd(rnd.get_card_rnd());
}

#[allow(dead_code)]
pub fn get_card_atc() -> CardATC {
    let card_atc = CARD_ATC.lock().unwrap();
    CardATC::new(card_atc.get_card_atc())
}

#[allow(dead_code)]
pub fn set_card_atc(atc: &CardATC) {
    let mut card_atc = CARD_ATC.lock().unwrap();
    card_atc.set_card_atc(atc.get_card_atc());
}

#[allow(dead_code)]
pub fn get_card_info1() -> CardInfo1 {
    let card_info1 = CARD_INFO1.lock().unwrap();
    CardInfo1::new(card_info1.get_card_info1())
}

#[allow(dead_code)]
pub fn set_card_info1(info: &CardInfo1) {
    let mut card_info1 = CARD_INFO1.lock().unwrap();
    card_info1.set_card_info1(info.get_card_info1());
}

#[allow(dead_code)]
pub fn get_card_iv() -> CardIV {
    let card_iv = CARD_IV.lock().unwrap();
    CardIV::new(card_iv.get_card_iv())
}

#[allow(dead_code)]
pub fn set_card_iv(iv: &CardIV) {
    let mut card_iv = CARD_IV.lock().unwrap();
    card_iv.set_card_iv(iv.get_card_iv());
}

#[allow(dead_code)]
pub fn get_card_auth_parameter() -> CardAuthParameter {
    let card_auth_parameter = CARD_AUTH_PARAMETER.lock().unwrap();
    CardAuthParameter::new(card_auth_parameter.get_card_auth_parameter())
}

#[allow(dead_code)]
pub fn set_card_auth_parameter(parameter: &CardAuthParameter) {
    let mut card_auth_parameter = CARD_AUTH_PARAMETER.lock().unwrap();
    card_auth_parameter.set_card_auth_parameter(parameter.get_card_auth_parameter());
}
