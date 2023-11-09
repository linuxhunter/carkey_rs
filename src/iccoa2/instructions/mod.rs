mod common;
mod select;
mod list_dk;
mod auth_0;
mod auth_1;
mod get_dk_certificate;
mod sharing_request;
mod rke;
mod sign;
mod enable_disable;
mod get_challenge;
mod get_response;

const VERSION_TAG: u8 = 0x5A;
const RANDOM_TAG: u8 = 0x55;
const RKE_CMD_TAG: u8 = 0x57;
const VEHICLE_TEMP_PUB_KEY_TAG: u8 = 0x81;
const VEHICLE_ID_TAG: u8 = 0x83;
const DEVICE_TEMP_PUB_KEY_TAG: u8 = 0x84;
const CRYPTO_GRAM_TAG: u8 = 0x85;
const KEY_ID_STATUS_TAG: u8 = 0x88;
const KEY_ID_TAG: u8 = 0x89;
const SIGNATURE_TAG: u8 = 0x8F; //origin 0x9F

#[derive(Debug, PartialOrd, PartialEq)]
pub enum ApduInstructions {
    Select,
    CreateDK,
    StoreDK,
    DeleteDK,
    ListDK,
    ControlFlow,
    Auth0,
    Auth1,
    SharingRequest,
    Rke,
    Sign,
    DisableDK,
    EnableDK,
    GetChallenge,
    GetResponse,
}

/*
impl ApduInstructions {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        todo!()
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        todo!()
    }
}

impl Display for ApduInstructions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
*/