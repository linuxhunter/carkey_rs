mod common;
mod select;

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