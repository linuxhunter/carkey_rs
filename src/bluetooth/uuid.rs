use std::str::FromStr;

use bluer::UuidExt;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct UuidOrShort(pub Uuid);

impl FromStr for UuidOrShort {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<UuidOrShort, std::string::String> {
        match s.parse::<Uuid>() {
            Ok(uuid) => Ok(Self(uuid)),
            Err(_) => {
                match u16::from_str_radix(s, 16) {
                    Ok(short) => Ok(Self(Uuid::from_u16(short))),
                    Err(_) => Err(s.to_string()),
                }
            }
        }
    }
}

impl From<UuidOrShort> for Uuid {
    fn from(value: UuidOrShort) -> Self {
        value.0
    }
}

impl From<Uuid> for UuidOrShort {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for UuidOrShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = self.0.as_u16() {
            write!(f, "{:04x}", s)
        } else {
            write!(f, "{}", self.0)
        }
    }
}
