pub mod vehicle_status;
pub mod senseless_control;
pub mod vehicle_unsafe;

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq)]
    pub struct CarDoorLockStatus: u8 {
        const FRONT_LEFT_UNLOCK     = 0b0000_0001;
        const FRONT_RIGHT_UNLOCK    = 0b0000_0010;
        const BACK_LEFT_UNLOCK      = 0b0000_0100;
        const BACK_RIGHT_UNLOCK     = 0b0000_1000;
    }
}

impl CarDoorLockStatus {
    pub fn as_u8(&self) -> u8 {
        self.bits()
    }
}

bitflags! {
    pub struct CarDoorStatus: u8 {
        const FRONT_LEFT_OPEN   = 0b0000_0001;
        const FRONT_RIGHT_OPEN  = 0b0000_0010;
        const BACK_LEFT_OPEN    = 0b0000_0100;
        const BACK_RIGHT_OPEN   = 0b0000_1000;
    }
}

impl CarDoorStatus {
    pub fn as_u8(&self) -> u8 {
        self.bits()
    }
}

bitflags! {
    pub struct CarDoorWindowStatus: u8 {
        const FRONT_LEFT_OPEN   = 0b0000_0001;
        const FRONT_RIGHT_OPEN  = 0b0000_0010;
        const BACK_LEFT_OPEN    = 0b0000_0100;
        const BACK_RIGHT_OPEN   = 0b0000_1000;
    }
}

impl CarDoorWindowStatus {
    pub fn as_u8(&self) -> u8 {
        self.bits()
    }
}
