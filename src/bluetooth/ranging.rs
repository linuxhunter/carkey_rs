use bluer::Address;
use log::debug;

static mut TEMP_RSSI: i16 = 0;
const MEASURED_BASE: f32 = 10.0;
const MEASURED_POWER: f32 = -69.0;
const MEASURED_N: f32 = 2.0;
fn calculate_distance_by_rssi(rssi: i16) -> f32 {
    let exponent = (MEASURED_POWER - rssi as f32) / (10_f32 * MEASURED_N);
    MEASURED_BASE.powf(exponent)
}

pub fn update_rssi(addr: Address, rssi: i16) {
    unsafe {
        if rssi != TEMP_RSSI {
            let distance = if TEMP_RSSI != 0 {
                calculate_distance_by_rssi((rssi + TEMP_RSSI) / 2)
            } else {
                calculate_distance_by_rssi(rssi)
            };
            TEMP_RSSI = rssi;
            debug!("Device {}, distance: {}m, rssi: {}", addr, distance, rssi);
        }
    }
}