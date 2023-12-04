use tokio::sync::mpsc::Sender;
use crate::iccoa::{command, objects};
use crate::iccoa::notification::{senseless_control, vehicle_status, vehicle_unsafe};
use crate::iccoa::objects::Iccoa;

pub async fn ble_send_demos(sender: Sender<Vec<u8>>) {
    let mut index = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let request = match index {
            0x00 => {
                command::ranging::create_iccoa_ranging_request_package().unwrap()
            },
            0x01 => {
                vehicle_status::create_iccoa_total_mileage_notification().unwrap()
            },
            0x02 => {
                vehicle_status::create_iccoa_rechange_mileage_notification().unwrap()
            },
            0x03 => {
                vehicle_status::create_iccoa_remaining_battery_notification().unwrap()
            },
            0x04 => {
                vehicle_status::create_iccoa_power_state_notification().unwrap()
            },
            0x05 => {
                vehicle_status::create_iccoa_door_lock_status_notification().unwrap()
            },
            0x06 => {
                vehicle_status::create_iccoa_door_open_status_notification().unwrap()
            },
            0x07 => {
                vehicle_status::create_iccoa_door_window_status_notification().unwrap()
            },
            0x08 => {
                vehicle_status::create_iccoa_front_hatch_status_notification().unwrap()
            },
            0x09 => {
                vehicle_status::create_iccoa_back_trunk_status_notification().unwrap()
            },
            0x0A => {
                vehicle_status::create_iccoa_sunroof_status_notification().unwrap()
            },
            0x0B => {
                vehicle_status::create_iccoa_headlight_status_notification().unwrap()
            },
            0x0C => {
                senseless_control::create_iccoa_senseless_control_passive_unlock_notification().unwrap()
            },
            0x0D => {
                senseless_control::create_iccoa_senseless_control_passive_lock_notification().unwrap()
            },
            0x0E => {
                senseless_control::create_iccoa_senseless_control_near_auto_unlock_notification().unwrap()
            },
            0x0F => {
                senseless_control::create_iccoa_senseless_control_far_auto_lock_notification().unwrap()
            },
            0x10 => {
                senseless_control::create_iccoa_senseless_control_one_key_start_notification().unwrap()
            },
            0x11 => {
                senseless_control::create_iccoa_senseless_control_welcome_notification().unwrap()
            },
            0x12 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_power_state_notification().unwrap()
            },
            0x13 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_door_lock_state_notification().unwrap()
            },
            0x14 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_door_open_state_notification().unwrap()
            },
            0x15 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_door_window_state_notification().unwrap()
            },
            0x16 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_front_hatch_state_notification().unwrap()
            },
            0x17 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_back_trunk_state_notification().unwrap()
            },
            0x18 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_sunroof_state_notification().unwrap()
            },
            0x19 => {
                vehicle_unsafe::create_iccoa_vehicle_unsafe_headlight_state_notification().unwrap()
            },
            _ => {
                Iccoa::new()
            },
        };
        if index > 0x19 {
            index = 0;
            continue;
        }
        index += 1;
        if let Some(splitted_request) = objects::split_iccoa(&request) {
            for request in splitted_request {
                let _ = sender.send(request.serialize()).await;
            }
        } else {
            let _ = sender.send(request.serialize()).await;
        }
    }
}
