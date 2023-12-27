use log::debug;
use tokio::sync::mpsc::Sender;
use crate::icce;

pub async fn ble_send_demos(sender: Sender<Vec<u8>>) {
    let mut index = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if !icce::session::is_session_key_valid() {
            continue;
        }
        let icce_package = match index {
            0x00 => {
                icce::command::test_create_rssi_measure_request()
            },
            0x01 => {
                icce::command::test_create_uwb_measure_request()
            },
            0x02 => {
                icce::command::test_create_hadm_measure_request()
            },
            0x03 => {
                icce::command::test_create_rssi_anti_relay_request()
            },
            0x04 => {
                icce::command::test_create_uwb_anti_relay_request()
            },
            0x05 => {
                icce::command::test_create_hadm_anti_replay_request()
            },
            0x06 => {
                icce::command::test_create_get_calibrate_data_mobile_info_request()
            },
            0x07 => {
                icce::command::test_create_get_anti_relay_result_mobile_info_request()
            },
            0x08 => {
                icce::command::test_create_get_custom_data_mobile_info_request()
            },
            0x09 => {
                icce::command::test_create_calbriate_time_request()
            },
            0x0A => {
                icce::command::test_create_protocol_request()
            },
            0x0B => {
                icce::notification::test_create_vehicle_instruction_success_event_request()
            },
            0x0C => {
                icce::notification::test_create_vehicle_instruction_failed_event_request()
            },
            0x0D => {
                icce::notification::test_create_vehicle_resend_event_request()
            },
            0x0E => {
                icce::notification::test_create_vehicle_locked_event_request()
            },
            0x0F => {
                icce::notification::test_create_vehicle_unlocked_event_request()
            },
            0x10 => {
                icce::notification::test_create_vehicle_engine_stopped_event_request()
            },
            0x11 => {
                icce::notification::test_create_vehicle_engine_started_event_request()
            },
            0x12 => {
                icce::notification::test_create_vehicle_clock_reset_event_request()
            },
            0x13 => {
                icce::notification::test_create_vehicle_bluetooth_disconnect_event_request()
            },
            0x14 => {
                icce::notification::test_create_app_event_request()
            },
            0x15 => {
                icce::notification::test_create_server_event_request()
            },
            _ => {
                vec![]
            }
        };
        debug!("sending icce_package is {:02X?}", icce_package);
        let _ = sender.send(icce_package).await;
        index += 1;
        if index > 0x15 {
            index = 0;
        }
    }
}
