use tokio::sync::mpsc::Sender;
use crate::icce;

pub async fn ble_send_demos(sender: Sender<Vec<u8>>) {
    let mut index = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if !icce::objects::is_session_key_valid() {
            continue;
        }
        let icce_package = match index {
            0x00 => {
                icce::command::test_create_measure_request()
            },
            0x01 => {
                icce::command::test_craate_anti_relay_request()
            },
            0x02 => {
                icce::command::test_create_mobile_info_request()
            },
            0x03 => {
                icce::command::test_create_calbriate_time_request()
            },
            0x04 => {
                icce::command::test_create_protocol_request()
            },
            0x05 => {
                icce::notification::test_create_vehicle_event_request()
            },
            0x06 => {
                icce::notification::test_create_app_event_request()
            },
            _ => {
                icce::notification::test_create_server_event_request()
            }
        };
        println!("sending icce_package is {:02X?}", icce_package);
        let _ = sender.send(icce_package).await;
        index += 1;
        if index > 0x07 {
            index = 0;
        }
    }
}
