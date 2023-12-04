use tokio::sync::mpsc::Sender;
use crate::iccoa2::{ble, Serde};
use crate::iccoa2::ble::bluetooth_io::{create_ble_measure_request_message, create_vehicle_server_custom_request};
use crate::iccoa2::ble::custom::VehicleServerCustomRequest;

pub async fn ble_send_demos(sender: Sender<Vec<u8>>) {
    let mut index = 0x00;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let request = match index {
            0x00 => {
                create_ble_measure_request_message(ble::measure::MeasureRequest::new(
                    ble::measure::MeasureType::BtRssi,
                    ble::measure::MeasureAction::Start,
                    ble::measure::MeasureDuration::new(0x20),
                )).unwrap()
            },
            0x01 => {
                create_ble_measure_request_message(ble::measure::MeasureRequest::new(
                    ble::measure::MeasureType::BtRssi,
                    ble::measure::MeasureAction::Stop,
                    ble::measure::MeasureDuration::new(0x20),
                )).unwrap()
            },
            0x02 => {
                create_vehicle_server_custom_request(VehicleServerCustomRequest::new(
                    0x0102,
                    0x03,
                )).unwrap()
            },
            _ => {
                todo!()
            }
        };
        if index <= 0x02 {
            let _ = sender.send(request.serialize().unwrap()).await;
        }
        if index == 0x02 {
            index = 0x00;
        } else {
            index += 1;
        }
    }
}
