#![recursion_limit = "1024"]
#[macro_use]
extern crate lazy_static;

mod bluetooth;
mod icce;
mod iccoa;

use bluer::{adv::Advertisement, UuidExt, AdapterEvent, DeviceEvent, DeviceProperty};
use bluer::gatt::local::{Application, Service, Characteristic, CharacteristicNotify, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod};
use futures::{FutureExt, pin_mut, stream::SelectAll, StreamExt};
use tokio::sync::{mpsc, broadcast};
use uuid::Uuid;

use crate::bluetooth::agent;
use crate::iccoa::objects::ICCOA;
use crate::iccoa::{bluetooth_io, objects, command, pairing};
use crate::iccoa::notification::senseless_control;
use crate::iccoa::notification::vehicle_status;
use crate::iccoa::notification::vehicle_unsafe;

lazy_static! {
    static ref SERVICE_UUID: Uuid = Uuid::from_u16(0xFCD1);
    static ref WRITE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFD);
    static ref READ_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFE);
}

fn test_create_measure_request() -> Vec<u8> {
    let measure_type = 0x01;
    let icce = icce::objects::create_icce_measure_request(measure_type);
    icce.serialize()
}

fn test_craate_anti_relay_request() -> Vec<u8> {
    let measure_type = 0x01;
    let vehicle_info = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let icce = icce::objects::create_icce_anti_relay_request(measure_type, &vehicle_info);
    icce.serialize()
}

fn test_create_mobile_info_request() -> Vec<u8> {
    let request_type = 0x01;
    let icce = icce::objects::create_icce_get_mobile_info_request(request_type);
    icce.serialize()
}

fn test_create_calbriate_time_request() -> Vec<u8> {
    let icce = icce::objects::create_icce_calibrate_clock_request();
    icce.serialize()
}

fn test_create_protocol_request() -> Vec<u8> {
    let vehicle_protocol = vec![0x01, 0x02, 0x03, 0x04];
    let icce = icce::objects::create_icce_get_protocol_request(&vehicle_protocol);
    icce.serialize()
}

fn test_create_vehicle_event_request() -> Vec<u8> {
    let vehicle_event = 0x00;
    let async_result = vec![0x11, 0x22, 0x33, 0x44];
    let vehicle_state = vec![0x55, 0x66, 0x77, 0x88];
    let icce = icce::objects::create_icce_vehicle_state_event_request(vehicle_event, &async_result, &vehicle_state);
    icce.serialize()
}

fn test_create_app_event_request() -> Vec<u8> {
    let app_data = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let icce = icce::objects::create_icce_vehicle_to_app_event_request(&app_data);
    icce.serialize()
}

fn test_create_server_event_request() -> Vec<u8> {
    let server_data = vec![0xff, 0xee, 0xdd, 0xcc];
    let icce = icce::objects::create_icce_vehicle_to_server_event_request(&server_data);
    icce.serialize()
}

const MEASURED_BASE: f32 = 10.0;
const MEASURED_POWER: f32 = -69.0;
const MEASURED_N: f32 = 3.0;
fn calculate_distance_by_rssi(rssi: i16) -> f32 {
    let exponent = (MEASURED_POWER - rssi as f32) / (10 as f32 * MEASURED_N);
    let distance = MEASURED_BASE.powf(exponent);
    distance
}

#[tokio::main]
async fn main() -> bluer::Result<()> {
    let (bt_write_tx, mut bt_write_rx) = mpsc::channel(32);
    let (bt_notify_tx, _) = broadcast::channel::<Vec<u8>>(32);
    let bt_notify_tx2 = bt_notify_tx.clone();
    let bt_notify_tx3 = bt_notify_tx.clone();
    let (bt_send_package_tx, mut bt_send_package_rx) = mpsc::channel::<Vec<u8>>(32);

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let agent_handle = agent::register_agent(&session, true, true).await?;

    let le_advertisement = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![*SERVICE_UUID].into_iter().collect(),
        discoverable: Some(true),
        local_name: Some("Neusoft".to_string()),
        ..Default::default()
    };
    let adv_handle = adapter.advertise(le_advertisement).await?;
    
    let timeout: u32 = 300;
    adapter.set_pairable_timeout(timeout).await?;
    adapter.set_pairable(true).await?;

    let app = Application {
        services: vec![Service {
            uuid: *SERVICE_UUID,
            primary: true,
            characteristics: vec![Characteristic {
                uuid: *WRITE_CHARACTERISTIC_UUID,
                write: Some(CharacteristicWrite {
                    write: true,
                    write_without_response: true,
                    encrypt_authenticated_write: true,
                    method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, _req| {
                        let bt_write_tx = bt_write_tx.clone();
                        async move {
                            let _ = bt_write_tx.send(new_value).await;
                            Ok(())
                        }.boxed()
                    })),
                    ..Default::default()
                }),
                read: None,
                notify: None,
                ..Default::default()
            }, Characteristic {
                uuid: *READ_CHARACTERISTIC_UUID,
                write: None,
                read: Some(CharacteristicRead {
                    read: true,
                    encrypt_authenticated_read: true,
                    fun: Box::new(move |_req| {
                        async move {
                            Ok(vec![])
                        }.boxed()
                    }),
                    ..Default::default()
                }),
                notify: Some(CharacteristicNotify {
                    notify: true,
                    method: bluer::gatt::local::CharacteristicNotifyMethod::Fun(Box::new(move |mut notifier| {
                        let bt_notify_tx = bt_notify_tx2.clone();
                        async move {
                            tokio::spawn(async move {
                                if notifier.is_stopped() == false {
                                    /*
                                    let icce = icce::objects::create_icce_auth_get_process_data_request();
                                    if let Err(err) = notifier.notify(icce.serialize()).await {
                                        println!("Notification error when setting get process data request: {}", err);
                                    }
                                    */
                                    let pairing_request = pairing::create_iccoa_pairing_data_request_package().unwrap();
                                    println!("pairing request = {:02X?}", pairing_request);
                                    if let Err(err) = notifier.notify(pairing_request).await {
                                        println!("Notification error when setting get process data request: {}", err);
                                    }
                                }
                                let mut bt_notify_rx = bt_notify_tx.subscribe();
                                while let Ok(notify_data) = bt_notify_rx.recv().await {
                                    if let Err(err) = notifier.notify(notify_data).await {
                                        println!("Notification error: {}", err);
                                        break;
                                    }
                                }
                            });
                        }.boxed()
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let app_handle = adapter.serve_gatt_application(app).await?;

    let device_events = adapter.discover_devices().await?;
    pin_mut!(device_events);
    let mut all_change_events = SelectAll::new();
/*
    //test code for sending message from vehicle to mobile by notification
    tokio::spawn(async move {
        let mut index = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if icce::objects::is_session_key_valid() == false {
                continue;
            }
            let icce_package = match index {
                0x00 => {
                    test_create_measure_request()
                },
                0x01 => {
                    test_craate_anti_relay_request()
                },
                0x02 => {
                    test_create_mobile_info_request()
                },
                0x03 => {
                    test_create_calbriate_time_request()
                },
                0x04 => {
                    test_create_protocol_request()
                },
                0x05 => {
                    test_create_vehicle_event_request()
                },
                0x06 => {
                    test_create_app_event_request()
                },
                _ => {
                    test_create_server_event_request()
                }
            };
            println!("sending icce_package is {:02X?}", icce_package);
            let _ = bt_send_package_tx.send(icce_package).await;
            index += 1;
            if index > 0x07 {
                index = 0;
            }
        }
    });
*/

    //test code for sending message from vehicle to mobile by notification
    tokio::spawn(async move {
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
                    ICCOA::new()
                },
            };
            if index > 0x19 {
                index = 0;
                continue;
            }
            index += 1;
            if let Some(splitted_request) = objects::split_iccoa(&request) {
                for request in splitted_request {
                    let _ = bt_send_package_tx.send(request.serialize()).await;
                }
            } else {
                let _ = bt_send_package_tx.send(request.serialize()).await;
            }
        }
    });

    println!("Server ready. Press ctrl-c to quit");
    loop {
        tokio::select! {
            Some(device_event) = device_events.next() => {
                match device_event {
                    AdapterEvent::DeviceAdded(addr) => {
                        let device = adapter.device(addr)?;
                        if device.is_trusted().await? {
                            let change_events = device.events().await?.map(move |evt| (addr, evt));
                            all_change_events.push(change_events);
                        }
                    },
                    _ => (),
                }
            },
            Some((addr, DeviceEvent::PropertyChanged(DeviceProperty::Rssi(rssi)))) = all_change_events.next() => {
                println!("Device {}, distance: {}m", addr, calculate_distance_by_rssi(rssi));
            },
            Some(data_package) = bt_write_rx.recv() => {
                println!("GOT ICCOA Package from Mobile = {:02X?}", data_package);
                if let Ok(response) = bluetooth_io::handle_data_package_from_mobile(&data_package) {
                    if let Some(splitted_response) = objects::split_iccoa(&response) {
                        for response in splitted_response {
                            let _ = bt_notify_tx.send(response.serialize());
                        }
                    } else {
                        let _ = bt_notify_tx.send(response.serialize());
                    }
                }
                /*
                if let Ok(response) = icce::objects::handle_data_package_from_mobile(&data_package) {
                    if let Some(splitted_response) = icce::objects::split_icce(&response) {
                        for response in splitted_response {
                            let _ = bt_notify_tx.send(response.serialize());
                        }
                    } else {
                        let _ = bt_notify_tx.send(response.serialize());
                    }
                }
                */
                /*
                println!("GOT ICCE Package from Mobile = {:02X?}", icce_package);
                if let Ok(mut icce_object) = icce::objects::ICCE::deserialize(&icce_package) {
                    println!("icce_object is {:?}", icce_object);
                    let icce_header_control = icce_object.get_header().get_control();
                    if icce_header_control.is_first_frag() || icce_header_control.is_conti_frag() {
                        icce::objects::collect_icce_fragments(icce_object);
                        continue;
                    }
                    if icce_header_control.is_last_frag() {
                        icce::objects::collect_icce_fragments(icce_object);
                        icce_object = icce::objects::reassemble_icce_fragments();
                    }
                    if icce_header_control.is_request() {
                        if let Ok(response) = icce::objects::handle_icce_mobile_request(&icce_object) {
                            if response.len() > 1 {
                                let _ = bt_notify_tx.send(response);
                            }
                        }
                    } else {
                        if let Ok(response) = icce::objects::handle_icce_mobile_response(&icce_object) {
                            if response.len() > 0 {
                                let _ = bt_notify_tx.send(response);
                            }
                        }
                    }
                } else {
                    println!("Error on ICCE deserialized");
                }
                */
            },
            Some(icce_package) = bt_send_package_rx.recv() => {
                println!("GOT ICCE Package from Vehicle = {:02X?}", icce_package);
                let _ = bt_notify_tx3.send(icce_package);
            },
            Ok(_) = tokio::signal::ctrl_c() => break,
            else => break,
        }
    }

    println!("Removing service and advertisement");
    adapter.set_pairable(false).await?;
    drop(app_handle);
    drop(adv_handle);
    drop(agent_handle);
    Ok(())
}
