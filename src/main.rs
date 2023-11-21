#![recursion_limit = "1024"]
#[macro_use]
extern crate lazy_static;

mod bluetooth;
mod icce;
mod iccoa;
mod iccoa2;

use std::collections::BTreeMap;
use std::env;
use bluer::{adv::Advertisement, UuidExt, AdapterEvent, DeviceEvent, DeviceProperty};
use bluer::gatt::local::{Application, Service, Characteristic, CharacteristicNotify, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod};
use futures::{FutureExt, pin_mut, stream::SelectAll, StreamExt};
use log::{debug, error, info};
use tokio::sync::{mpsc, broadcast};
use uuid::Uuid;

use crate::bluetooth::agent;
use crate::bluetooth::ranging;
use crate::iccoa::objects::Iccoa;
use crate::iccoa::{bluetooth_io, objects, command, pairing};
use crate::iccoa2::Serde;
use crate::iccoa::notification::senseless_control;
use crate::iccoa::notification::vehicle_status;
use crate::iccoa::notification::vehicle_unsafe;

lazy_static! {
    static ref SERVICE_UUID: Uuid = Uuid::from_u16(0xFCD1);
    static ref WRITE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFD);
    static ref READ_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFE);
}

static BLUETOOTH_EVENTS_MAX: usize = 10;

#[derive(Debug, Default, Copy, Clone)]
enum CarkeyProtocol {
    #[default]
    Iccoa2,
    Iccoa,
    Icce,
}

impl From<&str> for CarkeyProtocol {
    fn from(value: &str) -> Self {
        match value.to_ascii_lowercase().as_ref() {
            "icce" => CarkeyProtocol::Icce,
            "iccoa" => CarkeyProtocol::Iccoa,
            "iccoa2" => CarkeyProtocol::Iccoa2,
            _ => CarkeyProtocol::Iccoa2,
        }
    }
}

#[tokio::main]
async fn main() -> bluer::Result<()> {
    let args: Vec<String> = env::args().collect();
    let protocol = if args.len() < 2 {
        CarkeyProtocol::default()
    } else {
        CarkeyProtocol::from(args[1].as_ref())
    };

    env_logger::init();
    let (bt_write_tx, mut bt_write_rx) = mpsc::channel(32);
    let (bt_notify_tx, _) = broadcast::channel::<Vec<u8>>(32);
    let bt_notify_tx2 = bt_notify_tx.clone();
    let (bt_send_package_tx, mut bt_send_package_rx) = mpsc::channel::<Vec<u8>>(32);

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let agent_handle = agent::register_agent(&session, true, true).await?;

    let le_advertisement = match protocol {
        CarkeyProtocol::Iccoa2 => {
            Advertisement {
                advertisement_type: bluer::adv::Type::Peripheral,
                service_uuids: vec![*SERVICE_UUID].into_iter().collect(),
                discoverable: Some(true),
                local_name: Some("Neusoft".to_string()),
                advertisting_data: BTreeMap::from([
                    (0x7F, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
                ]),
                ..Default::default()
            }
        }
        CarkeyProtocol::Iccoa => {
            Advertisement {
                advertisement_type: bluer::adv::Type::Peripheral,
                service_uuids: vec![*SERVICE_UUID].into_iter().collect(),
                discoverable: Some(true),
                local_name: Some("Neusoft".to_string()),
                ..Default::default()
            }
        }
        CarkeyProtocol::Icce => {
            Advertisement {
                advertisement_type: bluer::adv::Type::Peripheral,
                service_uuids: vec![*SERVICE_UUID].into_iter().collect(),
                discoverable: Some(true),
                local_name: Some("Neusoft".to_string()),
                ..Default::default()
            }
        }
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
                        let mut bt_notify_rx = bt_notify_tx.clone().subscribe();
                        async move {
                            tokio::spawn(async move {
                                if !notifier.is_stopped() {
                                    match protocol {
                                        CarkeyProtocol::Icce => {
                                            let icce = icce::auth::create_icce_auth_get_process_data_request();
                                            if let Err(err) = notifier.notify(icce.serialize()).await {
                                                println!("Notification error when setting get process data request: {}", err);
                                            }
                                        },
                                        CarkeyProtocol::Iccoa => {
                                            if let Ok(iccoa) = pairing::create_iccoa_pairing_data_request_init() {
                                                if let Err(err) = notifier.notify(iccoa.serialize()).await {
                                                    error!("Notification error when setting get process data request: {}", err);
                                                }
                                            }
                                        }
                                        CarkeyProtocol::Iccoa2 => {
                                            if let Ok(message) = iccoa2::message::create_measure_request_message() {
                                                if let Err(err) = notifier.notify(message.serialize().unwrap()).await {
                                                    error!("Notification error when setting get process data request: {}", err);
                                                }
                                            }
                                        }
                                    }
                                }
                                while let Ok(notify_data) = bt_notify_rx.recv().await {
                                    if let Err(err) = notifier.notify(notify_data).await {
                                        error!("Notification error: {}", err);
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

    let device_events = adapter.discover_devices_with_changes().await?;
    pin_mut!(device_events);
    let mut all_change_events = SelectAll::new();

    match protocol {
        CarkeyProtocol::Icce => {
            //test code for sending message from vehicle to mobile by notification
            tokio::spawn(async move {
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
                    let _ = bt_send_package_tx.send(icce_package).await;
                    index += 1;
                    if index > 0x07 {
                        index = 0;
                    }
                }
            });
        },
        CarkeyProtocol::Iccoa => {
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
                            let _ = bt_send_package_tx.send(request.serialize()).await;
                        }
                    } else {
                        let _ = bt_send_package_tx.send(request.serialize()).await;
                    }
                }
            });
        },
        CarkeyProtocol::Iccoa2 => {
            //test code for sending message from vehicle to mobile by notification
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    let request = iccoa2::message::create_measure_request_message().unwrap();
                    let _ = bt_send_package_tx.send(request.serialize().unwrap()).await;
                }
            });
        }
    }

    println!("Server ready. Press ctrl-c to quit");
    loop {
        tokio::select! {
            Some(device_event) = device_events.next() => {
                if let AdapterEvent::DeviceAdded(addr) = device_event {
                    let device = adapter.device(addr)?;
                    if device.is_trusted().await? {
                        let change_events = device.events().await?.map(move |evt| (addr, evt));
                        if all_change_events.len() <= BLUETOOTH_EVENTS_MAX {
                            all_change_events.push(change_events);
                        } else {
                            all_change_events.clear();
                        }
                    }
                }
            },
            Some((addr, DeviceEvent::PropertyChanged(DeviceProperty::Rssi(rssi)))) = all_change_events.next() => {
                ranging::update_rssi(addr, rssi);
            },
            Some(data_package) = bt_write_rx.recv() => {
                debug!("GOT Package from Mobile = {:02X?}", data_package);
                match protocol {
                    CarkeyProtocol::Icce => {
                        if let Ok(response) = icce::bluetooth_io::handle_data_package_from_mobile(&data_package) {
                            if let Some(splitted_response) = icce::objects::split_icce(&response) {
                                for response in splitted_response {
                                    let _ = bt_notify_tx2.send(response.serialize());
                                }
                            } else {
                                let _ = bt_notify_tx2.send(response.serialize());
                            }
                        }
                    },
                    CarkeyProtocol::Iccoa => {
                        if let Ok(response) = bluetooth_io::handle_data_package_from_mobile(&data_package) {
                            if let Some(splitted_response) = objects::split_iccoa(&response) {
                                for response in splitted_response {
                                    let _ = bt_notify_tx2.send(response.serialize());
                                }
                            } else {
                                let _ = bt_notify_tx2.send(response.serialize());
                            }
                        }
                    },
                    CarkeyProtocol::Iccoa2 => {
                        if let Ok(response) = iccoa2::bluetooth_io::handle_data_package_from_mobile(&data_package) {
                            let _ = bt_notify_tx2.send(response.serialize().unwrap());
                        }
                    }
                }
            },
            Some(sending_package) = bt_send_package_rx.recv() => {
                debug!("GOT Sending Package from Vehicle = {:02X?}", sending_package);
                let _ = bt_notify_tx2.clone().send(sending_package);
            },
            Ok(_) = tokio::signal::ctrl_c() => break,
            else => break,
        }
    }

    info!("Removing service and advertisement");
    adapter.set_pairable(false).await?;
    drop(app_handle);
    drop(adv_handle);
    drop(agent_handle);
    Ok(())
}
