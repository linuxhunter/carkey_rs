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
use crate::iccoa::{bluetooth_io, objects, pairing};
use crate::iccoa2::{Serde, tsp};

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
    let bt_send_package_tx2 = bt_send_package_tx.clone();
    let ble_demo_sender= bt_send_package_tx.clone();

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
                                            if let Ok(message) = iccoa2::ble::bluetooth_io::create_select_request_message() {
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
            tokio::spawn(icce::ble_send_demo::ble_send_demos(ble_demo_sender));
        },
        CarkeyProtocol::Iccoa => {
            //test code for sending message from vehicle to mobile by notification
            tokio::spawn(iccoa::ble_send_demo::ble_send_demos(ble_demo_sender));
        },
        CarkeyProtocol::Iccoa2 => {
            //test code for sending message from vehicle to mobile by notification
            tokio::spawn(iccoa2::ble_send_demo::ble_send_demos(ble_demo_sender));
        }
    }

    tokio::spawn(tsp::tsp_handler());

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
                        if let Ok(response) = iccoa2::ble::bluetooth_io::handle_data_package_from_mobile(&data_package, bt_send_package_tx2.clone()) {
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
