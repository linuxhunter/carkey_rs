#[macro_use]
extern crate lazy_static;

mod bluetooth_agent;
mod bluetooth_uuid;
mod carkey_icce;
mod carkey_icce_crypto;

use bluer::{adv::Advertisement, gatt::local::{Application, Service, Characteristic, CharacteristicNotify, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod}, UuidExt};
use futures::FutureExt;
use tokio::sync::{mpsc, broadcast};
use uuid::Uuid;

use crate::bluetooth_agent::register_agent;

lazy_static! {
    static ref SERVICE_UUID: Uuid = Uuid::from_u16(0xFCD1);
    static ref WRITE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFD);
    static ref READ_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFE);
}

#[tokio::main]
async fn main() -> bluer::Result<()> {
    let (bt_write_tx, mut bt_write_rx) = mpsc::channel(32);
    let (bt_notify_tx, _) = broadcast::channel::<Vec<u8>>(32);
    let bt_notify_tx2 = bt_notify_tx.clone();
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let agent_handle = register_agent(&session, true, true).await?;

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
                    method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
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
                    fun: Box::new(move |req| {
                        async move {
                            let reader_type = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
                            let reader_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xe, 0x0f, 0x00];
                            let reader_rnd = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
                            let reader_key_parameter = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
                            let get_process_data_apdu = carkey_icce::create_auth_get_process_data_payload(&reader_type, &reader_id, &reader_rnd, &reader_key_parameter);
                            let icce = carkey_icce::create_icce_auth_request(&get_process_data_apdu);
                            let icce_package = icce.serialize();
                            println!("Read request {:?} with value {:02x?}", req, icce_package);
                            println!("Sending Get Process Data Request");
                            Ok(icce_package)
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

    tokio::spawn(async move {
        let bt_notify_tx = bt_notify_tx.clone();
        while let Some(icce_package) = bt_write_rx.recv().await {
            println!("GOT = {:02X?}", icce_package);
            if let Ok(icce_object) = carkey_icce::ICCE::deserialize(&icce_package) {
                if icce_object.get_header().get_control().is_request() {
                    if let Ok(response) = carkey_icce::handle_icce_mobile_request(&icce_object) {
                        let _ = bt_notify_tx.send(response);
                    }
                } else {
                    if let Ok(response) = carkey_icce::handle_icce_mobile_response(&icce_object) {
                        if response.len() > 0 {
                            let _ = bt_notify_tx.send(response);
                        }

                    }
                }
            }
        }
    });

    /*
    tokio::spawn(async move {
        loop {
            let mut value = vec![0x10, 0x11, 0x22, 0x33, 0x44];
            println!("Sending data from vehicle to mobile");
            let _ = bt_notify_tx3.send(value);
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
    */

    println!("Server ready. Press ctrl-c to quit");
    tokio::signal::ctrl_c().await?;

    println!("Removing service and advertisement");
    adapter.set_pairable(false).await?;
    drop(app_handle);
    drop(adv_handle);
    drop(agent_handle);
    Ok(())
}
