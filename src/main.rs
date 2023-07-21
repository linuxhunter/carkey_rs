#[macro_use]
extern crate lazy_static;

mod carkey_icce;
mod bluetooth_agent;
mod bluetooth_uuid;

use std::{sync::Arc, time::Duration};

use bluer::{adv::Advertisement, gatt::local::{Application, Service, Characteristic, CharacteristicNotify, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod}, UuidExt};
use futures::FutureExt;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::bluetooth_agent::register_agent;

lazy_static! {
    static ref SERVICE_UUID: Uuid = Uuid::from_u16(0xFCD1);
    static ref WRITE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFD);
    static ref READ_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFE);
}

#[tokio::main]
async fn main() -> bluer::Result<()> {
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

    let value = Arc::new(Mutex::new(vec![0x10, 0x11, 0x12, 0x13, 0x14]));
    let value_read = value.clone();
    let value_write = value.clone();
    let value_notify = value.clone();

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
                        let value = value_write.clone();
                        async move {
                            println!("Write request {:?} with value {:x?}", req, value);
                            let mut value = value.lock().await;
                            *value = new_value;
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
                        let value = value_read.clone();
                        async move {
                            let value = value.lock().await.clone();
                            println!("Read request {:?} with value {:x?}", req, value);
                            Ok(value)
                        }.boxed()
                    }),
                    ..Default::default()
                }),
                notify: Some(CharacteristicNotify {
                    notify: true,
                    method: bluer::gatt::local::CharacteristicNotifyMethod::Fun(Box::new(move |mut notifier| {
                        let value = value_notify.clone();
                        async move {
                            tokio::spawn(async move {
                                println!("Notification session start with confirming={:?}", notifier.confirming());
                                loop {
                                    let mut value = value.lock().await;
                                    println!("Notifying with value {:x?}", &*value);
                                    if let Err(err) = notifier.notify(value.to_vec()).await {
                                        println!("Notification error: {}", err);
                                        break;
                                    }
                                    println!("Decrementing each element by one");
                                    for v in &mut *value {
                                        *v = v.saturating_sub(1);
                                    }
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                }
                                println!("Notification session stop");
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

    println!("Server ready. Press ctrl-c to quit");
    tokio::signal::ctrl_c().await?;

    println!("Removing service and advertisement");
    adapter.set_pairable(false).await?;
    drop(app_handle);
    drop(adv_handle);
    drop(agent_handle);
    Ok(())
}
