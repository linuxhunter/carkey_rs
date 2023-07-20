#[macro_use]
extern crate lazy_static;

mod carkey_icce;

use std::{sync::Arc, time::Duration, str::FromStr};

use bluer::{adv::Advertisement, gatt::local::{Application, Service, Characteristic, CharacteristicNotify, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod}, Session, agent::{AgentHandle, Agent, RequestPinCode, ReqResult, DisplayPinCode, RequestPasskey, DisplayPasskey, ReqError, RequestConfirmation, RequestAuthorization, AuthorizeService}, id, UuidExt};
use futures::FutureExt;
use tokio::{sync::{Mutex, oneshot}, io::AsyncBufReadExt};
use uuid::Uuid;

lazy_static! {
    static ref SERVICE_UUID: Uuid = Uuid::from_u16(0xFCD1);
    static ref WRITE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFD);
    static ref READ_CHARACTERISTIC_UUID: Uuid = Uuid::from_u16(0xFFFE);
}

#[derive(Clone, Copy)]
struct UuidOrShort(pub Uuid);

impl FromStr for UuidOrShort {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<UuidOrShort, std::string::String> {
        match s.parse::<Uuid>() {
            Ok(uuid) => Ok(Self(uuid)),
            Err(_) => {
                match u16::from_str_radix(s, 16) {
                    Ok(short) => Ok(Self(Uuid::from_u16(short))),
                    Err(_) => Err(s.to_string()),
                }
            }
        }
    }
}

impl From<UuidOrShort> for Uuid {
    fn from(value: UuidOrShort) -> Self {
        value.0
    }
}

impl From<Uuid> for UuidOrShort {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for UuidOrShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = self.0.as_u16() {
            write!(f, "{:04x}", s)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

async fn get_line() -> String {
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        if done_rx.await.is_err() {
            println!();
            println!("Never mind! Request was cancelled. But you mast press enter now.");
        }
    });
    let mut line = String::new();
    let mut buf = tokio::io::BufReader::new(tokio::io::stdin());
    buf.read_line(&mut line).await.expect("cannot read stdin");
    let _ = done_tx.send(());
    println!("Thanks for you response");
    line.trim().to_string()
}

async fn get_yes_no() -> ReqResult<()> {
    loop {
        let line = get_line().await;
        if line == "y" {
            return Ok(())
        } else if line == "n" {
            return Err(ReqError::Rejected)
        } else {
            println!("Invalid response!");
        }
    }
}

async fn request_pin_code(req: RequestPinCode) -> ReqResult<String> {
    println!("Enter PIN code for device {} on {}", &req.device, &req.adapter);
    Ok(get_line().await)
}

async fn display_pin_code(req: DisplayPinCode) -> ReqResult<()> {
    println!("PIN code for device {} on {}", req.device, req.adapter);
    Ok(())
}

async fn request_passkey(req: RequestPasskey) -> ReqResult<u32> {
    println!("Enter 6-digit passkey for device {} on {}", &req.device, &req.adapter);
    loop {
        let line = get_line().await;
        let passkey: u32 = if let Ok(v) = line.parse() {
            v
        } else {
            println!("Invalid passkey");
            continue;
        };
        if passkey > 999999 {
            println!("Passkey must be 6 digits");
            continue;
        }
        return Ok(passkey);
    }
}

async fn display_passkey(req: DisplayPasskey) -> ReqResult<()> {
    println!("Passkey for device {} on {} is \"{:06}\"", &req.device, &req.adapter, &req.passkey);
    Ok(())
}

async fn request_confirmation(req: RequestConfirmation, session: Session, set_trust: bool) -> ReqResult<()> {
    println!("Is passkey \"{:06}\" correct for device {} on {}? (y/n)", &req.passkey, &req.device, &req.adapter);
    get_yes_no().await?;
    if set_trust {
        println!("Trusting device {}", &req.device);
        let adapter = session.adapter(&req.adapter).unwrap();
        let device = adapter.device(req.device).unwrap();
        if let Err(err) = device.set_trusted(true).await {
            println!("Cannot trust device: {}", err);
        }
    }
    Ok(())
}

async fn request_authorization(req: RequestAuthorization, session: Session, set_trust: bool) -> ReqResult<()> {
    println!("Is device {} on {} allowed to pair? (y/n)", &req.device, &req.adapter);
    get_yes_no().await?;
    if set_trust {
        println!("Trusting device {}", &req.device);
        let adapter = session.adapter(&req.adapter).unwrap();
        let device = adapter.device(req.device).unwrap();
        if let Err(err) = device.set_trusted(true).await {
            println!("Cannot trust device: {}", err);
        }
    }
    Ok(())
}

async fn authorize_service(req: AuthorizeService) -> ReqResult<()> {
    let service_id = match id::Service::try_from(req.service) {
        Ok(name) => format!("{} ({})", name, UuidOrShort(req.service)),
        Err(_) => format!("{}", UuidOrShort(req.service)),
    };
    println!("Is device {} on {} allowed to use service {}? (y/n)", &req.device, &req.adapter, service_id);
    get_yes_no().await
}

async fn register_agent(session: &Session, request_default: bool, set_trust: bool) -> bluer::Result<AgentHandle> {
    let session1 = session.clone();
    let session2 = session.clone();
    let agent = Agent {
        request_default,
        request_pin_code: Some(Box::new(|req| request_pin_code(req).boxed())),
        display_pin_code: Some(Box::new(|req| display_pin_code(req).boxed())),
        request_passkey: Some(Box::new(|req| request_passkey(req).boxed())),
        display_passkey: Some(Box::new(|req| display_passkey(req).boxed())),
        request_confirmation: Some(Box::new(move |req| request_confirmation(req, session1.clone(), set_trust).boxed())),
        request_authorization: Some(Box::new(move |req| request_authorization(req, session2.clone(), set_trust).boxed())),
        authorize_service: Some(Box::new(|req| authorize_service(req).boxed())),
        ..Default::default()
    };
    let handle = session.register_agent(agent).await?;
    Ok(handle)
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