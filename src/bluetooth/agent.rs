use bluer::{agent::{ReqResult, ReqError, RequestPinCode, DisplayPinCode, RequestPasskey, DisplayPasskey, RequestConfirmation, RequestAuthorization, AuthorizeService, Agent, AgentHandle}, Session, id};
use futures::FutureExt;
use tokio::{sync::oneshot, io::AsyncBufReadExt};

use crate::bluetooth::uuid::UuidOrShort;

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

pub async fn register_agent(session: &Session, request_default: bool, set_trust: bool) -> bluer::Result<AgentHandle> {
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
