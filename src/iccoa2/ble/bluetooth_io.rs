use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::{ble, identifier, instructions, Serde};
use crate::iccoa2::ble::auth::Auth;
use crate::iccoa2::ble::custom::{CustomMessage, VehicleAppCustomResponse, VehicleServerCustomRequest};
use crate::iccoa2::ble::vehicle_status;
use crate::iccoa2::ble::vehicle_status::{SubscribeVerificationResponse, VehicleStatusResponse};
use crate::iccoa2::ble_measure::BleMeasure;
use crate::iccoa2::errors::*;
use crate::iccoa2::instructions::get_dk_certificate::DkCertType;
use crate::iccoa2::transaction::StandardTransaction;
use crate::iccoa2::ble_auth::BleAuth;
use crate::iccoa2::ble_custom::BleCustom;
use crate::iccoa2::ble_rke::BleRke;
use crate::iccoa2::ble_vehicle_status::BleVehicleStatus;

const AID: u8 = 0x00;
lazy_static! {
    static ref STANDARD_TRANSACTION: Mutex<StandardTransaction> = Mutex::new(StandardTransaction::new(identifier::get_vehicle_id().unwrap()).unwrap());
    static ref BLE_MEASURE: Mutex<BleMeasure> = Mutex::new(BleMeasure::new());
    static ref BLE_AUTH: Mutex<BleAuth> = Mutex::new(BleAuth::new());
    static ref BLE_RKE: Mutex<BleRke> = Mutex::new(BleRke::new());
    static ref BLE_VEHICLE_STATUS: Mutex<BleVehicleStatus> = Mutex::new(BleVehicleStatus::new());
    static ref BLE_CUSTOM: Mutex<BleCustom> = Mutex::new(BleCustom::new());
}

pub fn create_select_request_message() -> Result<Message> {
    let standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
    standard_transaction.create_select_request(AID)
}

pub fn create_ble_measure_request_message() -> Result<Message> {
    let ble_measure = BLE_MEASURE.lock().unwrap();
    ble_measure.create_ble_measure_request(
        ble::measure::MeasureRequest::new(
            ble::measure::MeasureType::BtRssi,
            ble::measure::MeasureAction::Start,
            ble::measure::MeasureDuration::new(0x20),
        )
    )
}

pub fn create_vehicle_server_custom_request() -> Result<Message> {
    let ble_custom = BLE_CUSTOM.lock().unwrap();
    ble_custom.create_server_custom_request(&VehicleServerCustomRequest::new(
        0x0102,
        0x03,
    ))
}

#[allow(dead_code)]
pub fn handle_request_from_mobile(message: &Message) -> Result<Message> {
    match message.get_message_type() {
        MessageType::Apdu => {
            todo!()
        }
        MessageType::MeasureBroadcastRequest => {
            todo!()
        }
        MessageType::Rke => {
            if let MessageData::Rke(ble::rke::Rke::ContinuedRequest(request)) = message.get_message_data() {
                let ble_continued_rke = BLE_RKE.lock().unwrap();
                ble_continued_rke.handle_rke_continued_request(request);
                return ble_continued_rke.create_ble_rke_response(
                    MessageStatus::Success,
                    ble::rke::RkeResponse::new(
                        request.get_rke_request().get_rke_function(),
                        request.get_rke_request().get_rke_action(),
                        0xAABB,
                    ).unwrap()
                )
            }
            todo!()
        }
        MessageType::VehicleStatus => {
            if let MessageData::VehicleStatus(vehicle_status::VehicleStatus::Request(request)) = message.get_message_data() {
                match request.get_operation() {
                    vehicle_status::VehicleStatusOperations::Subscribe => {
                        vehicle_status::handle_subscribe_request(request)
                    },
                    vehicle_status::VehicleStatusOperations::Query => {
                        let response = vehicle_status::handle_query_request(request)?;
                        return Ok(
                            Message::new(
                                MessageType::VehicleStatus,
                                MessageStatus::Success,
                                response.serialize()?.len() as u16,
                                MessageData::VehicleStatus(vehicle_status::VehicleStatus::Response(response))
                            )
                        )
                    },
                    vehicle_status::VehicleStatusOperations::Unsubscribe => {
                        vehicle_status::handle_unsubscribe_request(request)
                    },
                }
                todo!()
            } else {
                todo!()
            }
        }
        MessageType::VehicleAppCustomMessage => {
            if let MessageData::VehicleAppCustomMessage(CustomMessage::AppCustomRequest(request)) = message.get_message_data() {
                let ble_custom = BLE_CUSTOM.lock().unwrap();
                ble_custom.handle_app_custom_request(request);
                return ble_custom.create_app_custom_response(&VehicleAppCustomResponse::new(
                    vec![0x03, 0x02, 0x01, 0x00].as_ref()
                ));
            }
            todo!()
        }
        MessageType::VehicleServerCustomMessage => {
            todo!()
        }
        MessageType::Auth => {
            if let MessageData::Auth(Auth::RequestRandom(request)) = message.get_message_data() {
                let mut ble_auth = BLE_AUTH.lock().unwrap();
                ble_auth.handle_random_request(request);
                return ble_auth.create_auth_request();
            }
            todo!()
        }
        MessageType::Custom => {
            todo!()
        }
    }
}

#[allow(dead_code)]
pub fn handle_response_from_mobile(message: &Message, bt_sender: Sender<Vec<u8>>) -> Result<Message> {
    match message.get_message_type() {
        MessageType::Apdu => {
            if let MessageData::Apdu(apdu) = message.get_message_data() {
                if let Some(instruction) = apdu.get_apdu_instructions().iter().next() {
                    return match instruction {
                        instructions::ApduInstructions::ResponseSelect(response) => {
                            let mut standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_select_response(response)?;
                            standard_transaction.create_auth0_request()
                        }
                        instructions::ApduInstructions::ResponseAuth0(response) => {
                            let mut standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_auth0_response(response)?;
                            standard_transaction.create_auth1_request()
                        }
                        instructions::ApduInstructions::ResponseAuth1(response) => {
                            let mut standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_auth1_response(response)?;
                            standard_transaction.create_get_dk_certificate_request(DkCertType::VehicleMasterKey)
                        }
                        instructions::ApduInstructions::ResponseGetDkCert(response) => {
                            let standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_get_dk_certificate_response(response)
                        }
                        instructions::ApduInstructions::ResponseControlFlow(response) => {
                            let standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_control_flow_response(response)?;
                            create_ble_measure_request_message()
                        }
                        /*
                        ApduInstructions::ResponseListDk(_) => {} }
                        ApduInstructions::ResponseSharingRequest(_) => {}
                        ApduInstructions::ResponseRke(_) => {}
                        ApduInstructions::ResponseSign(_) => {}
                        ApduInstructions::ResponseDisableDk(_) => {}
                        ApduInstructions::ResponseEnableDk(_) => {}
                        ApduInstructions::ResponseGetChallenge(_) => {}
                        ApduInstructions::ResponseGetResponse(_) => {}
                        */
                        _ => {
                            Err(ErrorKind::TransactionError("no reply".to_string()).into())
                        }
                    }
                }
            }
            todo!()
        }
        MessageType::MeasureBroadcastRequest => {
            if let MessageData::Measure(ble::measure::Measure::Response(response)) = message.get_message_data() {
                let mut ble_measure = BLE_MEASURE.lock().unwrap();
                ble_measure.handle_ble_measure_response(response)?;
            }
            Err("No response to mobile".to_string().into())
        }
        MessageType::Rke => {
            todo!()
        }
        MessageType::VehicleStatus => {
            todo!()
        }
        MessageType::VehicleAppCustomMessage => {
            todo!()
        }
        MessageType::VehicleServerCustomMessage => {
            if let MessageData::VehicleServerCustomMessage(CustomMessage::ServerCustomResponse(response)) = message.get_message_data() {
                let ble_custom = BLE_CUSTOM.lock().unwrap();
                ble_custom.handle_server_custom_response(response);
            }
            Err("No response to mobile".to_string().into())
        }
        MessageType::Auth => {
            if let MessageData::Auth(Auth::Response(response)) = message.get_message_data() {
                let mut ble_auth = BLE_AUTH.lock().unwrap();
                ble_auth.handle_auth_response(response)?;
                if let Some(rke) = ble_auth.get_rke() {
                    let mut ble_rke = BLE_RKE.lock().unwrap();
                    ble_rke.set_random(ble_auth.get_random());
                    ble_rke.handle_rke_request(rke);
                    let rke_response = ble_rke.create_ble_rke_response(
                        MessageStatus::Success,
                        ble::rke::RkeResponse::new(
                            rke.get_rke_function(),
                            rke.get_rke_action(),
                            0xAABB,
                        ).unwrap()
                    )?.serialize()?;
                    //create thread to simulate sending rke response to mobile
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(1));
                        bt_sender.blocking_send(rke_response).unwrap();
                    });
                    return ble_rke.create_rke_verification_response(MessageStatus::Success);
                }
                if let Some(subscribe) = ble_auth.get_subscribe() {
                    let mut ble_subscribe = BLE_VEHICLE_STATUS.lock().unwrap();
                    ble_subscribe.set_random(ble_auth.get_random());
                    ble_subscribe.handle_vehicle_status_request(subscribe);
                    let subscribe_response = ble_subscribe.create_vehicle_status_response(
                        MessageStatus::Success,
                        VehicleStatusResponse::new(
                            subscribe.get_entity_id(),
                            0x0102,
                            None,
                        )
                    )?.serialize()?;
                    //create thread to simulate sending rke response to mobile
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(1));
                        bt_sender.blocking_send(subscribe_response).unwrap();
                    });
                    return ble_subscribe.create_vehicle_status_verification_response();
                }
                if let Some(query) = ble_auth.get_query() {
                    let mut ble_query = BLE_VEHICLE_STATUS.lock().unwrap();
                    ble_query.set_random(ble_auth.get_random());
                    ble_query.handle_vehicle_status_request(query);
                    return ble_query.create_vehicle_status_response(
                        MessageStatus::Success,
                        VehicleStatusResponse::new(
                            query.get_entity_id(),
                            0x0304,
                            Some(SubscribeVerificationResponse::new(ble_auth.get_random())),
                        )
                    );
                }
                if let Some(unsubscribe) = ble_auth.get_unsubscribe() {
                    let mut ble_unsubscribe = BLE_VEHICLE_STATUS.lock().unwrap();
                    ble_unsubscribe.set_random(ble_auth.get_random());
                    ble_unsubscribe.handle_vehicle_status_request(unsubscribe);
                    return ble_unsubscribe.create_vehicle_status_verification_response();
                }
            }
            Err("No response to mobile".to_string().into())
        }
        MessageType::Custom => {
            todo!()
        }
    }
}

#[allow(dead_code)]
pub fn handle_data_package_from_mobile(data_package: &[u8], bt_sender: Sender<Vec<u8>>) -> Result<Message> {
    let message = Message::deserialize(data_package)?;
    match message.get_message_status() {
        MessageStatus::NoApplicable => handle_request_from_mobile(&message),
        MessageStatus::Success => handle_response_from_mobile(&message, bt_sender),
        MessageStatus::BeyondMessageLength |
        MessageStatus::NoPermission |
        MessageStatus::SeInaccessible |
        MessageStatus::TlvParseError |
        MessageStatus::VehicleNotSupported |
        MessageStatus::InstructionVerificationFailed |
        MessageStatus::UnknownError |
        MessageStatus::Custom |
        MessageStatus::Reserved => {
            Err(format!("Unsupported Error Message Type: {}", message.get_message_status()).into())
        }
    }
}
