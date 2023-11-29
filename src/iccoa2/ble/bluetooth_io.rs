use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::{ble, instructions, Serde};
use crate::iccoa2::ble::auth::Auth;
use crate::iccoa2::ble::rke::RkeResponse;
use crate::iccoa2::ble::vehicle_status;
use crate::iccoa2::ble::vehicle_status::{SubscribeVerificationResponse, VehicleStatusResponse};
use crate::iccoa2::ble_measure::BleMeasure;
use crate::iccoa2::errors::*;
use crate::iccoa2::instructions::get_dk_certificate::DkCertType;
use crate::iccoa2::transaction::StandardTransaction;
use crate::iccoa2::ble_auth::BleAuth;
use crate::iccoa2::ble_rke::BleRke;
use crate::iccoa2::ble_vehicle_status::BleVehicleStatus;

const AID: u8 = 0x00;
const VEHICLE_OEM_ID: u16 = 0x0102;
const VEHICLE_SERIAL_ID: [u8; 14] = [
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];
const DEFAULT_BLE_MEASURE_REQUEST_DURATION: u8 = 0x10;

lazy_static! {
    static ref STANDARD_TRANSACTION: Mutex<StandardTransaction> = Mutex::new(
        StandardTransaction::new(AID, VEHICLE_OEM_ID, VEHICLE_SERIAL_ID.as_ref()).unwrap()
    );
    static ref BLE_MEASURE: Mutex<BleMeasure> = Mutex::new(
        BleMeasure::new(
            ble::measure::MeasureRequest::new(
                ble::measure::MeasureType::BtRssi,
                ble::measure::MeasureAction::Start,
                ble::measure::MeasureDuration::new(DEFAULT_BLE_MEASURE_REQUEST_DURATION),
            )
        )
    );
    static ref BLE_AUTH: Mutex<BleAuth> = Mutex::new(BleAuth::new());
    static ref BLE_RKE: Mutex<BleRke> = Mutex::new(BleRke::new());
    static ref BLE_VEHICLE_STATUS: Mutex<BleVehicleStatus> = Mutex::new(BleVehicleStatus::new());
}

pub fn create_select_request_message() -> Result<Message> {
    let standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
    standard_transaction.create_select_request()
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
                    match instruction {
                        instructions::ApduInstructions::ResponseSelect(response) => {
                            let mut standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_select_response(response)?;
                            return standard_transaction.create_auth0_request();
                        }
                        instructions::ApduInstructions::ResponseAuth0(response) => {
                            let mut standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_auth0_response(response)?;
                            return standard_transaction.create_auth1_request();
                        }
                        instructions::ApduInstructions::ResponseAuth1(response) => {
                            let mut standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_auth1_response(response)?;
                            return standard_transaction.create_get_dk_certificate_request(DkCertType::VehicleMasterKey);
                        }
                        instructions::ApduInstructions::ResponseGetDkCert(response) => {
                            let standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            return standard_transaction.handle_get_dk_certificate_response(response);
                        }
                        instructions::ApduInstructions::ResponseControlFlow(response) => {
                            let standard_transaction = STANDARD_TRANSACTION.lock().unwrap();
                            standard_transaction.handle_control_flow_response(response)?;
                            let mut ble_measure = BLE_MEASURE.lock().unwrap();
                            ble_measure.set_request(
                                ble::measure::MeasureRequest::new(
                                    ble::measure::MeasureType::BtRssi,
                                    ble::measure::MeasureAction::Start,
                                    ble::measure::MeasureDuration::new(0x20),
                                )
                            );
                            return ble_measure.create_ble_measure_request();
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
                            return Err(ErrorKind::TransactionError("no reply".to_string()).into());
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
            todo!()
        }
        MessageType::Auth => {
            if let MessageData::Auth(Auth::Response(response)) = message.get_message_data() {
                let mut ble_auth = BLE_AUTH.lock().unwrap();
                ble_auth.handle_auth_response(response)?;
                if let Some(rke) = ble_auth.get_rke() {
                    let mut ble_rke = BLE_RKE.lock().unwrap();
                    ble_rke.set_random(ble_auth.get_random());
                    ble_rke.set_request(*rke);
                    //create rke response
                    ble_rke.set_response(RkeResponse::new(
                        rke.get_rke_function(),
                        rke.get_rke_action(),
                        0xAABB,
                    ).unwrap());
                    let rke_response = ble_rke.create_ble_rke_response()?.serialize()?;
                    //create thread to simulate sending rke response to mobile
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(1));
                        bt_sender.blocking_send(rke_response).unwrap();
                    });
                    return ble_rke.create_rke_verification_response();
                }
                if let Some(subscribe) = ble_auth.get_subscribe() {
                    let mut ble_subscribe = BLE_VEHICLE_STATUS.lock().unwrap();
                    ble_subscribe.set_random(ble_auth.get_random());
                    ble_subscribe.set_request(*subscribe);
                    ble_subscribe.set_response(VehicleStatusResponse::new(
                        subscribe.get_entity_id(),
                        0x0102,
                        None,
                    ));
                    let subscribe_response = ble_subscribe.create_vehicle_status_response()?.serialize()?;
                    //create thread to simulate sending rke response to mobile
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(1));
                        bt_sender.blocking_send(subscribe_response).unwrap();
                    });
                    return ble_subscribe.create_subscribe_verification_response();
                }
                if let Some(query) = ble_auth.get_query() {
                    let mut ble_query = BLE_VEHICLE_STATUS.lock().unwrap();
                    ble_query.set_random(ble_auth.get_random());
                    ble_query.set_request(*query);
                    ble_query.set_response(VehicleStatusResponse::new(
                        query.get_entity_id(),
                        0x0304,
                        Some(SubscribeVerificationResponse::new(ble_auth.get_random())),
                    ));
                    return ble_query.create_vehicle_status_response();
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
