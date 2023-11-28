use std::sync::Mutex;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::{ble, instructions, Serde};
use crate::iccoa2::ble::vehicle_status;
use crate::iccoa2::ble_measure::BleMeasure;
use crate::iccoa2::errors::*;
use crate::iccoa2::instructions::get_dk_certificate::DkCertType;
use crate::iccoa2::transaction::StandardTransaction;

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
            todo!()
        }
        MessageType::Custom => {
            todo!()
        }
    }
}

#[allow(dead_code)]
pub fn handle_response_from_mobile(message: &Message) -> Result<Message> {
    match message.get_message_type() {
        MessageType::Apdu => {
            if let MessageData::Apdu(apdu) = message.get_message_data() {
                for instruction in apdu.get_apdu_instructions() {
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
            todo!()
        }
        MessageType::Custom => {
            todo!()
        }
    }
}

#[allow(dead_code)]
pub fn handle_data_package_from_mobile(data_package: &[u8]) -> Result<Message> {
    let message = Message::deserialize(data_package)?;
    match message.get_message_status() {
        MessageStatus::NoApplicable => handle_request_from_mobile(&message),
        MessageStatus::Success => handle_response_from_mobile(&message),
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
