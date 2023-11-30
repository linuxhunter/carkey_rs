use log::{debug, info};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use rand::Rng;
use crate::iccoa2::{ble, certificate, Serde};
use crate::iccoa2::ble::auth::Auth;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::errors::*;
use crate::iccoa2::identifier::KeyId;

const BLE_AUTH_RANDOM_LENGTH: u8 = 0x10;


#[derive(Debug)]
pub struct BleAuth {
    random: Vec<u8>,
    key_id: Option<KeyId>,
    rke: Option<ble::rke::RkeRequest>,
    subscribe: Option<ble::vehicle_status::VehicleStatusRequest>,
    query: Option<ble::vehicle_status::VehicleStatusRequest>,
    unsubscribe: Option<ble::vehicle_status::VehicleStatusRequest>,
}

#[allow(dead_code)]
impl BleAuth {
    pub fn new() -> Self {
        BleAuth {
            random: vec![],
            key_id: None,
            rke: None,
            subscribe: None,
            query: None,
            unsubscribe: None,
        }
    }
    pub fn get_random(&self) -> &[u8] {
        self.random.as_ref()
    }
    pub fn generate_random(&mut self) {
        let mut rng = rand::thread_rng();
        self.random.clear();
        for _ in 0..BLE_AUTH_RANDOM_LENGTH {
            self.random.push(rng.gen::<u8>());
        }
    }
    pub fn get_key_id(&self) -> Option<&KeyId> {
        if let Some(ref key_id) = self.key_id {
            Some(key_id)
        } else {
            None
        }
    }
    pub fn set_key_id(&mut self, key_id: KeyId) {
        self.key_id = Some(key_id);
    }
    fn clear_business_contents(&mut self) {
        self.rke = None;
        self.subscribe = None;
        self.query = None;
        self.unsubscribe = None;
    }
    pub fn get_rke(&self) -> Option<&ble::rke::RkeRequest> {
        if let Some(ref rke) = self.rke {
            Some(rke)
        } else {
            None
        }
    }
    pub fn set_rke(&mut self, rke: ble::rke::RkeRequest) {
        self.clear_business_contents();
        self.rke = Some(rke);
    }
    pub fn get_subscribe(&self) -> Option<&ble::vehicle_status::VehicleStatusRequest> {
        if let Some(ref subscribe) = self.subscribe {
            Some(subscribe)
        } else {
            None
        }
    }
    pub fn set_subscribe(&mut self, subscribe: ble::vehicle_status::VehicleStatusRequest) {
        self.clear_business_contents();
        self.subscribe = Some(subscribe);
    }
    pub fn get_query(&self) -> Option<&ble::vehicle_status::VehicleStatusRequest> {
        if let Some(ref query) = self.query {
            Some(query)
        } else {
            None
        }
    }
    pub fn set_query(&mut self, query: ble::vehicle_status::VehicleStatusRequest) {
        self.clear_business_contents();
        self.query = Some(query);
    }
    pub fn get_unsubscribe(&self) -> Option<&ble::vehicle_status::VehicleStatusRequest> {
        if let Some(ref unsubscribe) = self.unsubscribe {
            Some(unsubscribe)
        } else {
            None
        }
    }
    pub fn set_unsubscribe(&mut self, unsubscribe: ble::vehicle_status::VehicleStatusRequest) {
        self.clear_business_contents();
        self.unsubscribe = Some(unsubscribe);
    }
    pub fn handle_random_request(&mut self, _request: &ble::auth::AuthRequestRandom) {
        self.generate_random();
    }
    pub fn create_auth_request(&self) -> Result<Message> {
        let auth_request = ble::auth::AuthRequest::new(self.get_random())?;
        Ok(Message::new(
            MessageType::Auth,
            MessageStatus::NoApplicable,
            auth_request.serialize()?.len() as u16,
            MessageData::Auth(Auth::Request(auth_request)),
        ))
    }
    fn verify_auth_data(&self, signature: &[u8]) -> Result<bool> {
        let mut auth_data = Vec::new();
        auth_data.append(&mut self.get_random().to_vec());
        if let Some(key_id) = self.get_key_id() {
            auth_data.append(&mut key_id.serialize()?);
        }
        if let Some(rke) = self.get_rke() {
            auth_data.append(&mut rke.serialize()?);
        }
        if let Some(subscribe) = self.get_subscribe() {
            auth_data.append(&mut subscribe.serialize()?);
        }
        if let Some(query) = self.get_query() {
            auth_data.append(&mut query.serialize()?);
        }
        if let Some(unsubscribe) = self.get_unsubscribe() {
            auth_data.append(&mut unsubscribe.serialize()?);
        }
        //load certificate according to key id
        let owner_certificate = certificate::Certificate::new(certificate::OWNER_CERT_PATH)
            .map_err(|e| ErrorKind::BleAuthError(format!("load owner certificate error: {}", e)))?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), owner_certificate.get_pkey()).unwrap();
        verifier.update(auth_data.as_ref())
            .map_err(|e| ErrorKind::BleAuthError(format!("verifier load data error: {}", e)))?;
        let result = verifier.verify(signature)
            .map_err(|e| ErrorKind::BleAuthError(format!("Ble Auth verification Failed: {}", e)))?;
        Ok(result)
    }
    pub fn handle_auth_response(&mut self, response: &ble::auth::AuthResponse) -> Result<()> {
        if let Some(entries) = response.get_auth_entries() {
            if entries.get_rke().is_none() &&
                entries.get_subscribe().is_none() &&
                entries.get_query().is_none() &&
                entries.get_unsubscribe().is_none() {
                return Err(ErrorKind::BleAuthError("Auth Rke entry contents is Null".to_string()).into());
            }
            self.set_key_id(response.get_key_id().clone());
            debug!("[Auth Response]: ");
            debug!("\tKey ID: {:?}", self.get_key_id());
            if let Some(rke) = entries.get_rke() {
                self.set_rke(*rke);
                debug!("\tRKE: {:?}", self.get_rke());
            }
            if let Some(subscribe) = entries.get_subscribe() {
                self.set_subscribe(*subscribe);
                debug!("\tSubscribe: {:?}", self.get_subscribe());
            }
            if let Some(query) = entries.get_query() {
                self.set_query(*query);
                debug!("\tQuery: {:?}", self.get_query());
            }
            if let Some(unsubscribe) = entries.get_unsubscribe() {
                self.set_unsubscribe(*unsubscribe);
                debug!("\tUnsubscribe: {:?}", self.get_unsubscribe());
            }
            debug!("\tSignature: {:02X?}", response.get_signature());
            info!("[BLE Auth]: ");
            if self.verify_auth_data(response.get_signature())? {
                info!("\tOK");
            } else {
                info!("\tFailed");
            }
            Ok(())
        } else {
            Err(ErrorKind::BleAuthError("Auth Entries is Null".to_string()).into())
        }
    }
}
