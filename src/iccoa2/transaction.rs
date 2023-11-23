use log::info;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use rand::Rng;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::errors::*;
use crate::iccoa2::instructions::ApduInstructions;
use crate::iccoa2::{ble, identifier, instructions, RANDOM_LENGTH, Serde};

#[derive(Debug)]
pub struct StandardTransaction {
    aid: u8,
    version: Option<u16>,
    vehicle_oem_id: u16,
    vehicle_serial_id: Vec<u8>,
    vehicle_temp_private_key: EcKey<Private>,
    random: Vec<u8>,
    device_temp_public_key: Option<PKey<Public>>,
    crypto_gram: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl StandardTransaction {
    pub fn new(aid: u8, vehicle_oem_id: u16, vehicle_serial_id: &[u8]) -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| ErrorKind::TransactionError(format!("create ec group error: {}", e)))?;
        let private_key = EcKey::generate(&group)
            .map_err(|e| ErrorKind::TransactionError(format!("create ec private key error: {}", e)))?;
        let mut random = Vec::with_capacity(RANDOM_LENGTH);
        let mut rng = rand::thread_rng();
        for _ in 0..RANDOM_LENGTH {
            random.push(rng.gen::<u8>());
        }
        Ok(StandardTransaction {
            aid,
            version: None,
            vehicle_oem_id,
            vehicle_serial_id: vehicle_serial_id.to_vec(),
            vehicle_temp_private_key: private_key,
            random,
            device_temp_public_key: None,
            crypto_gram: None,
        })
    }
    pub fn create_select_request(&self) -> Result<Message> {
        let select_request = instructions::select::CommandApduSelect::new(&[self.aid]);
        let mut apdu = ble::apdu::Apdu::new();
        apdu.add_apdu_instruction(ApduInstructions::CommandSelect(select_request));
        Ok(Message::new(
           MessageType::Apdu,
            MessageStatus::NoApplicable,
            apdu.serialize()?.len() as u16,
            MessageData::Apdu(apdu),
        ))
    }
    pub fn handle_select_response(&mut self, response: &instructions::select::ResponseApduSelect) -> Result<()> {
        self.version = Some(response.get_version());
        info!("version = {:?}", self.version);
        Ok(())
    }
    pub fn create_auth0_request(&self) -> Result<Message> {
        if self.version == None {
            return Err(ErrorKind::TransactionError("version is NULL".to_string()).into());
        }
        let vehicle_id = identifier::VehicleId::new(
            self.vehicle_oem_id,
            self.vehicle_serial_id.as_ref()
        ).map_err(|e| ErrorKind::TransactionError(format!("create vehicle id error: {}", e)))?;

        let group =EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| ErrorKind::TransactionError(format!("create ec group error: {}", e)))?;
        let mut ctx = BigNumContext::new()
            .map_err(|e| ErrorKind::TransactionError(format!("create big number context error: {}", e)))?;
        let vehicle_temp_pub_key = self.vehicle_temp_private_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|e| ErrorKind::TransactionError(format!("export vehicle temp public key error: {}", e)))?;

        let auth0_request = instructions::auth_0::CommandApduAuth0::new(
            instructions::CLA,
            instructions::auth_0::Auth0P1::Standard,
            self.version.unwrap(),
            vehicle_id,
            vehicle_temp_pub_key.as_ref(),
            self.random.as_ref(),
        );
        let mut apdu = ble::apdu::Apdu::new();
        apdu.add_apdu_instruction(ApduInstructions::CommandAuth0(auth0_request));
        Ok(Message::new(
            MessageType::Apdu,
            MessageStatus::NoApplicable,
            apdu.serialize()?.len() as u16,
            MessageData::Apdu(apdu),
        ))
    }
    pub fn handle_auth0_response(&mut self, response: &instructions::auth_0::ResponseApduAuth0) -> Result<()> {
        let group =EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| ErrorKind::TransactionError(format!("create ec group error: {}", e)))?;
        let mut ctx = BigNumContext::new()
            .map_err(|e| ErrorKind::TransactionError(format!("create big number context error: {}", e)))?;
        let ec_point = EcPoint::from_bytes(&group, response.get_device_temp_pub_key(), &mut ctx)
            .map_err(|e| ErrorKind::TransactionError(format!("create ec point from device temp public key error: {}", e)))?;
        let ec_key = EcKey::from_public_key(&group, &ec_point)
            .map_err(|e| ErrorKind::TransactionError(format!("create ec key error: {}", e)))?;
        let device_temp_public_key = PKey::from_ec_key(ec_key)
            .map_err(|e| ErrorKind::TransactionError(format!("create device temp public key error: {}", e)))?;
        self.device_temp_public_key = Some(device_temp_public_key);
        if let Some(crypto_gram) = response.get_cryptogram() {
            self.crypto_gram = Some(crypto_gram.to_vec())
        } else {
            self.crypto_gram = None
        }
        Ok(())
    }
    /*
    pub fn create_auth1_request(&self) -> Result<Message> {

    }
    pub fn handle_auth1_response(&mut self, response: &instructions::auth_1::ResponseApduAuth1) -> Result<()> {
        Ok(())
    }
    pub fn create_get_dk_certificate_request(&self) -> Result<Message> {

    }
    pub fn handle_get_dk_certificate_response(&self, response: &instructions::get_dk_certificate::ResponseApduGetDkCert) -> Result<()> {
        Ok(())
    }
    pub fn create_control_flow_request(&self) -> Result<Message> {

    }
    */
}

/*
pub struct FastTransaction {

}
*/