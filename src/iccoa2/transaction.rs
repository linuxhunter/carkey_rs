use std::fs;
use std::io::Write;
use std::path::Path;
use log::info;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::x509::{X509, X509Ref};
use rand::Rng;
use crate::iccoa2::ble::message::{Message, MessageData, MessageStatus, MessageType};
use crate::iccoa2::errors::*;
use crate::iccoa2::instructions::{ApduInstructions, CLA};
use crate::iccoa2::{ble, create_tlv_with_primitive_value, identifier, instructions, RANDOM_LENGTH, Serde};
use crate::iccoa2::instructions::get_dk_certificate::DkCertType;

const VEHICLE_OEM_CA_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle_oem_ca.pem";
#[allow(dead_code)]
const VEHICLE_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle.pem";
const OWNER_CERT_PATH: &str = "/etc/certs/iccoa2/owner.pem";

#[derive(Debug)]
pub struct Certificate {
    certificate: X509,
    pkey: PKey<Public>,
}

#[allow(dead_code)]
impl Certificate {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw_cert = fs::read_to_string(path.as_ref())
            .map_err(|e| ErrorKind::TransactionError(format!("read certificate {:?} error: {}", path.as_ref(), e)))?;
        let certificate = X509::from_pem(raw_cert.as_bytes())
            .map_err(|e| ErrorKind::TransactionError(format!("create X509 certificate from raw pem error: {}", e)))?;
        let pkey = certificate.public_key()
            .map_err(|e| ErrorKind::TransactionError(format!("crate public key from X509 certificate error: {}", e)))?;
        Ok(Certificate {
            certificate,
            pkey,
        })
    }
    pub fn get_certificate(&self) -> &X509Ref {
        self.certificate.as_ref()
    }
    pub fn get_pkey(&self) -> &PKeyRef<Public> {
        self.pkey.as_ref()
    }
    pub fn verify(&self, certificate: &Certificate) -> Result<bool> {
        certificate.get_certificate().verify(self.get_pkey())
               .map_err(|e| ErrorKind::TransactionError(format!("verify error: {}", e)).into())
    }
}

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
        info!("[Select Response]:");
        info!("\tversion = {:?}", self.version);
        Ok(())
    }
    pub fn create_auth0_request(&self) -> Result<Message> {
        if self.version.is_none() {
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
            CLA,
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
        info!("[Auth0 Response]:");
        info!("\tdevice temp public key = {:02X?}", self.device_temp_public_key);
        info!("\tcryptogram = {:?}", self.crypto_gram);
        Ok(())
    }
    fn create_auth1_authentication_data(&self) -> Result<instructions::auth_1::Auth1Data> {
        let group =EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| ErrorKind::TransactionError(format!("create ec group error: {}", e)))?;
        let mut ctx = BigNumContext::new()
            .map_err(|e| ErrorKind::TransactionError(format!("create big number context error: {}", e)))?;
        let device_ec_key: EcKey<Public> = self.device_temp_public_key.clone()
            .ok_or("device temp public key is NULL".to_string())?
            .try_into()
            .map_err(|e| ErrorKind::TransactionError(format!("change from PKey to EcKey error: {}", e)))?;
        let mut device_x = BigNum::new()
            .map_err(|e| ErrorKind::TransactionError(format!("create BigNum error: {}", e)))?;
        let mut device_y = BigNum::new()
            .map_err(|e| ErrorKind::TransactionError(format!("create BigNum error: {}", e)))?;
        device_ec_key.public_key().affine_coordinates(&group, &mut device_x, &mut device_y, &mut ctx).unwrap();
        let vehicle_ec_key = self.vehicle_temp_private_key.public_key();
        let mut vehicle_x = BigNum::new()
            .map_err(|e| ErrorKind::TransactionError(format!("create BigNum error: {}", e)))?;
        let mut vehicle_y = BigNum::new()
            .map_err(|e| ErrorKind::TransactionError(format!("create BigNum error: {}", e)))?;
        vehicle_ec_key.affine_coordinates(&group, &mut vehicle_x, &mut vehicle_y, &mut ctx)
            .map_err(|e| ErrorKind::TransactionError(format!("get vehicle ec key x and y error: {}", e)))?;
        Ok(instructions::auth_1::Auth1Data::new(
            identifier::VehicleId::new(
                self.vehicle_oem_id,
                self.vehicle_serial_id.as_ref(),
            )?,
            device_x.to_vec().as_ref(),
            vehicle_x.to_vec().as_ref(),
            self.random.as_ref(),
        ))
    }
    pub fn create_auth1_request(&self) -> Result<Message> {
        let data = self.create_auth1_authentication_data()?.serialize()?;
        println!("auth1 data = {:02X?}", data);
        let keypair = PKey::from_ec_key(self.vehicle_temp_private_key.clone())
            .map_err(|e| ErrorKind::TransactionError(format!("create private key from ec key error: {}", e)))?;
        let mut signer = Signer::new(MessageDigest::sha256(), &keypair)
            .map_err(|e| ErrorKind::TransactionError(format!("create signer with private key error: {}", e)))?;
        signer.update(data.as_ref()).map_err(|e| ErrorKind::TransactionError(format!("update signer with data error: {}", e)))?;
        let signature = signer.sign_to_vec().map_err(|e| ErrorKind::TransactionError(format!("get signature error: {}", e)))?;
        let signature_tlv = create_tlv_with_primitive_value(0x8F, signature.as_ref())
            .map_err(|e| ErrorKind::TransactionError(format!("create signature tlv error: {}", e)))?;
        let mut apdu = ble::apdu::Apdu::new();
        apdu.add_apdu_instruction(ApduInstructions::CommandAuth1(signature_tlv.to_vec()));
        Ok(Message::new(
            MessageType::Apdu,
            MessageStatus::NoApplicable,
            apdu.serialize()?.len() as u16,
            MessageData::Apdu(apdu),
        ))
    }
    pub fn handle_auth1_response(&mut self, response: &[u8]) -> Result<()> {
        info!("[Auth1 Response]:");
        info!("\tresponse = {:02X?}", response);

        if let Some(ref public_key) = self.device_temp_public_key {
            let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
            let data = self.create_auth1_authentication_data()?.serialize()?;
            verifier.update(data.as_ref()).unwrap();
            if verifier.verify(response).unwrap() {
                info!("\tVerification OK");
            } else {
                info!("\tVerification Failed");
            }
        }
        Ok(())
    }
    pub fn create_get_dk_certificate_request(&self, dk_cert_type: DkCertType) -> Result<Message> {
        match dk_cert_type {
            DkCertType::VehicleCA => {
                todo!()
            }
            DkCertType::VehicleMasterKey => {
                fs::File::create(OWNER_CERT_PATH)
                    .map_err(|e| ErrorKind::TransactionError(format!("create empty owner certificate file error: {}", e)))?;
            }
            DkCertType::TempSharedCert => {
                todo!()
            }
            DkCertType::FriendKey => {
                todo!()
            }
        }
        let request = instructions::get_dk_certificate::CommandApduGetDkCert::new(
            CLA,
            dk_cert_type,
        );
        let mut apdu = ble::apdu::Apdu::new();
        apdu.add_apdu_instruction(ApduInstructions::CommandGetDkCert(request));
        Ok(Message::new(
            MessageType::Apdu,
            MessageStatus::NoApplicable,
            apdu.serialize()?.len() as u16,
            MessageData::Apdu(apdu),
        ))
    }
    pub fn handle_get_dk_certificate_response(&self, response: &instructions::get_dk_certificate::ResponseApduGetDkCert) -> Result<Message> {
        match response.get_dk_cert_type() {
            DkCertType::VehicleCA => {
                todo!()
            }
            DkCertType::VehicleMasterKey => {
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(true)
                    .open(OWNER_CERT_PATH)
                    .map_err(|e| ErrorKind::TransactionError(format!("create owner certificate file error: {}", e)))?;
                file.write_all(response.get_dk_cert())
                    .map_err(|e| ErrorKind::TransactionError(format!("write owner certificate error: {}", e)))?;
                if response.get_status().has_remain() {
                    let request = instructions::get_response::CommandApduGetResponse::new();
                    let mut apdu = ble::apdu::Apdu::new();
                    apdu.add_apdu_instruction(ApduInstructions::CommandGetResponse(request));
                    Ok(Message::new(
                        MessageType::Apdu,
                        MessageStatus::NoApplicable,
                        apdu.serialize()?.len() as u16,
                        MessageData::Apdu(apdu),
                    ))
                } else {
                    let vehicle_ca_certificate = Certificate::new(VEHICLE_OEM_CA_CERT_PATH)
                        .map_err(|e| ErrorKind::TransactionError(format!("load vehicle oem ca certificate error: {}", e)))?;
                    let owner_certificate = Certificate::new(OWNER_CERT_PATH)
                        .map_err(|e| ErrorKind::TransactionError(format!("load owner certificate error: {}", e)))?;
                    if let Ok(result) = vehicle_ca_certificate.verify(&owner_certificate) {
                        if result {
                            println!("Owner Certificate Verification OK!!!");
                            self.create_control_flow_request(CLA, instructions::control_flow::ControlFlowP1P2::StandardAuthSuccess)
                        } else {
                            println!("Owner Certificate Verification Failed!!!");
                            self.create_control_flow_request(CLA, instructions::control_flow::ControlFlowP1P2::StandardAuthFailedWithUnknownVehicle)
                        }
                    } else {
                        println!("Owner Certificate Verification Failed!!!");
                        self.create_control_flow_request(CLA, instructions::control_flow::ControlFlowP1P2::StandardAuthFailedWithInvalidAuthInfo)
                    }
                }
            }
            DkCertType::TempSharedCert => {
                todo!()
            }
            DkCertType::FriendKey => {
                todo!()
            }
        }
    }
    pub fn create_control_flow_request(&self, cla: u8, p1p2: instructions::control_flow::ControlFlowP1P2) -> Result<Message> {
        let request = instructions::control_flow::CommandApduControlFlow::new(
            cla,
            p1p2,
        );
        let mut apdu = ble::apdu::Apdu::new();
        apdu.add_apdu_instruction(ApduInstructions::CommandControlFlow(request));
        Ok(Message::new(
            MessageType::Apdu,
            MessageStatus::NoApplicable,
            apdu.serialize()?.len() as u16,
            MessageData::Apdu(apdu),
        ))
    }
    pub fn handle_control_flow_response(&self, response: &instructions::control_flow::ResponseApduControlFlow) -> Result<()> {
        info!("[Control Flow Response]: ");
        info!("\tstatus: {}", response.get_status());
        Ok(())
    }
}
