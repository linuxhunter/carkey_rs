use std::sync::Mutex;

use openssl::{rsa::Rsa, pkey::{Private, PKey}, sign::{Signer, Verifier}, hash::MessageDigest, ec::{EcGroup, EcKey}, nid::Nid};

use super::errors::*;

lazy_static! {
    static ref AUTH_SIGN_OBJECT: Mutex<AuthSign> = Mutex::new(AuthSign::new());
}

#[derive(Debug, Clone)]
pub struct AuthSign {
    vehicle_temp_keypair: Option<PKey<Private>>,
    vehicle_id: Option<Vec<u8>>,
    mobile_temp_public_key: Option<Vec<u8>>,
    mobile_id: Option<Vec<u8>>,
}

impl AuthSign {
    pub fn new() -> Self {
        AuthSign {
            vehicle_temp_keypair: None,
            vehicle_id: Some([0x10; 16].to_vec()),
            mobile_temp_public_key: None,
            mobile_id: None,
        }
    }
    pub fn create_vehicle_temp_keypair(&mut self, mode: &str) -> Result<()> {
        if mode == "rsa" {
            let vehicle_temp_rsa = Rsa::generate(1024).map_err(|_| ErrorKind::ICCOAAuthError("create temp rsa keypair error".to_string()))?;
            let keypair = PKey::from_rsa(vehicle_temp_rsa).map_err(|_| ErrorKind::ICCOAAuthError("create pkey error".to_string()))?;
            self.vehicle_temp_keypair = Some(keypair);
            Ok(())
        } else if mode == "ec" {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| ErrorKind::ICCOAAuthError("create EC Group with SECP256K1 error".to_string()))?;
            let keypair = EcKey::generate(&group).map_err(|_| ErrorKind::ICCOAAuthError("create EC key pair error".to_string()))?;
            let pkey = PKey::from_ec_key(keypair).map_err(|_| ErrorKind::ICCOAAuthError("create PKey from EC keypair error".to_string()))?;
            self.vehicle_temp_keypair = Some(pkey);
            Ok(())
        } else {
            return Err(ErrorKind::ICCOAAuthError("not supported key mode error".to_string()).into());
        }
    }
    pub fn set_vehicle_id(&mut self, vehicle_id: &[u8]) {
        self.vehicle_id = Some(vehicle_id.to_vec());
    }
    pub fn set_mobile_temp_public_key_pem(&mut self, public_key_pem: &[u8]) -> Result<()> {
        self.mobile_temp_public_key = Some(public_key_pem.to_vec());
        Ok(())
    }
    pub fn set_mobile_id(&mut self, mobile_id: &[u8]) {
        self.mobile_id = Some(mobile_id.to_vec());
    }
    pub fn get_vehicle_temp_public_key_pem(&self) -> Result<Vec<u8>> {
        match &self.vehicle_temp_keypair {
            Some(vehicle_temp_keypair) => {
                let public_key_pem = vehicle_temp_keypair.public_key_to_pem().map_err(|_| ErrorKind::ICCOAAuthError("get vehicle temp public key error".to_string()))?;
                Ok(public_key_pem)
            },
            None => {
                return Err(ErrorKind::ICCOAAuthError("vehicle temp public key is empty".to_string()).into())
            }
        }
    }
    pub fn get_mobile_temp_public_key_pem(&self) -> Result<Vec<u8>> {
        match &self.mobile_temp_public_key {
            Some(mobile_temp_public_key) => {
                Ok(mobile_temp_public_key.to_vec())
            },
            None => {
                return Err(ErrorKind::ICCOAAuthError("mobile temp public key is empty".to_string()).into())
            }
        }
    }
    pub fn get_vehicle_id(&self) -> Result<Vec<u8>> {
        match &self.vehicle_id {
            Some(vehicle_id) => {
                Ok(vehicle_id.clone())
            },
            None => {
                return Err(ErrorKind::ICCOAAuthError("vehicle id is empty".to_string()).into())
            }
        }
    }
    pub fn get_mobile_id(&self) -> Result<Vec<u8>> {
        match &self.mobile_id {
            Some(mobile_id) => {
                Ok(mobile_id.clone())
            },
            None => {
                return Err(ErrorKind::ICCOAAuthError("mobile id is empty".to_string()).into())
            }
        }
    }
    pub fn signature(&self) -> Result<Vec<u8>> {
        let mut vehicle_auth_info = Vec::new();
        vehicle_auth_info.append(&mut self.get_vehicle_temp_public_key_pem()?);
        vehicle_auth_info.append(&mut self.get_mobile_temp_public_key_pem()?);
        vehicle_auth_info.append(&mut self.get_mobile_id()?);
        vehicle_auth_info.append(&mut "Auth".as_bytes().to_vec());

        println!("vehicle_auth_info = {:02X?}", vehicle_auth_info);
        match &self.vehicle_temp_keypair {
            Some(vehicle_temp_private_key) => {
                let mut signer = Signer::new(MessageDigest::sha256(), &vehicle_temp_private_key).unwrap();
                signer.update(&vehicle_auth_info).unwrap();
                signer.sign_to_vec().map_err(|_| ErrorKind::ICCOAAuthError("signature vehicle auth info error".to_string()).into())
            },
            None => {
                return Err(ErrorKind::ICCOAAuthError("vehicle temp private key is empty".to_string()).into())
            }
        }
    }
    pub fn verify(&self, signature: &[u8]) -> Result<bool> {
        let mut mobile_auth_info = Vec::new();
        mobile_auth_info.append(&mut self.get_vehicle_temp_public_key_pem()?);
        mobile_auth_info.append(&mut self.get_mobile_temp_public_key_pem()?);
        mobile_auth_info.append(&mut self.get_vehicle_id()?);
        mobile_auth_info.append(&mut "Auth".to_string().into_bytes());

        match &self.mobile_temp_public_key {
            Some(mobile_temp_public_key) => {
                let pubkey = PKey::public_key_from_pem(&mobile_temp_public_key).unwrap();
                let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
                verifier.update(&mobile_auth_info).unwrap();
                verifier.verify(signature).map_err(|_| ErrorKind::ICCOAAuthError("verify mobile auth info error".to_string()).into())
            },
            None => {
                return Err(ErrorKind::ICCOAAuthError("mobile temp public key is empty".to_string()).into())
            }
        }
    }
}

pub fn get_auth_sign_object() -> AuthSign {
    let auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    auth_sign_object.clone()
}

pub fn set_auth_sign_object(object: &AuthSign) {
    let mut auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    *auth_sign_object = object.clone();
}

pub fn get_vehicle_id() -> [u8; 16] {
    [0x10; 16]
}

mod tests {
    use super::*;

    #[test]
    fn test_rsa_auth_sign_object() {
        let mut object = get_auth_sign_object();
        let _ = object.create_vehicle_temp_keypair("rsa");
        println!("vehicle public key = {}", std::str::from_utf8(object.get_vehicle_temp_public_key_pem().unwrap().as_slice()).unwrap());
        set_auth_sign_object(&object);
    }
    #[test]
    fn test_eckey_auth_sign_object() {
        let mut object = get_auth_sign_object();
        let _ = object.create_vehicle_temp_keypair("ec");
        println!("vehicle public key = {}", std::str::from_utf8(object.get_vehicle_temp_public_key_pem().unwrap().as_slice()).unwrap());
        set_auth_sign_object(&object);
    }
}
