use std::sync::Mutex;

use aes::Aes128;
use cmac::{Cmac, Mac};
use hkdf::Hkdf;
use openssl::{rsa::Rsa, pkey::{Private, PKey}, sign::{Signer, Verifier}, hash::MessageDigest, ec::{EcGroup, EcKey}, nid::Nid, derive::Deriver};
use sha2::Sha256;

use super::errors::*;

lazy_static! {
    static ref AUTH_SIGN_OBJECT: Mutex<AuthSignMaterial> = Mutex::new(AuthSignMaterial::new());
    static ref AUTH_KEY_PERSISTENT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static ref AUTH_KEY: Mutex<AuthKey> = Mutex::new(AuthKey::new());
}

#[derive(Debug, Default, Clone)]
pub struct AuthKey {
    key_enc: Option<Vec<u8>>,
    key_mac: Option<Vec<u8>>,
    kv_mac: Option<Vec<u8>>,
    kd_mac: Option<Vec<u8>>,
}

impl AuthKey {
    pub fn new() -> Self {
        AuthKey {
            ..Default::default()
        }
    }
    pub fn set_key_enc(&mut self, key_enc: &[u8]) {
        self.key_enc = Some(key_enc.to_vec());
    }
    pub fn set_key_mac(&mut self, key_mac: &[u8]) {
        self.key_mac = Some(key_mac.to_vec());
    }
    pub fn set_kv_mac(&mut self, kv_mac: &[u8]) {
        self.kv_mac = Some(kv_mac.to_vec());
    }
    pub fn set_kd_mac(&mut self, kd_mac: &[u8]) {
        self.kd_mac = Some(kd_mac.to_vec());
    }
    pub fn get_key_enc(&self) -> Vec<u8> {
        match &self.key_enc {
            Some(key_enc) => {
                key_enc.to_vec()
            },
            None => Vec::new()
        }
    }
    pub fn get_key_mac(&self) -> Vec<u8> {
        match &self.key_mac {
            Some(key_mac) => {
                key_mac.to_vec()
            },
            None => Vec::new()
        }
    }
    pub fn get_kv_mac(&self) -> Vec<u8> {
        match &self.kv_mac {
            Some(kv_mac) => {
                kv_mac.to_vec()
            },
            None => Vec::new()
        }
    }
    pub fn get_kd_mac(&self) -> Vec<u8> {
        match &self.kd_mac {
            Some(kd_mac) => {
                kd_mac.to_vec()
            },
            None => Vec::new()
        }
    }
}
#[derive(Debug, Clone)]
pub struct AuthSignMaterial {
    vehicle_temp_keypair: Option<PKey<Private>>,
    vehicle_id: Option<Vec<u8>>,
    mobile_temp_public_key: Option<Vec<u8>>,
    mobile_id: Option<Vec<u8>>,
}

impl AuthSignMaterial {
    pub fn new() -> Self {
        AuthSignMaterial {
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
    pub fn derive_key(&mut self) -> Result<()> {
        let mobile_public_pkey = PKey::public_key_from_pem(&self.get_mobile_temp_public_key_pem()?).map_err(|_| ErrorKind::ICCOAAuthError("get mobile temp pubkey to Pkey error".to_string()))?;
        match &self.vehicle_temp_keypair {
            Some(private_key) => {
                let mut deriver = Deriver::new(private_key).map_err(|_| ErrorKind::ICCOAAuthError("create deriver from temp vehicle private key error".to_string()))?;
                deriver.set_peer(mobile_public_pkey.as_ref()).map_err(|_| ErrorKind::ICCOAAuthError("deriver set mobile public key pair error".to_string()))?;
                let secret = deriver.derive_to_vec().map_err(|_| ErrorKind::ICCOAAuthError("deriver derive to vector error".to_string()))?;
                let mut info = Vec::new();
                info.append(&mut self.get_vehicle_temp_public_key_pem()?);
                info.append(&mut self.get_mobile_temp_public_key_pem()?);
                info.append(&mut self.get_vehicle_id()?);
                info.append(&mut self.get_mobile_id()?);
                info.append(&mut "ECDH".as_bytes().to_vec());

                let hk = Hkdf::<Sha256>::new(None, &secret);
                let mut okm = [0u8; 32];
                hk.expand(&info, &mut okm).map_err(|_| "HKDF Sha256 with info error".to_string())?;
                set_auth_key_enc(&okm[0..16]);
                set_auth_key_mac(&okm[16..32]);
                println!("key_enc = {:02X?}", get_auth_key_enc());
                println!("key_mac = {:02X?}", get_auth_key_mac());
                Ok(())
            },
            None => todo!(),
        }
    }
    pub fn derive_persistent(&mut self) -> Result<()> {
        let mobile_public_pkey = PKey::public_key_from_pem(&self.get_mobile_temp_public_key_pem()?).map_err(|_| ErrorKind::ICCOAAuthError("get mobile temp pubkey to Pkey error".to_string()))?;
        match &self.vehicle_temp_keypair {
            Some(private_key) => {
                let mut deriver = Deriver::new(private_key).map_err(|_| ErrorKind::ICCOAAuthError("create deriver from temp vehicle private key error".to_string()))?;
                deriver.set_peer(mobile_public_pkey.as_ref()).map_err(|_| ErrorKind::ICCOAAuthError("deriver set mobile public key pair error".to_string()))?;
                let secret = deriver.derive_to_vec().map_err(|_| ErrorKind::ICCOAAuthError("deriver derive to vector error".to_string()))?;
                let mut info = Vec::new();
                info.append(&mut self.get_vehicle_temp_public_key_pem()?);
                info.append(&mut self.get_mobile_temp_public_key_pem()?);
                info.append(&mut self.get_vehicle_id()?);
                info.append(&mut self.get_mobile_id()?);
                info.append(&mut "Persistent".as_bytes().to_vec());

                let hk = Hkdf::<Sha256>::new(None, &secret);
                let mut okm = [0u8; 32];
                hk.expand(&info, &mut okm).map_err(|_| "HKDF Sha256 with info error".to_string())?;
                set_auth_key_persistent(&okm);
                println!("key_persistent = {:02X?}", get_auth_key_persistent());
                Ok(())
            },
            None => todo!(),
        }
    }
    pub fn derive_fast_auth_shared_key(&mut self) -> Result<()> {
        let secret = get_auth_key_persistent();
        let mut info = Vec::new();
        info.append(&mut self.get_vehicle_temp_public_key_pem()?);
        info.append(&mut self.get_mobile_temp_public_key_pem()?);
        info.append(&mut self.get_vehicle_id()?);
        info.append(&mut self.get_mobile_id()?);
        info.append(&mut "FastAuth".as_bytes().to_vec());

        let hk = Hkdf::<Sha256>::new(None, &secret);
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm).map_err(|_| "HKDF Sha256 with info error".to_string())?;
        set_auth_kv_mac(&okm[0..16]);
        set_auth_kd_mac(&okm[16..32]);
        set_auth_key_enc(&okm[32..48]);
        set_auth_key_mac(&okm[48..64]);

        println!("kv_mac = {:02X?}", get_auth_kv_mac());
        println!("kd_mac = {:02X?}", get_auth_kd_mac());
        println!("key_enc = {:02X?}", get_auth_key_enc());
        println!("key_mac = {:02X?}", get_auth_key_mac());

        Ok(())
    }
    pub fn calculate_cryptogram(&self, mode: &str) -> Result<Vec<u8>> {
        let mut cryptogram_message = Vec::new();
        if mode == "vehicle" {
            cryptogram_message.append(&mut self.get_mobile_temp_public_key_pem()?);
            cryptogram_message.append(&mut self.get_mobile_id()?);
            calculate_cmac(&get_auth_kv_mac(), &cryptogram_message)
        } else {
            cryptogram_message.append(&mut self.get_vehicle_temp_public_key_pem()?);
            cryptogram_message.append(&mut self.get_vehicle_id()?);
            calculate_cmac(&get_auth_kd_mac(), &cryptogram_message)
        }
    }
}

pub fn get_auth_sign_object() -> AuthSignMaterial {
    let auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    auth_sign_object.clone()
}

pub fn set_auth_sign_object(object: &AuthSignMaterial) {
    let mut auth_sign_object = AUTH_SIGN_OBJECT.lock().unwrap();
    *auth_sign_object = object.clone();
}

pub fn get_auth_key_persistent() -> Vec<u8> {
    let auth_key_persistent = AUTH_KEY_PERSISTENT.lock().unwrap();
    auth_key_persistent.clone()
}

pub fn set_auth_key_persistent(key_persistent: &[u8]) {
    let mut auth_key_persistent = AUTH_KEY_PERSISTENT.lock().unwrap();
    auth_key_persistent.append(&mut key_persistent.to_vec());
}

pub fn get_auth_key_enc() -> Vec<u8> {
    let auth_key = AUTH_KEY.lock().unwrap();
    auth_key.get_key_enc()
}

pub fn set_auth_key_enc(key_enc: &[u8]) {
    let mut auth_key = AUTH_KEY.lock().unwrap();
    auth_key.set_key_enc(key_enc);
}

pub fn get_auth_key_mac() -> Vec<u8> {
    let auth_key = AUTH_KEY.lock().unwrap();
    auth_key.get_key_mac()
}

pub fn set_auth_key_mac(key_mac: &[u8]) {
    let mut auth_key = AUTH_KEY.lock().unwrap();
    auth_key.set_key_mac(key_mac);
}

pub fn get_auth_kv_mac() -> Vec<u8> {
    let auth_key = AUTH_KEY.lock().unwrap();
    auth_key.get_kv_mac()
}

pub fn set_auth_kv_mac(kv_mac: &[u8]) {
    let mut auth_key = AUTH_KEY.lock().unwrap();
    auth_key.set_kv_mac(kv_mac);
}

pub fn get_auth_kd_mac() -> Vec<u8> {
    let auth_key = AUTH_KEY.lock().unwrap();
    auth_key.get_kd_mac()
}

pub fn set_auth_kd_mac(kd_mac: &[u8]) {
    let mut auth_key = AUTH_KEY.lock().unwrap();
    auth_key.set_kd_mac(kd_mac);
}

pub fn calculate_cmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).map_err(|_| ErrorKind::ICCOAAuthError("create aes 128 cmac object error".to_string()))?;
    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
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
