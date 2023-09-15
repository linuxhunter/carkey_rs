use aes::Aes128;
use cmac::{Cmac, Mac};
use hkdf::Hkdf;
use openssl::{rsa::Rsa, pkey::{Private, PKey}, sign::{Signer, Verifier}, hash::MessageDigest, ec::{EcGroup, EcKey}, nid::Nid, derive::Deriver, symm::{encrypt, decrypt}};
use sha2::Sha256;

use super::errors::*;

pub trait KeyMaterialOperation {
    fn signature(&self) -> Result<Vec<u8>>;
    fn verify(&self, signature: &[u8]) -> Result<bool>;
    fn derive_key(&mut self, ikm: Option<&[u8]>, other_materials: &[u8], key_length: usize) -> Result<Vec<u8>>;
}

#[derive(Debug, Default, Clone)]
pub struct CipherKey {
    key_enc: Option<Vec<u8>>,
    key_mac: Option<Vec<u8>>,
    kv_mac: Option<Vec<u8>>,
    kd_mac: Option<Vec<u8>>,
}

impl CipherKey {
    pub fn new() -> Self {
        CipherKey {
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
            None => [0x00; 16].to_vec()
        }
    }
    pub fn get_key_mac(&self) -> Vec<u8> {
        match &self.key_mac {
            Some(key_mac) => {
                key_mac.to_vec()
            },
            None => [0x00; 16].to_vec()
        }
    }
    pub fn get_kv_mac(&self) -> Vec<u8> {
        match &self.kv_mac {
            Some(kv_mac) => {
                kv_mac.to_vec()
            },
            None => [0x00; 16].to_vec()
        }
    }
    pub fn get_kd_mac(&self) -> Vec<u8> {
        match &self.kd_mac {
            Some(kd_mac) => {
                kd_mac.to_vec()
            },
            None => [0x00; 16].to_vec()
        }
    }
}
#[derive(Debug, Clone)]
pub struct KeyDeriveMaterial {
    vehicle_temp_keypair: Option<PKey<Private>>,
    vehicle_id: Option<Vec<u8>>,
    mobile_temp_public_key: Option<Vec<u8>>,
    mobile_id: Option<Vec<u8>>,
}

impl KeyDeriveMaterial {
    pub fn new() -> Self {
        KeyDeriveMaterial {
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
    pub fn serialize_key_material(&self, op_type: &str, other_materials: &[u8]) -> Result<Vec<u8>> {
        let mut key_material = Vec::new();
        key_material.append(&mut self.get_vehicle_temp_public_key_pem()?);
        key_material.append(&mut self.get_mobile_temp_public_key_pem()?);
        if op_type == "signature" {
            key_material.append(&mut self.get_mobile_id()?);
        } else if op_type == "verify" {
            key_material.append(&mut self.get_vehicle_id()?);
        } else if op_type == "derive" {
            key_material.append(&mut self.get_vehicle_id()?);
            key_material.append(&mut self.get_mobile_id()?);
        }
        key_material.append(&mut other_materials.to_vec());
        Ok(key_material)
    }
    pub fn calculate_cryptogram(&self, key: &[u8], mode: &str) -> Result<Vec<u8>> {
        let mut cryptogram_message = Vec::new();
        if mode == "vehicle" {
            cryptogram_message.append(&mut self.get_mobile_temp_public_key_pem()?);
            cryptogram_message.append(&mut self.get_mobile_id()?);
        } else {
            cryptogram_message.append(&mut self.get_vehicle_temp_public_key_pem()?);
            cryptogram_message.append(&mut self.get_vehicle_id()?);
        };
        calculate_cmac(key, &cryptogram_message)
    }
}

impl KeyMaterialOperation for KeyDeriveMaterial {
    fn signature(&self) -> Result<Vec<u8>> {
        let vehicle_auth_info = self.serialize_key_material("signature", "Auth".as_bytes())?;
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

    fn verify(&self, signature: &[u8]) -> Result<bool> {
        let mobile_auth_info = self.serialize_key_material("verify", "Auth".as_bytes())?;
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

    fn derive_key(&mut self, ikm: Option<&[u8]>, other_materials: &[u8], key_length: usize) -> Result<Vec<u8>> {
        let secret = match ikm {
            Some(value) => {
                value.to_vec()
            },
            None => {
                let mobile_public_pkey = PKey::public_key_from_pem(&self.get_mobile_temp_public_key_pem()?).map_err(|_| ErrorKind::ICCOAAuthError("get mobile temp pubkey to Pkey error".to_string()))?;
                match &self.vehicle_temp_keypair {
                    Some(private_key) => {
                        let mut deriver = Deriver::new(private_key).map_err(|_| ErrorKind::ICCOAAuthError("create deriver from temp vehicle private key error".to_string()))?;
                        deriver.set_peer(mobile_public_pkey.as_ref()).map_err(|_| ErrorKind::ICCOAAuthError("deriver set mobile public key pair error".to_string()))?;
                        deriver.derive_to_vec().map_err(|_| ErrorKind::ICCOAAuthError("deriver derive to vector error".to_string()))?
                    },
                    None => todo!()
                }
            },
        };
        let info = self.serialize_key_material("derive", other_materials)?;
        Ok(calculate_derive_key(None, &secret, &info, key_length))
    }
}

pub fn calculate_derive_key(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], key_length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).unwrap();
    okm[0..key_length].to_vec()
}

pub fn calculate_sha256(message: &[u8]) -> Vec<u8> {
    let mut hasher =  openssl::sha::Sha256::new();
    hasher.update(message);
    hasher.finish().to_vec()
}

pub fn calculate_cmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).map_err(|_| ErrorKind::ICCOAAuthError("create aes 128 cmac object error".to_string()))?;
    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

pub fn encrypt_aes_128_cbc(key: &[u8], plain_text: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_128_cbc();
    encrypt(cipher, key, Some(iv), plain_text).map_err(|_| ErrorKind::ICCOAEncryptError("aes 128 cbc encrypt data error".to_string()).into())
}

pub fn decrypt_aes_128_cbc(key: &[u8], cipher_text: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_128_cbc();
    decrypt(cipher, key, Some(iv), cipher_text).map_err(|_| ErrorKind::ICCOAEncryptError("aes 128 cbc decrypt data error".to_string()).into())
}

pub fn get_default_iv() -> [u8; 16] {
    [0x00; 16]
}
