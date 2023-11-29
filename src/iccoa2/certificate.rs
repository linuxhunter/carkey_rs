use std::fs;
use std::path::Path;
use openssl::pkey::{PKey, PKeyRef, Public};
use openssl::x509::{X509, X509Ref};
use crate::iccoa2::errors::*;

pub const VEHICLE_OEM_CA_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle_oem_ca.pem";
#[allow(dead_code)]
pub const VEHICLE_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle.pem";
pub const OWNER_CERT_PATH: &str = "/etc/certs/iccoa2/owner.pem";

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
