use std::fs;
use std::path::Path;
use std::str::FromStr;
use openssl::pkey::{PKey, PKeyRef, Public};
use openssl::x509::{X509, X509Ref};
use x509_parser::der_parser::Oid;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use crate::iccoa2::errors::*;

pub const VEHICLE_OEM_CA_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle_oem_ca.pem";
#[allow(dead_code)]
pub const VEHICLE_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle.pem";
pub const OWNER_CERT_PATH: &str = "/etc/certs/iccoa2/owner.pem";
pub const MIDDLE_CERT_PATH: &str = "/etc/certs/iccoa2/middle.pem";
pub const FRIEND_CERT_PATH: &str = "/etc/certs/iccoa2/friend.pem";

pub const KEY_ID_OID_STR: &str = "1.3.6.1.4.1.59129.2.2";

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

#[allow(dead_code)]
pub fn get_certificate_extension<P: AsRef<Path>>(cert_path: P, oid_str: &str) -> Result<Vec<u8>> {
    let cert_string = fs::read_to_string(cert_path)
        .map_err(|e| ErrorKind::TransactionError(format!("read x509 certificate error: {}", e)))?;
    let cert_bytes = cert_string.as_bytes();
    let (_rem, pem) = parse_x509_pem(cert_bytes)
        .map_err(|e| ErrorKind::TransactionError(format!("parse x509 pem file error: {}", e)))?;
    let (_rem, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| ErrorKind::TransactionError(format!("parse pem x509 certificate error: {}", e)))?;
    let oid = Oid::from_str(oid_str)
        .map_err(|e| ErrorKind::TransactionError(format!("translate oid string to Oid Object error: {:?}", e)))?;
    for extension in cert.extensions() {
        if extension.oid.eq(&oid) {
            return Ok(extension.value.to_vec())
        }
    }
    Err(ErrorKind::TransactionError("oid string is not exist in x509 certificate".to_string()).into())
}
