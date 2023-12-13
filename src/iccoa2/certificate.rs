use std::fs;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use openssl::pkey::{PKey, PKeyRef, Public};
use openssl::x509::{X509, X509Ref};
use x509_parser::der_parser::Oid;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use crate::iccoa2::errors::*;

#[allow(dead_code)]
pub const VEHICLE_OEM_CA_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle_oem_ca.pem";
#[allow(dead_code)]
pub const VEHICLE_CERT_PATH: &str = "/etc/certs/iccoa2/vehicle.pem";
#[allow(dead_code)]
pub const OWNER_CERT_PATH: &str = "/etc/certs/iccoa2/owner.pem";
#[allow(dead_code)]
pub const MIDDLE_CERT_PATH: &str = "/etc/certs/iccoa2/middle.pem";
#[allow(dead_code)]
pub const FRIEND_CERT_PATH: &str = "/etc/certs/iccoa2/friend.pem";

#[allow(dead_code)]
pub const VEHICLE_ID_OID_STR: &str = "1.3.6.1.4.1.59129.2.1";
#[allow(dead_code)]
pub const KEY_ID_OID_STR: &str = "1.3.6.1.4.1.59129.2.2";
#[allow(dead_code)]
pub const KEY_PERMISSION_ID_OID_STR: &str = "1.3.6.1.4.1.59129.2.4";
#[allow(dead_code)]
pub const VEHICLE_OEM_ID_OID_STR: &str = "1.3.6.1.4.1.59129.2.5";
#[allow(dead_code)]
pub const DEVICE_OEM_ID_OID_STR: &str = "1.3.6.1.4.1.59129.2.6";

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

pub fn write_certificate(cert_type: String, cert_data: &[u8]) -> Result<()> {
    let cert_file = if cert_type.eq_ignore_ascii_case("owner") {
        OWNER_CERT_PATH
    } else if cert_type.eq_ignore_ascii_case("middle") {
        MIDDLE_CERT_PATH
    } else if cert_type.eq_ignore_ascii_case("friend") {
        FRIEND_CERT_PATH
    } else {
        return Err(ErrorKind::TransactionError(format!("Certifiate type {} is not supported", cert_type)).into());
    };
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(cert_file)
        .map_err(|e| ErrorKind::TransactionError(format!("create middle certificate file error: {}", e)))?;
    file.write_all(cert_data)
        .map_err(|e| ErrorKind::TransactionError(format!("write middle certificate error: {}", e)))?;
    Ok(())
}
