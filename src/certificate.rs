use der_parser::asn1_rs::FromDer;
use x509_parser::prelude::X509Certificate;

use crate::error::{PdfSignError, Result};

/// Estrutura para armazenar certificado X.509
#[derive(Clone)]
pub struct Certificate {
  der_bytes: Vec<u8>,
  parsed: X509Certificate<'static>,
}

impl Certificate {
  pub fn from_der(der: Vec<u8>) -> Result<Self> {
    // Converte para 'static lifetime
    let owned_der = der.clone();
    let parsed_static = X509Certificate::from_der(&owned_der)
      .map_err(|e| PdfSignError::DecodingError(format!("Erro ao parsear certificado: {:?}", e)))?
      .1;

    Ok(Self {
      der_bytes: der,
      parsed: unsafe { std::mem::transmute(parsed_static) },
    })
  }

  pub fn der(&self) -> &[u8] {
    &self.der_bytes
  }

  pub fn subject_cn(&self) -> Option<String> {
    // Usa OpenSSL para extrair o CN de forma mais confiável
    use openssl::x509::X509;

    if let Ok(cert) = X509::from_der(&self.der_bytes) {
      let subject = cert.subject_name();
      for entry in subject.entries() {
        if entry.object().nid().as_raw() == openssl::nid::Nid::COMMONNAME.as_raw() {
          if let Ok(data) = entry.data().as_utf8() {
            return Some(data.to_string());
          }
        }
      }
    }

    None
  }

  pub fn subject_org(&self) -> Option<String> {
    // Usa OpenSSL para extrair a organização
    use openssl::x509::X509;

    if let Ok(cert) = X509::from_der(&self.der_bytes) {
      let subject = cert.subject_name();
      for entry in subject.entries() {
        if entry.object().nid().as_raw() == openssl::nid::Nid::ORGANIZATIONNAME.as_raw() {
          if let Ok(data) = entry.data().as_utf8() {
            return Some(data.to_string());
          }
        }
      }
    }

    None
  }

  pub fn not_before(&self) -> String {
    self.parsed.validity().not_before.to_string()
  }

  pub fn not_after(&self) -> String {
    self.parsed.validity().not_after.to_string()
  }

  pub fn serial_number(&self) -> String {
    hex::encode(self.parsed.serial.to_bytes_be())
  }
}
