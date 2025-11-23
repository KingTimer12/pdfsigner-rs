#![deny(clippy::all)]

mod certificate;
mod error;
mod pdfsigner;
mod signature_config;
mod utils;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use pdfsigner::PdfSigner;
use signature_config::SignatureConfig;

#[napi(object)]
pub struct CertificateInfo {
  pub pfx_path: String,
  pub pfx_password: String,
}

#[napi(object)]
pub struct Config {
  pub reason: Option<String>,
  pub location: Option<String>,
  pub contact_info: Option<String>,
}

// Função para assinar PDF
#[napi]
pub fn sign_pdf(
  certificate: CertificateInfo,
  pdf_path: String,
  config: Option<Config>,
) -> Result<Buffer> {
  let signer = PdfSigner::from_pfx_file(&certificate.pfx_path, &certificate.pfx_password)
    .map_err(|e| Error::from_reason(format!("Erro ao carregar certificado: {}", e)))?;

  let mut signature_config = SignatureConfig::default();
  if let Some(cfg) = config {
    if let Some(reason) = cfg.reason {
      signature_config.reason = reason;
    }
    if let Some(location) = cfg.location {
      signature_config.location = location;
    }
    if let Some(contact_info) = cfg.contact_info {
      signature_config.contact_info = contact_info;
    }
  }

  let signed_buffer = signer
    .sign_pdf(&pdf_path, &signature_config)
    .map_err(|e| Error::from_reason(format!("Erro ao assinar PDF: {}", e)))?;

  Ok(Buffer::from(signed_buffer))
}
