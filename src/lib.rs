#![deny(clippy::all)]

mod certificate;
mod error;
mod pdfsigner;
mod signature_config;
mod utils;

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{self as s3, primitives::ByteStream};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use pdfsigner::PdfSigner;
use signature_config::SignatureConfig;

#[napi(object)]
pub struct S3Info {
  pub bucket: String,
  pub access_key: String,
  pub secret_key: String,
  pub endpoint: String,
  pub region: Option<String>,
  pub provider_name: Option<String>,
}

#[napi(object)]
pub struct CertificateInfo {
  pub pfx_path: Option<String>,
  pub pfx_data: Option<Buffer>,
  pub pfx_password: String,
}

#[napi(object)]
pub struct Config {
  pub reason: Option<String>,
  pub location: Option<String>,
  pub contact_info: Option<String>,
}

#[napi(string_enum)]
pub enum SaveFormat {
  File,
  S3,
}

#[napi(constructor)]
pub struct PdfSigned {
  pub data: Arc<Vec<u8>>,
  #[napi(skip)]
  pub s3_info: Option<S3Info>,
}

#[napi]
impl PdfSigned {
  pub fn new(data: Vec<u8>) -> Self {
    PdfSigned {
      data: Arc::new(data),
      s3_info: None,
    }
  }

  #[napi]
  pub fn credentials_provider(&self, s3_info: S3Info) -> Self {
    PdfSigned {
      data: Arc::clone(&self.data),
      s3_info: Some(s3_info),
    }
  }

  #[napi]
  pub fn to_buffer(&self) -> Buffer {
    Buffer::from(self.data.as_slice())
  }

  #[napi]
  pub async fn save(&self, path: String, format: SaveFormat) -> Result<()> {
    match format {
      SaveFormat::File => tokio::fs::write(&path, self.data.as_ref())
        .await
        .map_err(|e| Error::from_reason(format!("Erro ao salvar PDF: {}", e))),
      SaveFormat::S3 => match &self.s3_info {
        Some(s3_info) => {
          let access_key = s3_info.access_key.clone();
          let secret_key = s3_info.secret_key.clone();
          let provider_name = s3_info.provider_name.clone().unwrap_or_default();
          let endpoint = s3_info.endpoint.clone();
          let region = s3_info.region.clone().unwrap();
          let bucket = s3_info.bucket.clone();

          let credentials = aws_sdk_s3::config::Credentials::new(
            access_key.leak() as &str,
            secret_key.leak() as &str,
            None,
            None,
            provider_name.leak() as &str,
          );
          let config = aws_config::defaults(BehaviorVersion::latest())
            .endpoint_url(endpoint)
            .credentials_provider(credentials)
            .region(Region::new(region))
            .load()
            .await;
          let client = s3::Client::new(&config);
          let body = ByteStream::from(self.data.as_ref().clone());
          client
            .put_object()
            .bucket(bucket)
            .key(path)
            .body(body)
            .send()
            .await
            .map_err(|e| Error::from_reason(format!("Erro ao fazer upload para S3: {}", e)))?;
          Ok(())
        }
        None => Err(Error::from_reason("S3 credentials not provided")),
      },
    }
  }
}

// Função para assinar PDF
#[napi]
pub fn sign_pdf(
  certificate: CertificateInfo,
  pdf_data: Buffer,
  config: Option<Config>,
) -> Result<PdfSigned> {
  let signer = if let Some(pfx_path) = certificate.pfx_path {
    PdfSigner::from_pfx_file(&pfx_path, &certificate.pfx_password)
      .map_err(|e| Error::from_reason(format!("Erro ao carregar certificado: {}", e)))?
  } else {
    PdfSigner::from_pfx_bytes(&certificate.pfx_data.unwrap(), &certificate.pfx_password)
      .map_err(|e| Error::from_reason(format!("Erro ao carregar certificado: {}", e)))?
  };

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
    .sign_pdf(pdf_data.into(), &signature_config)
    .map_err(|e| Error::from_reason(format!("Erro ao assinar PDF: {}", e)))?;

  Ok(PdfSigned::new(signed_buffer))
}

// Função para assinar PDF a partir de um caminho
#[napi]
pub fn sign_pdf_with_path(
  certificate: CertificateInfo,
  pdf_path: String,
  config: Option<Config>,
) -> Result<PdfSigned> {
  let signer = if let Some(pfx_path) = certificate.pfx_path {
    PdfSigner::from_pfx_file(&pfx_path, &certificate.pfx_password)
      .map_err(|e| Error::from_reason(format!("Erro ao carregar certificado: {}", e)))?
  } else {
    PdfSigner::from_pfx_bytes(&certificate.pfx_data.unwrap(), &certificate.pfx_password)
      .map_err(|e| Error::from_reason(format!("Erro ao carregar certificado: {}", e)))?
  };

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
    .sign_pdf_with_path(&pdf_path, &signature_config)
    .map_err(|e| Error::from_reason(format!("Erro ao assinar PDF: {}", e)))?;

  Ok(PdfSigned::new(signed_buffer))
}
