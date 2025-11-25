use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum PdfSignError {
  #[error("Erro ao ler arquivo: {0}")]
  IoError(#[from] std::io::Error),

  #[error("Certificado inválido ou senha incorreta")]
  InvalidCertificate,

  #[error("PDF inválido: {0}")]
  InvalidPdf(String),

  #[error("Erro ao assinar: {0}")]
  SigningError(String),

  #[error("Erro na validação da cadeia ICP-Brasil: {0}")]
  IcpBrasilValidationError(String),

  #[error("Erro ao obter timestamp: {0}")]
  TimestampError(String),

  #[error("Erro de rede: {0}")]
  NetworkError(String),

  #[error("Erro ao decodificar: {0}")]
  DecodingError(String),

  #[error("Erro RSA: {0}")]
  RsaError(String),

  #[error("Erro AWS S3: {0}")]
  AwsS3Error(String),
}

pub type Result<T> = std::result::Result<T, PdfSignError>;

impl From<PdfSignError> for napi::Error {
  fn from(err: PdfSignError) -> Self {
    napi::Error::new(napi::Status::GenericFailure, err.to_string())
  }
}
