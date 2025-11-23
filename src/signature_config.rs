/// Configuração para assinatura PAdES
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SignatureConfig {
  /// Motivo da assinatura
  pub reason: String,
  /// Localização da assinatura
  pub location: String,
  /// Informações de contato
  pub contact_info: String,
  /// URL do servidor de timestamp (TSA)
  pub tsa_url: Option<String>,
  /// Validar cadeia ICP-Brasil
  pub validate_icp_brasil: bool,
  /// Incluir OCSP (Online Certificate Status Protocol)
  pub include_ocsp: bool,
  /// Incluir CRL (Certificate Revocation List)
  pub include_crl: bool,
  /// Nível PAdES (B-B, B-T, B-LT, B-LTA)
  pub pades_level: PadesLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
pub enum PadesLevel {
  /// PAdES-B-B: Assinatura básica
  BB,
  /// PAdES-B-T: Assinatura com timestamp
  BT,
  /// PAdES-B-LT: Assinatura com validação long-term (OCSP/CRL)
  BLT,
  /// PAdES-B-LTA: Assinatura com archive timestamp
  BLTA,
}

impl Default for SignatureConfig {
  fn default() -> Self {
    Self {
      reason: "Assinatura digital conforme ICP-Brasil".to_string(),
      location: "Brasil".to_string(),
      contact_info: String::new(),
      tsa_url: Some("http://timestamp.iti.gov.br/".to_string()),
      validate_icp_brasil: true,
      include_ocsp: true,
      include_crl: true,
      pades_level: PadesLevel::BLT,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_signature_config_default() {
    let config = SignatureConfig::default();
    assert_eq!(config.pades_level, PadesLevel::BLT);
    assert!(config.validate_icp_brasil);
  }

  #[test]
  fn test_pades_level_comparison() {
    assert!(PadesLevel::BT >= PadesLevel::BB);
    assert!(PadesLevel::BLT >= PadesLevel::BT);
    assert!(PadesLevel::BLTA >= PadesLevel::BLT);
  }
}
