use base64::Engine;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::certificate::Certificate;
use crate::error::{PdfSignError, Result};
use crate::signature_config::SignatureConfig;
use crate::utils::{
  extract_catalog_info, extract_first_page_info, get_next_object_number, remove_trailing_newline,
};

/// Estrutura principal para assinatura de PDFs
pub struct PdfSigner {
  _private_key: RsaPrivateKey,
  _certificate: Certificate,
  _cert_chain: Vec<Certificate>,
  _pem_content: String,
}

impl PdfSigner {
  /// Cria um novo assinador a partir de um arquivo PFX/P12
  pub fn from_pfx_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
    let pfx_data = fs::read(path)?;
    Self::from_pfx_bytes_openssl(&pfx_data, password)
  }

  /// Extrai chave e certificados usando o openssl crate
  fn from_pfx_bytes_openssl(pfx_data: &[u8], password: &str) -> Result<Self> {
    use openssl::pkcs12::Pkcs12;
    use openssl::provider::Provider;

    // Carrega o provider legado e o provider padrão do OpenSSL 3.x
    // Isso é necessário para suportar algoritmos antigos como RC2-40-CBC
    let _legacy = Provider::load(None, "legacy").ok();
    let _default = Provider::load(None, "default").ok();

    let pkcs12 = Pkcs12::from_der(pfx_data)
      .map_err(|e| PdfSignError::DecodingError(format!("Erro ao parsear PKCS#12: {:?}", e)))?;

    let parsed = pkcs12.parse2(password).map_err(|e| {
      PdfSignError::DecodingError(format!("Erro ao descriptografar PKCS#12: {:?}", e))
    })?;

    // Cria conteúdo PEM ANTES de consumir o parsed
    let pem_content = Self::create_pem_from_openssl(&parsed)?;

    // Extrai a chave privada
    let private_key_der = if let Some(pkey) = parsed.pkey {
      pkey.private_key_to_der().map_err(|e| {
        PdfSignError::DecodingError(format!("Erro ao exportar chave privada: {:?}", e))
      })?
    } else {
      return Err(PdfSignError::DecodingError(
        "Nenhuma chave privada encontrada no PKCS#12".to_string(),
      ));
    };

    // Extrai certificados
    let mut cert_ders = Vec::new();
    if let Some(cert) = parsed.cert {
      let cert_der = cert.to_der().map_err(|e| {
        PdfSignError::DecodingError(format!("Erro ao exportar certificado: {:?}", e))
      })?;
      cert_ders.push(cert_der);
    }

    if let Some(chain) = parsed.ca {
      for cert in chain {
        let cert_der = cert.to_der().map_err(|e| {
          PdfSignError::DecodingError(format!("Erro ao exportar certificado da cadeia: {:?}", e))
        })?;
        cert_ders.push(cert_der);
      }
    }

    if cert_ders.is_empty() {
      return Err(PdfSignError::InvalidCertificate);
    }

    // Decodifica a chave privada RSA
    let private_key: RsaPrivateKey = RsaPrivateKey::from_pkcs8_der(&private_key_der)
      .or_else(|_| {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        RsaPrivateKey::from_pkcs1_der(&private_key_der)
      })
      .map_err(|e| {
        PdfSignError::DecodingError(format!("Erro ao decodificar chave privada: {:?}", e))
      })?;

    // Parseia o primeiro certificado
    let certificate: Certificate = Certificate::from_der(cert_ders[0].clone())?;

    // Restantes são a cadeia
    let mut cert_chain: Vec<Certificate> = Vec::new();
    for cert_der in cert_ders.iter().skip(1) {
      if let Ok(cert) = Certificate::from_der(cert_der.clone()) {
        cert_chain.push(cert);
      }
    }

    Ok(Self {
      _private_key: private_key,
      _certificate: certificate,
      _cert_chain: cert_chain,
      _pem_content: pem_content,
    })
  }

  /// Cria conteúdo PEM usando o OpenSSL diretamente
  fn create_pem_from_openssl(parsed: &openssl::pkcs12::ParsedPkcs12_2) -> Result<String> {
    let mut pem = String::new();

    // Exporta chave privada
    if let Some(ref pkey) = parsed.pkey {
      let key_pem = pkey.private_key_to_pem_pkcs8().map_err(|e| {
        PdfSignError::DecodingError(format!("Erro ao exportar chave privada PEM: {:?}", e))
      })?;
      pem.push_str(&String::from_utf8_lossy(&key_pem));
    }

    // Exporta certificado principal
    if let Some(ref cert) = parsed.cert {
      let cert_pem = cert.to_pem().map_err(|e| {
        PdfSignError::DecodingError(format!("Erro ao exportar certificado PEM: {:?}", e))
      })?;
      pem.push_str(&String::from_utf8_lossy(&cert_pem));
    }

    // Exporta cadeia de certificados
    if let Some(ref chain) = parsed.ca {
      for cert in chain {
        let cert_pem = cert.to_pem().map_err(|e| {
          PdfSignError::DecodingError(format!(
            "Erro ao exportar certificado da cadeia PEM: {:?}",
            e
          ))
        })?;
        pem.push_str(&String::from_utf8_lossy(&cert_pem));
      }
    }

    Ok(pem)
  }

  /// Assina um PDF a partir de bytes e retorna o buffer assinado
  pub fn sign_pdf_bytes(&self, mut pdf_data: Vec<u8>, config: &SignatureConfig) -> Result<Vec<u8>> {
    // CRÍTICO: Remove trailing newlines ANTES de processar (node-signpdf faz isso!)
    pdf_data = remove_trailing_newline(pdf_data);

    // 1. Cria estrutura PKCS#7/CMS para assinatura (será substituído depois)
    let _signature_cms = self.create_pkcs7_signature(&pdf_data, config)?;

    // 2. Cria o dicionário de assinatura PDF

    // Calcula o tamanho necessário para a assinatura (com padding moderado)
    // Uma assinatura PKCS#7 típica com cadeia de certificados pode ter ~7-8KB
    // JavaScript que funciona usa ~8KB, vamos usar o mesmo
    let sig_size = 16000; // 16KB de espaço para a assinatura (8000 hex chars)
    let sig_placeholder = "<".to_string() + &"0".repeat(sig_size) + ">";

    // 3. Monta o PDF com o dicionário de assinatura
    let next_obj = get_next_object_number(&pdf_data)?;

    // Extrai o nome do signatário do certificado (CN - Common Name)
    let signer_name = self
      ._certificate
      .subject_cn()
      .unwrap_or_else(|| "Unknown".to_string());

    // IMPORTANTE: A data será definida DEPOIS, junto com a assinatura PKCS7
    // para garantir que /M e signingTime sejam idênticos (Adobe valida isso!)
    // Usando placeholder de tamanho fixo: D:YYYYMMDDHHmmSSZ = 18 caracteres
    let date_placeholder = "D:00000000000000Z";

    // JavaScript: ByteRange antes de Contents, e DEPOIS de Contents vêm os outros campos!
    // Estrutura: /ByteRange [...] /Contents <...zeros...> /Reason (...) /M (...) etc
    // IMPORTANTE: JavaScript usa EXATAMENTE 17 espaços DEPOIS do ] (padrão fixo)
    // Placeholder: 7 dígitos cada (suporta até 9.999.999 bytes = ~10MB)
    let sig_dict = format!(
            "{} 0 obj\n<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n/ByteRange [0000000 0000000 0000000 0000000]                 \n/Contents {}\n/Reason ({})\n/M ({})\n/ContactInfo ({})\n/Name ({})\n/Location ({})\n/Prop_Build <<\n/Filter <<\n/Name /Adobe.PPKLite\n>>\n>>\n>>\nendobj\n",
            next_obj,
            sig_placeholder,
            config.reason,
            date_placeholder,
            config.contact_info,
            signer_name,
            config.location
        );

    // 4. Insere a assinatura no PDF usando ATUALIZAÇÃO INCREMENTAL
    // CRÍTICO: NÃO modificar o PDF original! Apenas adicionar novos objetos!
    // Isso garante que o ByteRange seja válido e a assinatura seja aceita

    let mut output = Vec::new();

    // Extrai informações do PDF de forma robusta (funciona com PDFs reconstruídos)
    let catalog_info = extract_catalog_info(&pdf_data)?;
    let page_info = extract_first_page_info(&pdf_data)?;

    let catalog_obj = catalog_info.catalog_obj;
    let pages_ref = catalog_info.pages_ref;
    let first_page_obj = page_info.first_page_obj;

    // Copia o PDF original INTEIRO sem modificações
    output.extend_from_slice(&pdf_data);

    // CRÍTICO: Adiciona \n após o PDF original (remove_trailing_newline removeu!)
    // Node-signpdf faz isso implicitamente ao usar Buffer.concat com '\n'
    output.push(b'\n');

    // IMPORTANTE: Calcular posições ANTES de adicionar os objetos
    // As posições devem ser relativas ao tamanho atual do output
    let sig_dict_pos = output.len();

    // Adiciona o dicionário de assinatura
    output.extend_from_slice(sig_dict.as_bytes());

    // Calcula posição do AcroForm
    let acroform_pos = output.len();

    // Adiciona referência ao campo de assinatura no catálogo
    // JavaScript que funciona tem /Type /AcroForm e /SigFlags 3
    let acroform = format!(
      "{} 0 obj\n<<\n/Type /AcroForm\n/SigFlags 3\n/Fields [{} 0 R]\n>>\nendobj\n",
      next_obj + 1,
      next_obj + 2
    );
    output.extend_from_slice(acroform.as_bytes());

    // Calcula posição do sig_field
    let sig_field_pos = output.len();

    // JavaScript que funciona tem campos adicionais no widget de assinatura
    // IMPORTANTE: /P deve referenciar o objeto da primeira página, não hardcoded como 1 0 R
    let sig_field = format!(
            "{} 0 obj\n<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/Rect [0 0 0 0]\n/V {} 0 R\n/T (Signature1)\n/F 4\n/P {} 0 R\n>>\nendobj\n",
            next_obj + 2,
            next_obj,
            first_page_obj
        );
    output.extend_from_slice(sig_field.as_bytes());

    // CRÍTICO: Adiciona um NOVO Catalog que substitui o original na atualização incremental
    // Isso é o que o JavaScript faz! Não modifica o Catalog original, cria um novo!
    let new_catalog_pos = output.len();

    // IMPORTANTE: Preserva estruturas adicionais do Catalog original se existirem
    // PDFs reconstruídos podem ter campos personalizados que precisam ser mantidos
    let new_catalog =
      build_updated_catalog(catalog_obj, pages_ref, (next_obj + 1) as usize, &pdf_data)?;

    output.extend_from_slice(new_catalog.as_bytes());

    // Encontra o startxref anterior
    let pdf_str_for_xref = String::from_utf8_lossy(&pdf_data);
    let prev_xref = if let Some(pos) = pdf_str_for_xref.rfind("startxref\n") {
      let start = pos + "startxref\n".len();
      if let Some(end) = pdf_str_for_xref[start..].find("\n") {
        pdf_str_for_xref[start..start + end]
          .trim()
          .parse::<usize>()
          .unwrap_or(0)
      } else {
        0
      }
    } else {
      0
    };

    // Cria xref table incremental
    // IMPORTANTE: Formato correto de subsecções no xref
    // Primeiro uma entrada para o objeto 0 (sempre f = free)
    // Depois os 3 novos objetos em sequência
    // Depois uma subsecção para o Catalog que está sendo substituído
    let xref_start = output.len();
    let xref = format!(
            "xref\n0 1\n0000000000 65535 f \n{} 1\n{:010} 00000 n \n{} 3\n{:010} 00000 n \n{:010} 00000 n \n{:010} 00000 n \n",
            catalog_obj,
            new_catalog_pos,
            next_obj,
            sig_dict_pos,
            acroform_pos,
            sig_field_pos
        );
    output.extend_from_slice(xref.as_bytes());

    // Adiciona trailer
    // IMPORTANTE: Usa catalog_obj como Root (agora aponta para o novo Catalog)
    let trailer = format!(
      "trailer\n<<\n/Size {}\n/Prev {}\n/Root {} 0 R\n>>\nstartxref\n{}\n%%EOF\n",
      next_obj + 3,
      prev_xref,
      catalog_obj,
      xref_start
    );
    output.extend_from_slice(trailer.as_bytes());

    // 5. CRÍTICO: Encontra ByteRange e calcula posições EXATAMENTE como node-signpdf
    // Node-signpdf: busca o placeholder, depois busca /Contents APÓS o ByteRange

    let byte_range_search = b"/ByteRange [0000000 0000000 0000000 0000000]                 ";
    let range_pos = output
      .windows(byte_range_search.len())
      .position(|w| w == byte_range_search)
      .ok_or_else(|| PdfSignError::InvalidPdf("ByteRange não encontrado".to_string()))?;

    let byterange_placeholder_len = byte_range_search.len();
    let byterange_end = range_pos + byterange_placeholder_len;

    // CRÍTICO: Busca /Contents DEPOIS do ByteRange (node-signpdf faz assim!)
    let contents_tag_pos = output[byterange_end..]
      .windows(b"/Contents ".len())
      .position(|w| w == b"/Contents ")
      .ok_or_else(|| {
        PdfSignError::InvalidPdf("/Contents não encontrado após ByteRange".to_string())
      })?
      + byterange_end;

    // Busca o '<' que inicia o placeholder da assinatura (DEPOIS do /Contents)
    let placeholder_pos = output[contents_tag_pos..]
      .windows(1)
      .position(|w| w == b"<")
      .ok_or_else(|| PdfSignError::InvalidPdf("< não encontrado após /Contents".to_string()))?
      + contents_tag_pos;

    // Busca o '>' que termina o placeholder
    let placeholder_end = output[placeholder_pos..]
      .windows(1)
      .position(|w| w == b">")
      .ok_or_else(|| PdfSignError::InvalidPdf("> não encontrado após <".to_string()))?
      + placeholder_pos;

    let placeholder_length_with_brackets = (placeholder_end + 1) - placeholder_pos;

    // 6. Calcula ByteRange EXATAMENTE como node-signpdf
    let byte_range_values = [
      0,
      placeholder_pos,
      placeholder_pos + placeholder_length_with_brackets,
      output.len() - (placeholder_pos + placeholder_length_with_brackets),
    ];

    // 7. Cria string do ByteRange com PADDING DINÂMICO (como node-signpdf!)
    let byte_range_str_raw = format!(
      "/ByteRange [{} {} {} {}]",
      byte_range_values[0], byte_range_values[1], byte_range_values[2], byte_range_values[3]
    );

    // CRÍTICO: Padding dinâmico até o tamanho do placeholder original!
    let padding_needed = byterange_placeholder_len - byte_range_str_raw.len();
    let byte_range_str = format!("{}{}", byte_range_str_raw, " ".repeat(padding_needed));

    // 8. Substitui ByteRange MANTENDO O TAMANHO (node-signpdf faz assim!)
    if byte_range_str.len() != byterange_placeholder_len {
      return Err(PdfSignError::InvalidPdf(format!(
        "ByteRange com padding ({}) != placeholder ({})",
        byte_range_str.len(),
        byterange_placeholder_len
      )));
    }

    output[range_pos..range_pos + byterange_placeholder_len]
      .copy_from_slice(byte_range_str.as_bytes());

    // 9. Prepara o conteúdo a ser assinado (excluindo o placeholder da assinatura)
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(
      &output[byte_range_values[0]..byte_range_values[0] + byte_range_values[1]],
    );
    to_sign.extend_from_slice(
      &output[byte_range_values[2]..byte_range_values[2] + byte_range_values[3]],
    );

    // 10. Captura o timestamp AGORA (antes de assinar) para garantir que /M e signingTime
    // no PKCS7 sejam idênticos - Adobe Reader valida isso!
    let now = chrono::Utc::now();
    let date_str = format!("D:{}Z", now.format("%Y%m%d%H%M%S"));

    // Substitui o placeholder da data pelo timestamp real
    let date_placeholder_bytes = b"D:00000000000000Z";
    let date_pos = output
      .windows(date_placeholder_bytes.len())
      .position(|w| w == date_placeholder_bytes)
      .ok_or_else(|| PdfSignError::InvalidPdf("Placeholder de data não encontrado".to_string()))?;

    let date_bytes = date_str.as_bytes();
    if date_bytes.len() != date_placeholder_bytes.len() {
      return Err(PdfSignError::InvalidPdf(format!(
        "Data tem tamanho errado: {} vs {}",
        date_bytes.len(),
        date_placeholder_bytes.len()
      )));
    }
    output[date_pos..date_pos + date_bytes.len()].copy_from_slice(date_bytes);

    // IMPORTANTE: Recalcula to_sign após substituir a data!
    to_sign.clear();
    to_sign.extend_from_slice(
      &output[byte_range_values[0]..byte_range_values[0] + byte_range_values[1]],
    );
    to_sign.extend_from_slice(
      &output[byte_range_values[2]..byte_range_values[2] + byte_range_values[3]],
    );

    // Usa a API OpenSSL para criar o PKCS#7 corretamente
    // IMPORTANTE: Isso deve acontecer IMEDIATAMENTE após capturar o timestamp
    // para que o signingTime no PKCS7 seja o mais próximo possível do /M
    let final_cms = self.create_pkcs7_detached(&to_sign, config)?;

    // Codifica a assinatura em hex
    let sig_hex = hex::encode(&final_cms);

    // Verifica se a assinatura cabe no placeholder (sem os delimitadores < >)
    if sig_hex.len() > sig_size {
      return Err(PdfSignError::InvalidPdf(format!(
        "Assinatura muito grande: {} bytes, mas placeholder tem apenas {} bytes",
        sig_hex.len(),
        sig_size
      )));
    }

    // Preenche com zeros para manter o tamanho do placeholder
    let padded_sig_hex = format!("{}{}", sig_hex, "0".repeat(sig_size - sig_hex.len()));
    let final_sig_hex = format!("<{}>", padded_sig_hex);

    // 12. Substitui placeholder pela assinatura real - usa placeholder_pos que já foi calculado!
    let sig_bytes = final_sig_hex.as_bytes();

    // Verifica que o tamanho é exatamente o mesmo
    if sig_bytes.len() != placeholder_length_with_brackets {
      return Err(PdfSignError::InvalidPdf(format!(
        "Tamanho da assinatura final ({}) diferente do placeholder ({})",
        sig_bytes.len(),
        placeholder_length_with_brackets
      )));
    }

    output[placeholder_pos..placeholder_pos + sig_bytes.len()].copy_from_slice(sig_bytes);

    Ok(output)
  }

  /// Assina um PDF com configuração completa
  pub fn sign_pdf(&self, pdf_data: Vec<u8>, config: &SignatureConfig) -> Result<Vec<u8>> {
    self.sign_pdf_bytes(pdf_data, config)
  }

  /// Assina um PDF com configuração completa
  pub fn sign_pdf_with_path<P: AsRef<Path>>(
    &self,
    input_path: P,
    config: &SignatureConfig,
  ) -> Result<Vec<u8>> {
    let pdf_data = fs::read(input_path)?;
    self.sign_pdf(pdf_data, config)
  }

  /// Cria estrutura PKCS#7/CMS detached usando OpenSSL
  fn create_pkcs7_detached(&self, data: &[u8], _config: &SignatureConfig) -> Result<Vec<u8>> {
    use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
    use openssl::pkey::PKey;
    use openssl::stack::Stack;
    use openssl::x509::X509;

    // Carrega TUDO do mesmo PEM para garantir compatibilidade
    use openssl::provider::Provider;

    // Garante que os providers estão carregados
    let _legacy = Provider::load(None, "legacy").ok();
    let _default = Provider::load(None, "default").ok();

    let pem_bytes = self._pem_content.as_bytes();

    let pkey = PKey::private_key_from_pem(pem_bytes).map_err(|e| {
      PdfSignError::DecodingError(format!("Erro ao carregar chave privada: {:?}", e))
    })?;

    // Carrega o primeiro certificado do mesmo PEM
    let cert = X509::from_pem(pem_bytes)
      .map_err(|e| PdfSignError::DecodingError(format!("Erro ao carregar certificado: {:?}", e)))?;

    // Cria stack com a cadeia de certificados
    let mut certs = Stack::new()
      .map_err(|e| PdfSignError::DecodingError(format!("Erro ao criar stack: {:?}", e)))?;

    for cert_chain in &self._cert_chain {
      let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD
          .encode(cert_chain.der())
          .as_bytes()
          .chunks(64)
          .map(|chunk| std::str::from_utf8(chunk).unwrap())
          .collect::<Vec<_>>()
          .join("\n")
      );

      if let Ok(c) = X509::from_pem(cert_pem.as_bytes()) {
        certs.push(c).map_err(|e| {
          PdfSignError::DecodingError(format!("Erro ao adicionar certificado à cadeia: {:?}", e))
        })?;
      }
    }

    // Cria PKCS#7 detached (sem incluir o conteúdo, mas COM atributos assinados)
    // NOSMIMECAP: remove S/MIME capabilities (não usado em PDF)
    // Não usar NOATTR pois ele remove TODOS atributos incluindo messageDigest que é obrigatório
    let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY | Pkcs7Flags::NOSMIMECAP;

    let pkcs7 = Pkcs7::sign(&cert, &pkey, &certs, data, flags)
      .map_err(|e| PdfSignError::DecodingError(format!("Erro ao criar PKCS#7: {:?}", e)))?;

    // Converte para DER
    let pkcs7_der = pkcs7
      .to_der()
      .map_err(|e| PdfSignError::DecodingError(format!("Erro ao serializar PKCS#7: {:?}", e)))?;

    Ok(pkcs7_der)
  }

  /// Cria estrutura PKCS#7/CMS inicial (placeholder)
  fn create_pkcs7_signature(&self, _pdf_data: &[u8], _config: &SignatureConfig) -> Result<Vec<u8>> {
    // Por enquanto retorna um PKCS#7 vazio, será substituído depois
    Ok(vec![0u8; 256])
  }

  /// Retorna informações do certificado
  #[allow(dead_code)]
  pub fn get_certificate_info(&self) -> CertificateInfo {
    CertificateInfo {
      common_name: self._certificate.subject_cn().unwrap_or_default(),
      organization: self._certificate.subject_org(),
      email: None,
      valid_from: self._certificate.not_before(),
      valid_until: self._certificate.not_after(),
      serial_number: Some(self._certificate.serial_number()),
    }
  }
}

/// Informações do certificado
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CertificateInfo {
  pub common_name: String,
  pub organization: Option<String>,
  pub email: Option<String>,
  pub valid_from: String,
  pub valid_until: String,
  pub serial_number: Option<String>,
}

/// Constrói um novo Catalog preservando campos extras do original
/// Isso é crítico para PDFs reconstruídos que podem ter metadados personalizados
fn build_updated_catalog(
  catalog_obj: usize,
  pages_ref: usize,
  acroform_ref: usize,
  pdf_data: &[u8],
) -> Result<String> {
  // Busca o Catalog original
  let catalog_pattern = format!("{} 0 obj", catalog_obj);

  if let Some(catalog_start) = pdf_data
    .windows(catalog_pattern.len())
    .position(|w| w == catalog_pattern.as_bytes())
  {
    if let Some(catalog_end) = pdf_data[catalog_start..]
      .windows(b"endobj".len())
      .position(|w| w == b"endobj")
    {
      let catalog_section = &pdf_data[catalog_start..catalog_start + catalog_end];

      // Extrai campos extras do Catalog (tudo exceto /Type, /Pages e /AcroForm)
      let catalog_str = String::from_utf8_lossy(catalog_section);

      // Procura o dicionário do catalog (entre << e >>)
      if let Some(dict_start) = catalog_str.find("<<") {
        if let Some(dict_end) = catalog_str.rfind(">>") {
          let dict_content = &catalog_str[dict_start + 2..dict_end];

          // Extrai campos extras (preserva tudo exceto /Type, /Pages, /AcroForm)
          let mut extra_fields = Vec::new();
          let lines: Vec<&str> = dict_content.lines().collect();

          for line in lines {
            let trimmed = line.trim();
            // Ignora campos que vamos redefinir
            if !trimmed.starts_with("/Type")
              && !trimmed.starts_with("/Pages")
              && !trimmed.starts_with("/AcroForm")
              && !trimmed.is_empty()
            {
              extra_fields.push(trimmed);
            }
          }

          // Constrói o novo Catalog com campos extras preservados
          let mut new_catalog = format!(
            "{} 0 obj\n<<\n/Type /Catalog\n/Pages {} 0 R\n/AcroForm {} 0 R\n",
            catalog_obj, pages_ref, acroform_ref
          );

          // Adiciona campos extras
          for field in extra_fields {
            new_catalog.push_str(field);
            new_catalog.push('\n');
          }

          new_catalog.push_str(">>\nendobj\n");
          return Ok(new_catalog);
        }
      }
    }
  }

  // Fallback: cria Catalog básico se não conseguir extrair o original
  Ok(format!(
    "{} 0 obj\n<<\n/Type /Catalog\n/Pages {} 0 R\n/AcroForm {} 0 R\n>>\nendobj\n",
    catalog_obj, pages_ref, acroform_ref
  ))
}
