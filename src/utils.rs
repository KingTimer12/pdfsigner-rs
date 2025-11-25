/// Utilidades para manipulação de PDFs
use crate::error::{PdfSignError, Result};

/// Remove trailing newlines do PDF (compatível com node-signpdf)
///
/// Node-signpdf remove `\n` e `\r` finais antes de processar o PDF
/// para garantir cálculos corretos do ByteRange
pub fn remove_trailing_newline(mut pdf: Vec<u8>) -> Vec<u8> {
  // Remove \n final
  while pdf.last() == Some(&b'\n') {
    pdf.pop();
  }
  // Remove \r final
  while pdf.last() == Some(&b'\r') {
    pdf.pop();
  }
  pdf
}

/// Encontra o próximo número de objeto disponível no PDF
pub fn get_next_object_number(pdf_data: &[u8]) -> Result<u32> {
  let pdf_str = String::from_utf8_lossy(pdf_data);
  let mut max_obj: u32 = 0;

  for line in pdf_str.lines() {
    if let Some(num_str) = line.split_whitespace().next() {
      if let Ok(num) = num_str.parse::<u32>() {
        if line.contains("0 obj") {
          max_obj = max_obj.max(num);
        }
      }
    }
  }

  Ok(max_obj + 1)
}

/// Estrutura com informações do Catalog do PDF
#[derive(Debug, Clone)]
pub struct PdfCatalogInfo {
  pub catalog_obj: usize,
  pub pages_ref: usize,
  pub has_acroform: bool,
}

/// Extrai informações do Catalog do PDF de forma robusta
/// Funciona mesmo com PDFs reconstruídos que têm estruturas não padrão
pub fn extract_catalog_info(pdf_data: &[u8]) -> Result<PdfCatalogInfo> {
  let pdf_str = String::from_utf8_lossy(pdf_data);

  // Primeiro, tenta encontrar o Catalog via startxref/trailer/Root
  let catalog_obj = find_catalog_from_trailer(&pdf_str).unwrap_or_else(|| {
    // Fallback: busca por /Type /Catalog diretamente
    find_catalog_by_pattern(pdf_data).unwrap_or(1)
  });

  // Busca a referência /Pages dentro do Catalog
  let pages_ref = find_pages_ref_in_catalog(pdf_data, catalog_obj).unwrap_or_else(|| {
    // Fallback: busca o objeto Pages diretamente
    find_pages_object(pdf_data).unwrap_or(1)
  });

  // Valida que o objeto Pages realmente existe
  let pages_ref = validate_pages_object(pdf_data, pages_ref).unwrap_or(pages_ref);

  // Verifica se já tem AcroForm
  let has_acroform = check_catalog_has_acroform(pdf_data, catalog_obj);

  Ok(PdfCatalogInfo {
    catalog_obj,
    pages_ref,
    has_acroform,
  })
}

/// Encontra o objeto Catalog através do trailer (método correto)
fn find_catalog_from_trailer(pdf_str: &str) -> Option<usize> {
  // Busca o último trailer (em caso de atualizações incrementais)
  let trailer_pos = pdf_str.rfind("trailer")?;
  let trailer_section = &pdf_str[trailer_pos..];

  // Procura /Root N 0 R
  let root_pos = trailer_section.find("/Root")?;
  let after_root = &trailer_section[root_pos + 5..];

  // Extrai o número do objeto
  for word in after_root.split_whitespace() {
    if let Ok(num) = word.parse::<usize>() {
      return Some(num);
    }
  }

  None
}

/// Busca o Catalog por padrão /Type /Catalog ou /Type/Catalog (fallback)
fn find_catalog_by_pattern(pdf_data: &[u8]) -> Option<usize> {
  // Tenta ambos os padrões: com e sem espaço
  let catalog_markers = [b"/Type /Catalog" as &[u8], b"/Type/Catalog"];

  for catalog_marker in &catalog_markers {
    if let Some(catalog_start) = pdf_data
      .windows(catalog_marker.len())
      .position(|w| w == *catalog_marker)
    {
      // Procura para trás para encontrar "N 0 obj"
      // Aumentado para 2000 bytes pois PDFs podem ter objetos muito grandes
      let search_start = catalog_start.saturating_sub(2000);
      let obj_pattern = b" 0 obj";

      if let Some(obj_pos) = pdf_data[search_start..catalog_start]
        .windows(obj_pattern.len())
        .rposition(|w| w == obj_pattern)
      {
        let actual_pos = search_start + obj_pos;
        let mut num_start = actual_pos;

        while num_start > 0 && pdf_data[num_start - 1] >= b'0' && pdf_data[num_start - 1] <= b'9' {
          num_start -= 1;
        }

        if let Ok(obj_str) = std::str::from_utf8(&pdf_data[num_start..actual_pos]) {
          if let Ok(obj_num) = obj_str.trim().parse::<usize>() {
            return Some(obj_num);
          }
        }
      }
    }
  }

  None
}

/// Encontra a referência /Pages dentro de um objeto Catalog
fn find_pages_ref_in_catalog(pdf_data: &[u8], catalog_obj: usize) -> Option<usize> {
  // Busca o objeto do Catalog
  let catalog_pattern = format!("{} 0 obj", catalog_obj);
  let catalog_start = pdf_data
    .windows(catalog_pattern.len())
    .position(|w| w == catalog_pattern.as_bytes())?;

  // Encontra o fim do objeto (endobj)
  let catalog_end = pdf_data[catalog_start..]
    .windows(b"endobj".len())
    .position(|w| w == b"endobj")?
    + catalog_start;

  let catalog_section = &pdf_data[catalog_start..catalog_end];

  // Busca /Pages N 0 R
  let pages_pos = catalog_section
    .windows(b"/Pages".len())
    .position(|w| w == b"/Pages")?;

  let after_pages = &catalog_section[pages_pos + 6..];
  let pages_str = std::str::from_utf8(after_pages).ok()?;

  // Extrai o primeiro número após /Pages
  for word in pages_str.split_whitespace() {
    if let Ok(num) = word.parse::<usize>() {
      return Some(num);
    }
  }

  None
}

/// Verifica se o Catalog já tem AcroForm
fn check_catalog_has_acroform(pdf_data: &[u8], catalog_obj: usize) -> bool {
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
      return catalog_section
        .windows(b"/AcroForm".len())
        .any(|w| w == b"/AcroForm");
    }
  }
  false
}

/// Estrutura com informações da primeira página do PDF
#[derive(Debug, Clone)]
pub struct PdfPageInfo {
  pub first_page_obj: usize,
}

/// Extrai informações sobre a primeira página do PDF de forma robusta
pub fn extract_first_page_info(pdf_data: &[u8]) -> Result<PdfPageInfo> {
  // Método 1: Busca /Type /Page diretamente (mais simples e funciona com PDFs reconstruídos)
  let first_page_obj = find_first_page_by_pattern(pdf_data).ok_or_else(|| {
    PdfSignError::InvalidPdf("Não foi possível encontrar a primeira página".to_string())
  })?;

  Ok(PdfPageInfo { first_page_obj })
}

/// Busca a primeira página por padrão /Type /Page ou /Type/Page
/// IMPORTANTE: Diferencia /Type /Page de /Type /Pages (com 's' no final)
fn find_first_page_by_pattern(pdf_data: &[u8]) -> Option<usize> {
  // Tenta ambos os padrões: com e sem espaço
  let page_markers = [b"/Type /Page" as &[u8], b"/Type/Page"];

  for page_marker in &page_markers {
    let mut pos = 0;
    while pos < pdf_data.len() {
      if let Some(relative_pos) = pdf_data[pos..]
        .windows(page_marker.len())
        .position(|w| w == *page_marker)
      {
        let page_start = pos + relative_pos;

        // CRÍTICO: Verifica se o próximo caractere NÃO é 's'
        // Isso evita confundir "/Type /Page" com "/Type /Pages" ou "/Type/Pages"
        let next_char_pos = page_start + page_marker.len();
        if next_char_pos < pdf_data.len() {
          let next_char = pdf_data[next_char_pos];

          // Se o próximo char é 's', isso é "/Type /Pages" ou "/Type/Pages", não "/Type /Page" ou "/Type/Page"
          if next_char == b's' {
            // Continua buscando
            pos = page_start + 1;
            continue;
          }
        }

        // Encontrou um "/Type /Page" ou "/Type/Page" válido (não é /Pages)
        // Procura para trás para encontrar "N 0 obj"
        // Aumentado para 2000 bytes pois PDFs podem ter objetos muito grandes (ex: muitos recursos)
        let search_start = page_start.saturating_sub(2000);
        let obj_pattern = b" 0 obj";

        if let Some(obj_pos) = pdf_data[search_start..page_start]
          .windows(obj_pattern.len())
          .rposition(|w| w == obj_pattern)
        {
          let actual_pos = search_start + obj_pos;
          let mut num_start = actual_pos;

          while num_start > 0 && pdf_data[num_start - 1] >= b'0' && pdf_data[num_start - 1] <= b'9'
          {
            num_start -= 1;
          }

          if let Ok(obj_str) = std::str::from_utf8(&pdf_data[num_start..actual_pos]) {
            if let Ok(obj_num) = obj_str.trim().parse::<usize>() {
              return Some(obj_num);
            }
          }
        }

        // Se não conseguiu extrair o número, continua buscando
        pos = page_start + 1;
      } else {
        // Não encontrou mais ocorrências com este padrão
        break;
      }
    }
  }

  None
}

/// Busca o objeto Pages diretamente (fallback quando não encontrado no Catalog)
fn find_pages_object(pdf_data: &[u8]) -> Option<usize> {
  // Tenta ambos os padrões: com e sem espaço
  let pages_markers = [b"/Type /Pages" as &[u8], b"/Type/Pages"];

  for pages_marker in &pages_markers {
    if let Some(pages_start) = pdf_data
      .windows(pages_marker.len())
      .position(|w| w == *pages_marker)
    {
      // Procura para trás para encontrar "N 0 obj"
      // Aumentado para 2000 bytes pois PDFs podem ter objetos muito grandes
      let search_start = pages_start.saturating_sub(2000);
      let obj_pattern = b" 0 obj";

      if let Some(obj_pos) = pdf_data[search_start..pages_start]
        .windows(obj_pattern.len())
        .rposition(|w| w == obj_pattern)
      {
        let actual_pos = search_start + obj_pos;
        let mut num_start = actual_pos;

        while num_start > 0 && pdf_data[num_start - 1] >= b'0' && pdf_data[num_start - 1] <= b'9' {
          num_start -= 1;
        }

        if let Ok(obj_str) = std::str::from_utf8(&pdf_data[num_start..actual_pos]) {
          if let Ok(obj_num) = obj_str.trim().parse::<usize>() {
            return Some(obj_num);
          }
        }
      }
    }
  }

  None
}

/// Valida que o objeto Pages existe e é válido
fn validate_pages_object(pdf_data: &[u8], pages_obj: usize) -> Option<usize> {
  // Verifica se existe um objeto com esse número
  let obj_pattern = format!("{} 0 obj", pages_obj);

  if pdf_data
    .windows(obj_pattern.len())
    .any(|w| w == obj_pattern.as_bytes())
  {
    return Some(pages_obj);
  }

  // Se não encontrou, tenta buscar o objeto Pages diretamente
  find_pages_object(pdf_data)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_remove_trailing_newline() {
    let pdf = b"test\n\n".to_vec();
    let result = remove_trailing_newline(pdf);
    assert_eq!(result, b"test");

    let pdf = b"test\r\n".to_vec();
    let result = remove_trailing_newline(pdf);
    assert_eq!(result, b"test");
  }

  #[test]
  fn test_get_next_object_number() {
    let pdf = b"1 0 obj\n<<\n>>\n5 0 obj\n<<\n>>\n";
    let result = get_next_object_number(pdf).unwrap();
    assert_eq!(result, 6);
  }
}
