/// Utilidades para manipulação de PDFs
use crate::error::Result;

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
