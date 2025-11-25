# pdfsigner-rs

[![CI](https://github.com/KingTimer12/pdfsigner-rs/workflows/CI/badge.svg)](https://github.com/KingTimer12/pdfsigner-rs/actions)
[![npm version](https://img.shields.io/npm/v/pdfsigner-rs.svg)](https://www.npmjs.com/package/pdfsigner-rs)

Biblioteca de alto desempenho para assinatura digital de documentos PDF usando certificados digitais no padrão ICP-Brasil, escrita em Rust com bindings para Node.js via NAPI-RS.

## 🚀 Características

- ✅ **Alta Performance**: Implementado em Rust para máxima velocidade
- ✅ **Otimizado**: Binários com menos de 10MB
- ✅ **Suporte AWS3**: Salve o arquivo assinado em um bucket AWS S3
- ✅ **Compatível com ICP-Brasil**: Suporta certificados A1 (PFX/P12)
- ✅ **Padrão PAdES**: Assinaturas compatíveis com Adobe Reader
- ✅ **Zero Dependências Nativas**: Binários pré-compilados para todas as plataformas
- ✅ **TypeScript**: Tipagem completa incluída
- ✅ **Cross-Platform**: Windows, macOS e Linux

## 📦 Instalação

```bash
npm install pdfsigner-rs
# ou
yarn add pdfsigner-rs
# ou
pnpm add pdfsigner-rs
# ou
bun add pdfsigner-rs
```

## 🔧 Uso

### Assinando um PDF a partir de um arquivo

```javascript
const { signPdfWithPath } = require('pdfsigner-rs')
const fs = require('fs')

// Assinar PDF e retornar buffer
// Nesse método usamos o caminho do documento ao invés de ser buffer.
const pdfSigned = signPdfWithPath(
  {
    pfxPath: path.join(__dirname, 'certificado.pfx'),
    pfxPassword: 'senha',
  },
  path.join(__dirname, 'pdf_sample_2.pdf'),
  {
    reason: 'I approve this document',
    location: 'New York, USA',
  },
)

// Salvar o PDF assinado
fs.writeFileSync('./documento_assinado.pdf', pdfSigned.toBuffer())
console.log('✓ PDF assinado com sucesso!')
```

### Assinando um PDF a partir de bytes (Buffer)

```javascript
const { signPdf } = require('pdfsigner-rs')
const fs = require('fs')

// Ler o PDF como buffer
const pdfBuffer = fs.readFileSync('./documento.pdf')

// Assinar o buffer
// Nesse método usamos o buffer do documento.
const pdfSigned = signPdf(
  {
    pfxPath: path.join(__dirname, 'certificado.pfx'),
    pfxPassword: 'senha',
  },
  pdfBuffer,
  {
    reason: 'I approve this document',
    location: 'New York, USA',
  },
)

// Salvar ou usar o buffer diretamente
fs.writeFileSync('./documento_assinado.pdf', pdfSigned.toBuffer())
```

### TypeScript

```typescript
import { signPdf } from 'pdfsigner-rs'

const pdfSigned: PdfSigned = signPdf(
  {
    pfxPath: path.join(__dirname, 'certificado.pfx'),
    pfxPassword: 'senha',
  },
  pdfBuffer,
  {
    reason: 'I approve this document',
    location: 'New York, USA',
  },
)
```

## 📝 API

### `signPdf(certificate: CertificateInfo, pdfData: Buffer, config?: Config | undefined | null): PdfSigned`

Assina um PDF a partir de bytes e retorna o buffer assinado.

**Parâmetros:**

- `certificate` (CertificateInfo): Informações do certificado
- `pdfData` (Buffer): Buffer contendo o PDF
- `config` (Config | undefined | null, opcional): Configurações adicionais

**Retorna:** `PdfSigned` - Uma classe que representa o PDF assinado

### `signPdfWithPath(certificate: CertificateInfo, pdfPath: string, config?: Config | undefined | null): PdfSigned`

Assina um PDF a partir de um caminho de arquivo e retorna o buffer assinado.

**Parâmetros:**

- `certificate` (CertificateInfo): Informações do certificado
- `pdfPath` (string): Caminho para o arquivo PDF
- `config` (Config | undefined | null, opcional): Configurações adicionais

**Retorna:** `PdfSigned` - Uma classe que representa o PDF assinado

## 🏗️ Plataformas Suportadas

| Plataforma | Arquitetura           | Status |
| ---------- | --------------------- | ------ |
| Windows    | x64                   | ✅     |
| macOS      | x64                   | ✅     |
| macOS      | ARM64 (Apple Silicon) | ✅     |
| Linux      | x64 (glibc)           | ✅     |

## 🔐 Segurança

- Suporta certificados digitais ICP-Brasil (A1)
- Implementa assinatura PAdES (PDF Advanced Electronic Signatures)
- Compatível com Adobe Reader e validadores ICP-Brasil
- OpenSSL para operações criptográficas

## 🛠️ Desenvolvimento

### Requisitos

- Rust (última versão estável)
- Node.js 20+
- Yarn 1.x ou superior

### Build Local

```bash
# Instalar dependências
yarn install

# Build do projeto
yarn build

# Executar testes
yarn test

# Lint
yarn lint
```

## 📄 Licença

MIT

## 🤝 Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

## 👤 Autor

**AaronKing** - [@KingTimer12](https://github.com/KingTimer12)

## 🙏 Agradecimentos

- Baseado em [NAPI-RS](https://napi.rs/) para bindings Rust ↔ Node.js
- Inspirado em [node-signpdf](https://github.com/vbuch/node-signpdf)
