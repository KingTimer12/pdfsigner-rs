# pdfsigner-rs

[![CI](https://github.com/KingTimer12/pdfsigner-rs/workflows/CI/badge.svg)](https://github.com/KingTimer12/pdfsigner-rs/actions)
[![npm version](https://img.shields.io/npm/v/pdfsigner-rs.svg)](https://www.npmjs.com/package/pdfsigner-rs)

Biblioteca de alto desempenho para assinatura digital de documentos PDF usando certificados digitais no padrão ICP-Brasil, escrita em Rust com bindings para Node.js via NAPI-RS.

## 🚀 Características

- ✅ **Alta Performance**: Implementado em Rust para máxima velocidade
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
```

## 🔧 Uso

### Assinando um PDF a partir de um arquivo

```javascript
const { signPdfBuffer } = require('pdfsigner-rs');
const fs = require('fs');

// Assinar PDF e retornar buffer
const signedBuffer = signPdfBuffer(
  './certificado.pfx',           // Caminho para o certificado PFX
  'senha_do_certificado',         // Senha do certificado
  './documento.pdf',              // Caminho para o PDF a ser assinado
  'Assinatura digital',           // Motivo (opcional)
  'Brasil',                       // Localização (opcional)
  'contato@exemplo.com'          // Informações de contato (opcional)
);

// Salvar o PDF assinado
fs.writeFileSync('./documento_assinado.pdf', signedBuffer);
console.log('✓ PDF assinado com sucesso!');
```

### Assinando um PDF a partir de bytes (Buffer)

```javascript
const { signPdfFromBytes } = require('pdfsigner-rs');
const fs = require('fs');

// Ler o PDF como buffer
const pdfBuffer = fs.readFileSync('./documento.pdf');

// Assinar o buffer
const signedBuffer = signPdfFromBytes(
  './certificado.pfx',
  'senha_do_certificado',
  pdfBuffer,
  'Assinatura digital',
  'Brasil',
  'contato@exemplo.com'
);

// Salvar ou usar o buffer diretamente
fs.writeFileSync('./documento_assinado.pdf', signedBuffer);
```

### TypeScript

```typescript
import { signPdfBuffer, signPdfFromBytes } from 'pdfsigner-rs';

const signedBuffer: Buffer = signPdfBuffer(
  './certificado.pfx',
  'senha',
  './documento.pdf'
);
```

## 📝 API

### `signPdfBuffer(pfxPath, password, pdfPath, reason?, location?, contactInfo?): Buffer`

Assina um PDF a partir de um arquivo e retorna o buffer assinado.

**Parâmetros:**
- `pfxPath` (string): Caminho para o arquivo PFX/P12
- `password` (string): Senha do certificado
- `pdfPath` (string): Caminho para o PDF a ser assinado
- `reason` (string, opcional): Motivo da assinatura (padrão: "Assinatura digital conforme ICP-Brasil")
- `location` (string, opcional): Localização (padrão: "Brasil")
- `contactInfo` (string, opcional): Informações de contato (padrão: "")

**Retorna:** `Buffer` - Buffer do PDF assinado

### `signPdfFromBytes(pfxPath, password, pdfBytes, reason?, location?, contactInfo?): Buffer`

Assina um PDF a partir de bytes e retorna o buffer assinado.

**Parâmetros:**
- `pfxPath` (string): Caminho para o arquivo PFX/P12
- `password` (string): Senha do certificado
- `pdfBytes` (Buffer): Buffer contendo o PDF
- `reason` (string, opcional): Motivo da assinatura
- `location` (string, opcional): Localização
- `contactInfo` (string, opcional): Informações de contato

**Retorna:** `Buffer` - Buffer do PDF assinado

## 🏗️ Plataformas Suportadas

| Plataforma | Arquitetura | Status |
|------------|-------------|--------|
| Windows | x64 | ✅ |
| macOS | x64 | ✅ |
| macOS | ARM64 (Apple Silicon) | ✅ |
| Linux | x64 (glibc) | ✅ |

## 🔐 Segurança

- Suporta certificados digitais ICP-Brasil (A1)
- Implementa assinatura PAdES (PDF Advanced Electronic Signatures)
- Compatível com Adobe Reader e validadores ICP-Brasil
- OpenSSL para operações criptográficas

## 🛠️ Desenvolvimento

### Requisitos

- Rust (última versão estável)
- Node.js 16+
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
