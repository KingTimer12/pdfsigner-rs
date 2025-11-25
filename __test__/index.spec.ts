import { PDFDocument } from 'pdf-lib'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import fs from 'node:fs'
import path from 'node:path'
import test from 'ava'

import { signPdfWithPath, signPdf } from '../index'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

test('sync function from native code', (t) => {
  const pdfSigned = signPdfWithPath(
    {
      pfxPath: path.join(__dirname, 'certificado-a1.pfx'),
      pfxPassword: '123456',
    },
    path.join(__dirname, 'pdf_sample_2.pdf'),
    {
      reason: 'I approve this document',
      location: 'New York, USA',
    },
  )
  t.true(Buffer.isBuffer(pdfSigned.toBuffer()))
})

const fixDocument = async (pdfBytes: Buffer) => {
  const newPdfDoc = await PDFDocument.create()
  const pdfDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true })
  const pageCount = pdfDoc.getPageCount()
  const pageIndices = Array.from(Array(pageCount).keys())
  const copiedPages = await newPdfDoc.copyPages(pdfDoc, pageIndices)
  copiedPages.forEach((page) => newPdfDoc.addPage(page))
  const newPdfBytes = await newPdfDoc.save({ useObjectStreams: false })
  return Buffer.from(newPdfBytes)
}

test('testing fixDocument function', async (t) => {
  const pdfBytes = fs.readFileSync(path.join(__dirname, 'pdf_sample_2.pdf'))
  const fixedPdfBytes = await fixDocument(pdfBytes)
  const pdfSigned = signPdf(
    {
      pfxPath: path.join(__dirname, 'certificado-a1.pfx'),
      pfxPassword: '123456',
    },
    fixedPdfBytes,
    {
      reason: 'I approve this document',
      location: 'New York, USA',
    },
  )
  t.true(Buffer.isBuffer(pdfSigned.toBuffer()))
})
