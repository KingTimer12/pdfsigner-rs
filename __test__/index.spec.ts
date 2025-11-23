import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import path from 'node:path'
import test from 'ava'

import { signPdf } from '../index'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

test('sync function from native code', (t) => {
  const pdfBuffer = signPdf({
    pfxPath: path.join(__dirname, 'certificado-a1.pfx'),
    pfxPassword: '123456'
  }, path.join(__dirname, 'pdf_sample_2.pdf'), {
    reason: 'I approve this document',
    location: 'New York, USA',
  })
  t.true(Buffer.isBuffer(pdfBuffer))
})
