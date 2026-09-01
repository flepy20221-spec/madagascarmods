const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const missionEvidenceRouter = require('../src/routes/missionEvidence');

async function withEvidenceServer(callback) {
  const app = express();
  app.use('/api/mission-evidence', missionEvidenceRouter);
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  try {
    const address = server.address();
    return await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('rotas publicas de comprovante usam limiter dedicado e nao o bucket geral por IP', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/index.js'), 'utf8');
  assert.match(source, /req\.path === '\/mission-evidence\/session'/);
  assert.match(source, /req\.path === '\/mission-evidence\/submit'/);
  assert.match(source, /return next\(\);[\s\S]*return generalLimiter\(req, res, next\);/);
});

test('normaliza variantes JPEG enviadas por navegadores Android', () => {
  const { canonicalImageMime, detectedImageMime } = missionEvidenceRouter._test;
  assert.equal(canonicalImageMime('image/jpg'), 'image/jpeg');
  assert.equal(canonicalImageMime('image/pjpeg'), 'image/jpeg');
  assert.equal(canonicalImageMime('image/png'), 'image/png');
  assert.equal(detectedImageMime(Buffer.from([0xff, 0xd8, 0xff, 0xd9, 0, 0, 0, 0, 0, 0, 0, 0])), 'image/jpeg');
});

test('multer devolve JSON claro para imagem acima de 8 MB', async () => {
  await withEvidenceServer(async (baseUrl) => {
    const form = new FormData();
    form.append('mission_slug', 'manus-account-proof');
    form.append('access_token', 'token-invalido');
    form.append('attestation', 'true');
    form.append('evidence', new Blob([Buffer.alloc(8 * 1024 * 1024 + 1)], { type: 'image/jpeg' }), 'grande.jpg');

    const response = await fetch(`${baseUrl}/api/mission-evidence/submit`, { method: 'POST', body: form });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, 'EVIDENCE_TOO_LARGE');
  });
});

test('multer devolve JSON claro para formato não aceito', async () => {
  await withEvidenceServer(async (baseUrl) => {
    const form = new FormData();
    form.append('mission_slug', 'manus-account-proof');
    form.append('access_token', 'token-invalido');
    form.append('attestation', 'true');
    form.append('evidence', new Blob([Buffer.from('arquivo-heic')], { type: 'image/heic' }), 'print.heic');

    const response = await fetch(`${baseUrl}/api/mission-evidence/submit`, { method: 'POST', body: form });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, 'EVIDENCE_UNSUPPORTED_TYPE');
  });
});
