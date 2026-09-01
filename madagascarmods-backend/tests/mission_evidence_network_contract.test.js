const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const missionEvidenceRouter = require('../src/routes/missionEvidence');

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
