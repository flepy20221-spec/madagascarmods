/**
 * Teste de compatibilidade da assinatura HMAC entre o app Flutter e o backend.
 *
 * Este teste existe porque o descompasso de assinatura e uma falha silenciosa e caríssima:
 * se o path ou o corpo divergirem em um único caractere, TODAS as requisicoes legitimas do
 * app passam a receber 403 e o aplicativo para de funcionar em producao, sem erro visivel
 * no servidor além do log de "INVALID_SIGNATURE".
 *
 * O teste reproduz exatamente o que o app faz em api_service.dart:
 *   payload = '$path|$timestamp|$nonce|$body'   com path SEM o prefixo '/api'
 * e confronta com o que o middleware calcula a partir de uma request simulada.
 *
 * Executar:  node tests/hmac_compat.test.js
 */
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_com_mais_de_32_caracteres_ok';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_com_mais_de_32_chars_ok';
process.env.APP_HMAC_SECRET = process.env.APP_HMAC_SECRET || 'test_hmac_secret_com_mais_de_32_caracteres';

const crypto = require('crypto');
const assert = require('assert');
const { canonicalPath, validateSignature } = require('../src/middleware/antiFraud');

const HMAC_SECRET = process.env.APP_HMAC_SECRET;

/** Reproduz _generateSignature do app Flutter (api_service.dart). */
function appSignature(path, timestamp, nonce, body) {
  const payload = `${path}|${timestamp}|${nonce}|${body}`;
  return crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
}

/** Simula o objeto req do Express para uma rota montada sob /api. */
function fakeReq(originalUrl) {
  return { originalUrl, url: originalUrl };
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL  ${name}`);
    console.error(`        ${err.message}`);
    failed++;
  }
}

console.log('\nCompatibilidade HMAC app <-> backend\n');

// ---------------------------------------------------------------------------
// 1. O path canonico do backend deve ser identico ao path assinado pelo app.
// ---------------------------------------------------------------------------
const pathCases = [
  ['/api/points/reward', '/points/reward'],
  ['/api/withdrawals/request', '/withdrawals/request'],
  ['/api/pix-withdrawals/request', '/pix-withdrawals/request'],
  ['/api/points/history?page=2', '/points/history'],
  ['/api/auth/login', '/auth/login'],
  ['/api/auth/device', '/auth/device'],
];

for (const [originalUrl, expected] of pathCases) {
  test(`canonicalPath('${originalUrl}') === '${expected}'`, () => {
    assert.strictEqual(canonicalPath(fakeReq(originalUrl)), expected);
  });
}

// ---------------------------------------------------------------------------
// 2. Assinatura gerada pelo app deve ser aceita pelo backend.
// ---------------------------------------------------------------------------
test('assinatura do app e aceita no /points/reward', () => {
  const ts = String(Date.now());
  const nonce = crypto.randomBytes(16).toString('base64url');
  const body = JSON.stringify({
    ad_type: 'rewarded',
    ad_unit_id: 'ca-app-pub-000/111',
    ad_network: 'admob',
    ssv_token: 'token.exemplo.assinado',
    ts: Number(ts),
  });

  const sig = appSignature('/points/reward', ts, nonce, body);
  const path = canonicalPath(fakeReq('/api/points/reward'));

  assert.ok(validateSignature(path, ts, nonce, body, sig), 'assinatura legitima foi rejeitada');
});

test('assinatura do app e aceita no /withdrawals/request', () => {
  const ts = String(Date.now());
  const nonce = crypto.randomBytes(16).toString('base64url');
  const body = JSON.stringify({ amount: 5.0, idempotency_key: 'abc-123' });

  const sig = appSignature('/withdrawals/request', ts, nonce, body);
  const path = canonicalPath(fakeReq('/api/withdrawals/request'));

  assert.ok(validateSignature(path, ts, nonce, body, sig));
});

// ---------------------------------------------------------------------------
// 3. Qualquer adulteracao deve invalidar a assinatura (o objetivo da protecao).
//    Cada caso abaixo representa um ataque real via proxy HTTP (HTTPCanary).
// ---------------------------------------------------------------------------
const ts = String(Date.now());
const nonce = crypto.randomBytes(16).toString('base64url');
const originalBody = JSON.stringify({ ad_type: 'rewarded', ssv_token: 'tok' });
const validSig = appSignature('/points/reward', ts, nonce, originalBody);
const canonPath = canonicalPath(fakeReq('/api/points/reward'));

test('corpo adulterado invalida a assinatura', () => {
  const tampered = JSON.stringify({ ad_type: 'rewarded', ssv_token: 'tok', points: 999999 });
  assert.strictEqual(validateSignature(canonPath, ts, nonce, tampered, validSig), false);
});

test('remover o ssv_token invalida a assinatura', () => {
  const tampered = JSON.stringify({ ad_type: 'rewarded' });
  assert.strictEqual(validateSignature(canonPath, ts, nonce, tampered, validSig), false);
});

test('reaproveitar a assinatura em outra rota falha', () => {
  const otherPath = canonicalPath(fakeReq('/api/withdrawals/request'));
  assert.strictEqual(validateSignature(otherPath, ts, nonce, originalBody, validSig), false);
});

test('timestamp alterado invalida a assinatura', () => {
  assert.strictEqual(validateSignature(canonPath, String(Number(ts) + 1), nonce, originalBody, validSig), false);
});

test('nonce alterado invalida a assinatura', () => {
  assert.strictEqual(validateSignature(canonPath, ts, 'outro-nonce', originalBody, validSig), false);
});

test('assinatura com segredo errado e rejeitada', () => {
  const payload = `${canonPath}|${ts}|${nonce}|${originalBody}`;
  const wrong = crypto.createHmac('sha256', 'segredo_errado_do_atacante').update(payload).digest('hex');
  assert.strictEqual(validateSignature(canonPath, ts, nonce, originalBody, wrong), false);
});

// ---------------------------------------------------------------------------
// 4. Entradas malformadas nao devem lancar excecao (evita 500 e fail-open).
//    crypto.timingSafeEqual lanca se os buffers tiverem tamanhos diferentes.
// ---------------------------------------------------------------------------
const malformed = ['', 'nao-e-hex', 'abc', null, undefined, 'ff', 'ZZZZ', '0'.repeat(63)];
for (const bad of malformed) {
  test(`assinatura malformada (${JSON.stringify(bad)}) retorna false sem lancar`, () => {
    let result;
    assert.doesNotThrow(() => {
      result = validateSignature(canonPath, ts, nonce, originalBody, bad);
    });
    assert.strictEqual(result, false);
  });
}

console.log(`\n${passed} passaram, ${failed} falharam\n`);
process.exit(failed === 0 ? 0 : 1);
