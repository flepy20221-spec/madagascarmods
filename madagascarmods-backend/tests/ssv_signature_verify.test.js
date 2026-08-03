/**
 * Testa a lógica de verificação de assinatura SSV com uma chave ECDSA
 * gerada localmente, replicando exatamente o que o Google faz.
 *
 * Objetivo: isolar se o defeito está na NOSSA lógica ou no que chega do proxy.
 */
const crypto = require('crypto');
const assert = require('assert');

const {
  buildVerificationMessage,
  verifySsvSignature,
} = require('../src/utils/admobSsv');

let pass = 0;
let fail = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
    pass++;
  } catch (err) {
    console.log(`  FAIL ${name}`);
    console.log(`       ${err.message}`);
    fail++;
  }
}

// Gera par de chaves ECDSA P-256 (mesma curva do Google: prime256v1)
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
});

const pem = publicKey.export({ type: 'spki', format: 'pem' });
const keyEntry = { keyId: 3335741209, pem };

/** Assina uma mensagem como o Google faria: ECDSA SHA-256, base64url, DER. */
function signAsGoogle(message) {
  const signer = crypto.createSign('SHA256');
  signer.update(message, 'utf8');
  signer.end();
  return signer.sign(privateKey).toString('base64url');
}

console.log('\n== Verificação de assinatura SSV ==\n');

test('assinatura válida sobre a query canônica é aceita', () => {
  const canonical =
    'ad_network=5450213213286189855&ad_unit=5158063103&custom_data=' +
    '37e6c23a-9a61-477a-bd5c-4a3528b75ba9%3A1b2c3d4e-5f60-4718-8293-0a1b2c3d4e5f' +
    '&reward_amount=1&reward_item=Reward&timestamp=1785776578451' +
    '&transaction_id=abc123def456&user_id=';
  const sig = signAsGoogle(canonical);
  assert.strictEqual(verifySsvSignature(canonical, sig, keyEntry), true);
});

test('buildVerificationMessage corta exatamente antes de &signature=', () => {
  const canonical = 'ad_network=123&custom_data=uid%3Asid&transaction_id=t1';
  const raw = `${canonical}&signature=SIGVALUE&key_id=3335741209`;
  assert.strictEqual(buildVerificationMessage({}, raw), canonical);
});

test('fluxo completo: build + sign + verify', () => {
  const canonical =
    'ad_network=5450213213286189855&ad_unit=5158063103' +
    '&custom_data=uid%3Asid&reward_amount=1&reward_item=Reward' +
    '&timestamp=1785776578451&transaction_id=tx-999&user_id=';
  const sig = signAsGoogle(canonical);
  const raw = `${canonical}&signature=${sig}&key_id=3335741209`;

  const message = buildVerificationMessage({}, raw);
  assert.strictEqual(message, canonical, 'mensagem reconstruída difere');
  assert.strictEqual(verifySsvSignature(message, sig, keyEntry), true);
});

test('mensagem alterada em 1 byte é rejeitada', () => {
  const canonical = 'ad_network=123&transaction_id=t1';
  const sig = signAsGoogle(canonical);
  assert.strictEqual(
    verifySsvSignature('ad_network=124&transaction_id=t1', sig, keyEntry),
    false
  );
});

test('percent-encoding decodificado quebra a assinatura (regressão)', () => {
  // Prova por que req.query NÃO pode ser usado: ':' vira %3A na URL original.
  const canonical = 'custom_data=uid%3Asid&transaction_id=t1';
  const sig = signAsGoogle(canonical);
  const decoded = 'custom_data=uid:sid&transaction_id=t1';
  assert.strictEqual(verifySsvSignature(decoded, sig, keyEntry), false);
});

test('ordem trocada dos parâmetros é rejeitada', () => {
  const canonical = 'ad_network=123&transaction_id=t1';
  const sig = signAsGoogle(canonical);
  assert.strictEqual(
    verifySsvSignature('transaction_id=t1&ad_network=123', sig, keyEntry),
    false
  );
});

test('signature em base64 padrão também é aceita quando url-safe', () => {
  // base64url e base64 coincidem quando não há + nem /
  const canonical = 'ad_network=1&transaction_id=t2';
  const sig = signAsGoogle(canonical);
  assert.ok(sig.length > 0);
  assert.strictEqual(verifySsvSignature(canonical, sig, keyEntry), true);
});

console.log(`\n${pass} passaram, ${fail} falharam\n`);
process.exit(fail === 0 ? 0 : 1);
