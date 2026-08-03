/**
 * Regressão: callbacks SSV cujo `custom_data` contém percent-encoding.
 *
 * CAUSA RAIZ: a implementação de referência do AdMob monta o conteúdo assinado a
 * partir de `URI.getQuery()`, que em Java devolve a query **decodificada**
 * (`getRawQuery()` é a variante crua). A documentação reforça isso na seção
 * "Custom data": "The custom reward string is percent escaped and might require
 * decoding when parsed from the SSV callback."
 *
 * O backend verificava apenas os bytes crus. Enquanto `custom_data` não tinha
 * caracteres escapados, crua == decodificada e tudo passava. No formato v2
 * (`<user_uuid>%3A<session_uuid>`) as duas divergem em 2 bytes por `%3A`, e toda
 * verificação falhava — exatamente o que ocorreu em produção (messageLength=244
 * crua vs 242 decodificada).
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const {
  buildVerificationMessage,
  verifySsvSignature,
  validateSsvCallback,
} = require('../src/utils/admobSsv');

const UUID_USER = 'f7449b7e-1111-4222-8333-444455556666';
const UUID_SESSION = 'aaaabbbb-2222-4333-8444-555566667777';

/** Monta a query canônica real (9 params, sem user_id) observada em produção. */
function canonicalQuery(customData) {
  return [
    'ad_network=5450213213286189855',
    'ad_unit=5158063103',
    `custom_data=${customData}`,
    'reward_amount=1',
    'reward_item=Reward',
    'timestamp=1785779722024',
    'transaction_id=000658283d5296180661b18b8b0f3160',
  ].join('&');
}

test('a query crua e a decodificada divergem quando custom_data tem %3A', () => {
  const raw = canonicalQuery(`${UUID_USER}%3A${UUID_SESSION}`);
  const decoded = canonicalQuery(`${UUID_USER}:${UUID_SESSION}`);

  assert.strictEqual(raw.length, 244, 'canônica crua deve ter 244 chars');
  assert.strictEqual(decoded.length, 242, 'canônica decodificada deve ter 242');
  assert.notStrictEqual(raw, decoded);
});

test('assinatura feita sobre a mensagem DECODIFICADA deve validar', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const keyEntry = {
    keyId: '3335741209',
    pem: publicKey.export({ type: 'spki', format: 'pem' }),
  };

  // O Google assina a forma decodificada.
  const decoded = canonicalQuery(`${UUID_USER}:${UUID_SESSION}`);
  const signature = crypto
    .createSign('SHA256')
    .update(decoded, 'utf8')
    .sign(privateKey)
    .toString('base64url');

  // Mas o callback chega percent-encoded.
  const rawQuery =
    `${canonicalQuery(`${UUID_USER}%3A${UUID_SESSION}`)}` +
    `&signature=${signature}&key_id=3335741209`;

  const built = buildVerificationMessage({}, rawQuery);

  // A mensagem crua NÃO valida — este era o bug em produção.
  assert.strictEqual(
    verifySsvSignature(built, signature, keyEntry),
    false,
    'a forma crua não deve validar contra assinatura da forma decodificada'
  );

  // A forma decodificada valida.
  assert.strictEqual(
    verifySsvSignature(decodeURIComponent(built), signature, keyEntry),
    true,
    'a forma decodificada deve validar'
  );
});

test('validateSsvCallback aceita callback com custom_data percent-encoded', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });

  const decoded = canonicalQuery(`${UUID_USER}:${UUID_SESSION}`);
  const signature = crypto
    .createSign('SHA256')
    .update(decoded, 'utf8')
    .sign(privateKey)
    .toString('base64url');

  const rawQuery =
    `${canonicalQuery(`${UUID_USER}%3A${UUID_SESSION}`)}` +
    `&signature=${signature}&key_id=TESTKEY`;

  const queryParams = Object.fromEntries(new URLSearchParams(rawQuery).entries());

  // Injeta o keyset de teste para não depender da rede.
  const result = await validateSsvCallback(queryParams, rawQuery, [
    { keyId: 'TESTKEY', pem: publicKey.export({ type: 'spki', format: 'pem' }) },
  ]);

  assert.strictEqual(result.valid, true, `esperava válido, veio: ${result.error}`);
  assert.strictEqual(result.data.customData, `${UUID_USER}:${UUID_SESSION}`);
});
