const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeDeviceAccountKey,
  buildDeviceAccountEmail,
} = require('../src/utils/deviceIdentity');

const VALID_KEY = 'a'.repeat(64);

test('normaliza somente chaves SHA-256 hexadecimais de 64 caracteres', () => {
  assert.equal(normalizeDeviceAccountKey(`  ${VALID_KEY.toUpperCase()}  `), VALID_KEY);
  assert.equal(normalizeDeviceAccountKey('a'.repeat(63)), null);
  assert.equal(normalizeDeviceAccountKey('g'.repeat(64)), null);
  assert.equal(normalizeDeviceAccountKey(null), null);
});

test('gera identificador interno deterministico sem e-mail pessoal', () => {
  const email = buildDeviceAccountEmail(VALID_KEY);
  assert.equal(email, `device-${'a'.repeat(32)}@cashpix.local`);
  assert.equal(email.includes('@gmail.com'), false);
});

test('recusa gerar conta para uma chave de aparelho invalida', () => {
  assert.throws(
    () => buildDeviceAccountEmail('invalida'),
    /Invalid device account key/
  );
});
