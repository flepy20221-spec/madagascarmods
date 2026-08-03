'use strict';

const assert = require('assert');
const crypto = require('crypto');
const {
  buildVerificationMessage,
  publicKeyFromEntry,
  verifySsvSignature,
} = require('../src/utils/admobSsv');

function signBase64Url(message, privateKey) {
  const signer = crypto.createSign('SHA256');
  signer.update(message, 'utf8');
  signer.end();
  return signer.sign(privateKey).toString('base64url');
}

function run() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });

  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const base64 = publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64');

  const signedMessage = [
    'ad_network=5450213213286189855',
    'ad_unit=5158063103',
    'custom_data=user%2Babc%2F123',
    'reward_amount=1',
    'reward_item=Reward',
    'timestamp=1785727913705',
    'transaction_id=0006581c264cb2c0066184346634fc81',
  ].join('&');

  const signature = signBase64Url(signedMessage, privateKey);
  const rawQuery = `${signedMessage}&signature=${signature}&key_id=3335741209`;
  const queryParams = Object.fromEntries(new URLSearchParams(rawQuery));

  assert.strictEqual(
    buildVerificationMessage(queryParams, rawQuery),
    signedMessage,
    'A mensagem assinada deve preservar os bytes crus antes de &signature=',
  );

  assert.strictEqual(
    verifySsvSignature(signedMessage, signature, { pem }),
    true,
    'A chave PEM completa do Google deve ser aceita diretamente',
  );

  assert.strictEqual(
    verifySsvSignature(signedMessage, signature, { base64 }),
    true,
    'O campo DER em Base64 deve funcionar como fallback',
  );

  assert.strictEqual(
    verifySsvSignature(`${signedMessage}&tampered=1`, signature, { pem }),
    false,
    'Qualquer alteração na mensagem deve invalidar a assinatura',
  );

  assert.throws(
    () => publicKeyFromEntry({}),
    /no usable pem or base64/i,
    'Uma entrada de chave vazia deve falhar fechada',
  );

  console.log('PASS: AdMob SSV PEM/base64url/raw-query verification');
}

run();
