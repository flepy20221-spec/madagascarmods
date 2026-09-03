'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), 'utf8');
const { _test: faucetPayTest } = require('../src/utils/faucetpay');
const { validatePayoutDestination, validatePixPayload } = require('../src/utils/payoutHelpers');

test('FaucetPay classifica conta confirmada, inexistente e indisponibilidade sem pagar', () => {
  const verified = faucetPayTest.interpretCheckAddressResult({
    status: 200,
    message: 'This address belongs to a FaucetPay user.',
    payout_user_hash: 'hash-do-usuario',
  });
  assert.equal(verified.verified, true);
  assert.equal(verified.temporary, false);

  const notPayable = faucetPayTest.interpretCheckAddressResult({ status: 456, message: 'Not payable' });
  assert.equal(notPayable.verified, false);
  assert.equal(notPayable.temporary, false);
  assert.equal(notPayable.code, 'FAUCETPAY_ACCOUNT_NOT_PAYABLE');

  for (const status of [401, 403, 459]) {
    const temporary = faucetPayTest.interpretCheckAddressResult({ status, message: 'Temporary' });
    assert.equal(temporary.verified, false);
    assert.equal(temporary.temporary, true);
  }
});

test('PIX mantém validações locais estritas antes da aprovação', () => {
  const valid = validatePixPayload({
    cpf: '529.982.247-25',
    full_name: 'Ana Maria Souza',
    pix_key_type: 'email',
    pix_key_value: 'ANA.PIX@EXEMPLO.COM',
  });
  assert.equal(valid.ok, true);
  assert.equal(valid.data.pixKeyValue, 'ana.pix@exemplo.com');

  const invalidCpf = validatePixPayload({
    cpf: '11111111111',
    full_name: 'Ana Maria Souza',
    pix_key_type: 'cpf',
    pix_key_value: '11111111111',
  });
  assert.equal(invalidCpf.code, 'INVALID_CPF');
  assert.equal(invalidCpf.status, 400);

  const invalidEmail = validatePixPayload({
    cpf: '52998224725',
    full_name: 'Ana Maria Souza',
    pix_key_type: 'email',
    pix_key_value: 'email-invalido',
  });
  assert.equal(invalidEmail.code, 'INVALID_PIX_KEY_EMAIL');
  assert.equal(invalidEmail.status, 400);
});

test('FaucetPay valida, normaliza e prepara o destino sem função ausente', () => {
  const invalid = validatePayoutDestination('email-invalido');
  assert.equal(invalid.ok, false);
  assert.equal(invalid.status, 400);
  assert.equal(invalid.code, 'INVALID_FAUCETPAY_EMAIL');

  const valid = validatePayoutDestination('  ANA.PIX@EXEMPLO.COM  ');
  assert.equal(valid.ok, true);
  assert.equal(valid.normalized, 'ana.pix@exemplo.com');
  assert.match(valid.hash, /^[a-f0-9]{64}$/);
  assert.equal(valid.masked, 'an***x@exemplo.com');
  assert.equal(typeof valid.encrypted, 'string');
  assert.ok(valid.encrypted.length > 0);
});

test('cadastros são aprovados em transação e auditados como sistema', () => {
  const payoutRoute = read('src/routes/payout.js');
  const pixRoute = read('src/routes/pix.js');

  assert.match(payoutRoute, /checkAddress\(\{ address: validation\.normalized, currency: 'LTC' \}\)/);
  assert.match(payoutRoute, /Number\.isInteger\(validation\.status\) \? validation\.status : 400/);
  assert.match(payoutRoute, /'PAYOUT_DESTINATION_AUTO_APPROVED'/);
  assert.match(payoutRoute, /'APPROVED'/);
  assert.match(payoutRoute, /client\.query\('BEGIN'\)/);
  assert.match(payoutRoute, /Esta conta FaucetPay já está aprovada/);
  assert.doesNotMatch(payoutRoute, /sendPayment|sendPixPayment|asaas/i);

  assert.match(pixRoute, /'PIX_ACCOUNT_AUTO_APPROVED'/);
  assert.match(pixRoute, /Number\.isInteger\(validation\.status\) \? validation\.status : 400/);
  assert.match(pixRoute, /'APPROVED'/);
  assert.match(pixRoute, /pg_advisory_xact_lock/);
  assert.match(pixRoute, /Esta chave PIX já está aprovada/);
  assert.match(pixRoute, /PIX_KEY_ALREADY_USED/);
  assert.doesNotMatch(pixRoute, /sendPayment|sendPixPayment|asaas/i);
});

test('pendências são tratadas sem aprovação cega da FaucetPay', () => {
  const service = read('src/services/payoutDestinationAutoApproval.js');
  const migration = read('migrations/017_auto_approve_pix_accounts.sql');

  assert.match(service, /if \(verification\.temporary\)/);
  assert.match(service, /PAYOUT_DESTINATION_AUTO_APPROVED_BACKLOG/);
  assert.match(service, /PAYOUT_DESTINATION_AUTO_REJECTED_BACKLOG/);
  assert.doesNotMatch(service, /sendPayment|sendPixPayment|transfers/);
  assert.match(migration, /PIX_ACCOUNT_AUTO_APPROVED_MIGRATION/);
  assert.doesNotMatch(migration, /withdrawals|pix_withdrawals/i);
});

test('solicitações e processamento de saques permanecem manuais', () => {
  const withdrawals = read('src/routes/withdrawals.js');
  const pixWithdrawals = read('src/routes/pix_withdrawals.js');
  const admin = read('src/routes/admin.js');

  assert.match(withdrawals, /status[^\n]*PENDING|PENDING[^\n]*status/i);
  assert.match(pixWithdrawals, /status[^\n]*PENDING|PENDING[^\n]*status/i);
  assert.match(admin, /process-faucetpay/);
  assert.match(admin, /authenticateAdmin/);
});
