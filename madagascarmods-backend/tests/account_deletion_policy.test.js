'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const {
  MAX_DELETABLE_BALANCE_POINTS,
  getBalancePoints,
  canDeleteAccount,
  deletionBlockedReason,
} = require('../src/services/accountDeletionPolicy');

const read = (relativePath) =>
  fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');

test('a política de saldo usa 1.000 pontos como limite inclusivo', () => {
  assert.equal(MAX_DELETABLE_BALANCE_POINTS, 1000);
  assert.equal(getBalancePoints('1000'), 1000);
  assert.equal(canDeleteAccount(1000), true);
  assert.equal(canDeleteAccount(1000.01), false);
  assert.equal(canDeleteAccount(1001), false);
  assert.match(deletionBlockedReason(1001), /1001.*1000/);
});

test('valores ausentes ou inválidos não contornam a política', () => {
  assert.equal(getBalancePoints(null), 0);
  assert.equal(getBalancePoints(undefined), 0);
  assert.equal(getBalancePoints('valor-invalido'), 0);
  assert.equal(canDeleteAccount('valor-invalido'), true);
});

test('a rota manual e o job automático aplicam a proteção no servidor', () => {
  const adminRoute = read('src/routes/admin.js');
  const abandonedJob = read('src/services/abandonedAccounts.js');
  const migration = read('migrations/018_protect_high_balance_deletion.sql');

  assert.match(adminRoute, /ACCOUNT_BALANCE_PROTECTED/);
  assert.match(adminRoute, /canDeleteAccount\(user\.balance\)/);
  assert.match(abandonedJob, /MAX_DELETABLE_BALANCE_POINTS/);
  assert.match(abandonedJob, /<= \$3/);
  assert.match(migration, /v_previous_balance > 1000/);
});
