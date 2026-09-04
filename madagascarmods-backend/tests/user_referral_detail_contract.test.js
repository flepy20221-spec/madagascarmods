'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const read = (relativePath) =>
  fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');

test('detalhes do usuário expõem a contagem persistida de convidados', () => {
  const adminRoute = read('src/routes/admin.js');
  assert.match(adminRoute, /u\.referral_count/);
  assert.match(adminRoute, /totalReferred: parseInt\(user\.referral_count/);
});
