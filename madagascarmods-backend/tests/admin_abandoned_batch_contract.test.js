'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const read = (relativePath) =>
  fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');

test('limpeza em lote aplica os critérios de segurança confirmados', () => {
  const adminRoute = read('src/routes/admin.js');
  assert.match(adminRoute, /users\/abandoned\/delete-eligible/);
  assert.match(adminRoute, /u\.is_banned = false/);
  assert.match(adminRoute, /w\.status IN \('PAID', 'PROCESSING'\)/);
  assert.match(adminRoute, /u\.merged_into_user_id IS NULL/);
  assert.match(adminRoute, /\) < \$2/);
  assert.match(adminRoute, /admin_abandoned_batch/);
});

test('rotas admin usam bucket de rate limit separado do aplicativo', () => {
  const index = read('src/index.js');
  const limits = read('src/middleware/rateLimits.js');
  assert.match(index, /adminApiLimiter/);
  assert.match(index, /req\.path\.startsWith\('\/admin\/'\)/);
  assert.match(limits, /ADMIN_RATE_LIMIT/);
});
